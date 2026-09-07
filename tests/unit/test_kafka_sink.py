"""api/kafka_sink.py carries the mass-assignment fix (validate every
Kafka payload through AlertPayload BEFORE it's ever sent anywhere, so an
attacker-controlled message can't set "id" or a SQLAlchemy internal
attribute name) and the DLQ rotation/file fallback logic.
process_batch/_safe_dlq_send are module-level (not nested closures
inside run_sink()) so they're directly testable without a live Kafka
consumer loop.

kafka_sink no longer writes to Postgres directly -- it POSTs each batch
to the tenant-scoped ingest API (api/routes/ingest.py, see
tests/unit/test_ingest_routes.py for the server-side behavior) using a
per-tenant sensor token. These tests mock that HTTP call (ingest_fn)
rather than a database session.
"""
import json
from unittest.mock import MagicMock

from api.kafka_sink import (
    _rotate_dlq_if_needed,
    _safe_dlq_send,
    process_batch,
    send_to_dlq,
    write_to_file_dlq,
)


def _valid_raw_item(alert_id="ALT-test-1", **overrides):
    item = {
        "alert_id": alert_id,
        "timestamp": "2026-09-05T00:00:00Z",
        "event_type": "dns",
        "threat_class": "DGA",
        "confidence_score": 0.9,
        "severity": "high",
        "source_ip": "10.0.0.1",
        "destination_ip": "10.0.0.2",
        "evidence": {"domain": "bad.example"},
    }
    item.update(overrides)
    return item


def _ok_ingest(accepted_dicts=None, failed=None):
    """A fake ingest_fn matching api/routes/ingest.py's real response
    shape: {"accepted": N, "failed": [{"alert_id":..., "error":...}]}."""
    calls = []

    def _fn(alert_dicts):
        calls.append(alert_dicts)
        return {"accepted": len(alert_dicts) - len(failed or []), "failed": failed or []}

    _fn.calls = calls
    return _fn


class TestProcessBatchValidation:
    def test_valid_item_is_sent_to_the_ingest_api(self):
        ingest = _ok_ingest()
        item = _valid_raw_item()
        offsets = process_batch([(item, "tp0", 0)], ingest_fn=ingest)
        assert offsets == {"tp0": 1}

        assert len(ingest.calls) == 1
        assert ingest.calls[0][0]["alert_id"] == "ALT-test-1"
        assert ingest.calls[0][0]["threat_class"] == "DGA"

    def test_mass_assignment_payload_cannot_reach_the_ingest_call(self):
        """An attacker-influenced Kafka message trying to inject "id" or a
        SQLAlchemy internal attribute name must never reach ingest_fn --
        AlertPayload has no such fields, so pydantic strips/rejects them
        before anything is sent."""
        ingest = _ok_ingest()
        item = _valid_raw_item(alert_id="ALT-evil-1")
        item["id"] = 999999
        item["metadata"] = "malicious-override"
        item["registry"] = "malicious-override"

        offsets = process_batch([(item, "tp0", 0)], ingest_fn=ingest)
        assert offsets == {"tp0": 1}

        sent = ingest.calls[0][0]
        assert "id" not in sent
        assert "metadata" not in sent
        assert "registry" not in sent

    def test_invalid_item_routes_to_dlq_and_still_advances_offset(self, tmp_path, monkeypatch):
        import api.kafka_sink as sink

        monkeypatch.setattr(sink, "DLQ_PATH", str(tmp_path / "alerts.jsonl"))
        monkeypatch.setattr(sink, "DLQ_LOCK_PATH", str(tmp_path / "alerts.jsonl.lock"))

        bad_item = {"not_a_valid_field": "whatever"}  # missing required alert_id etc.
        offsets = process_batch([(bad_item, "tp0", 5)], ingest_fn=_ok_ingest())

        # A poisoned message must not stall the partition -- offset still advances.
        assert offsets == {"tp0": 6}
        dlq_content = (tmp_path / "alerts.jsonl").read_text()
        assert "not_a_valid_field" in dlq_content or "whatever" in dlq_content

    def test_evidence_dict_is_serialized_to_json_string_before_sending(self):
        ingest = _ok_ingest()
        process_batch([(_valid_raw_item(alert_id="ALT-evidence-1"), "tp0", 0)], ingest_fn=ingest)
        sent = ingest.calls[0][0]
        assert isinstance(sent["evidence"], str)
        assert json.loads(sent["evidence"]) == {"domain": "bad.example"}

    def test_ingest_api_call_failure_returns_no_offsets(self):
        def _raising_ingest(alert_dicts):
            raise RuntimeError("connection refused")

        offsets = process_batch([(_valid_raw_item(), "tp0", 0)], ingest_fn=_raising_ingest)
        assert offsets == {}


class TestIngestResponseHandling:
    def test_a_row_the_api_rejects_is_dlqd_but_its_offset_still_advances(self, tmp_path, monkeypatch):
        """The bulk-then-per-item-fallback logic now lives server-side
        (api/routes/ingest.py) -- kafka_sink's job is just to honor
        whatever the response's `failed` list says: DLQ that one row,
        but still advance past it (retrying a permanently-rejected row
        forever would stall the partition), while the other row in the
        same batch is treated as accepted."""
        import api.kafka_sink as sink

        monkeypatch.setattr(sink, "DLQ_PATH", str(tmp_path / "alerts.jsonl"))
        monkeypatch.setattr(sink, "DLQ_LOCK_PATH", str(tmp_path / "alerts.jsonl.lock"))

        ingest = _ok_ingest(failed=[{"alert_id": "ALT-rejected-1", "error": "constraint violation"}])
        offsets = process_batch(
            [
                (_valid_raw_item(alert_id="ALT-rejected-1"), "tp0", 0),
                (_valid_raw_item(alert_id="ALT-ok-1"), "tp0", 1),
            ],
            ingest_fn=ingest,
        )
        assert offsets == {"tp0": 2}  # both offsets advanced

        dlq_content = (tmp_path / "alerts.jsonl").read_text()
        assert "ALT-rejected-1" in dlq_content
        assert "constraint violation" in dlq_content

    def test_duplicate_alert_id_within_one_batch_sends_only_the_last_value(self):
        ingest = _ok_ingest()
        offsets = process_batch(
            [
                (_valid_raw_item(alert_id="ALT-dup-1", severity="low"), "tp0", 0),
                (_valid_raw_item(alert_id="ALT-dup-1", severity="high"), "tp0", 1),
            ],
            ingest_fn=ingest,
        )
        assert offsets == {"tp0": 2}

        # Only one entry for the duplicated alert_id, and it's the LAST value.
        sent = ingest.calls[0]
        matching = [d for d in sent if d["alert_id"] == "ALT-dup-1"]
        assert len(matching) == 1
        assert matching[0]["severity"] == "high"

    def test_empty_valid_items_never_calls_ingest(self, tmp_path, monkeypatch):
        import api.kafka_sink as sink

        monkeypatch.setattr(sink, "DLQ_PATH", str(tmp_path / "alerts.jsonl"))
        monkeypatch.setattr(sink, "DLQ_LOCK_PATH", str(tmp_path / "alerts.jsonl.lock"))

        ingest = _ok_ingest()
        offsets = process_batch([({"not_a_valid_field": "x"}, "tp0", 0)], ingest_fn=ingest)
        assert offsets == {"tp0": 1}
        assert ingest.calls == []


class TestDlqHelpers:
    def test_send_to_dlq_never_raises_when_producer_is_none(self):
        send_to_dlq(None, {"alert_id": "x"}, "boom")  # must not raise

    def test_send_to_dlq_never_raises_when_producer_send_fails(self):
        producer = MagicMock()
        producer.send.side_effect = RuntimeError("broker unreachable")
        send_to_dlq(producer, {"alert_id": "x"}, "boom")  # must not raise

    def test_safe_dlq_send_falls_back_to_file_when_kafka_fails(self, tmp_path, monkeypatch):
        import api.kafka_sink as sink

        dlq_path = tmp_path / "alerts.jsonl"
        monkeypatch.setattr(sink, "DLQ_PATH", str(dlq_path))
        monkeypatch.setattr(sink, "DLQ_LOCK_PATH", str(dlq_path) + ".lock")

        producer = MagicMock()
        producer.send.side_effect = RuntimeError("broker unreachable")
        _safe_dlq_send(producer, "ALT-1", {"alert_id": "ALT-1"}, "some error")

        assert dlq_path.exists()
        line = json.loads(dlq_path.read_text().splitlines()[0])
        assert line["alert"] == {"alert_id": "ALT-1"}
        assert line["error"] == "some error"

    def test_write_to_file_dlq_appends_jsonl(self, tmp_path, monkeypatch):
        import api.kafka_sink as sink

        dlq_path = tmp_path / "alerts.jsonl"
        monkeypatch.setattr(sink, "DLQ_PATH", str(dlq_path))
        monkeypatch.setattr(sink, "DLQ_LOCK_PATH", str(dlq_path) + ".lock")

        write_to_file_dlq({"alert_id": "a"}, "err-1")
        write_to_file_dlq({"alert_id": "b"}, "err-2")

        lines = dlq_path.read_text().splitlines()
        assert len(lines) == 2
        assert json.loads(lines[0])["error"] == "err-1"
        assert json.loads(lines[1])["error"] == "err-2"

    def test_rotate_dlq_if_needed_rotates_oversized_file(self, tmp_path, monkeypatch):
        import api.kafka_sink as sink

        dlq_path = tmp_path / "alerts.jsonl"
        dlq_path.write_bytes(b"x" * (1024 * 1024))  # 1 MiB
        monkeypatch.setattr(sink, "DLQ_PATH", str(dlq_path))
        monkeypatch.setattr(sink, "DLQ_MAX_SIZE_MB", 0)  # force rotation regardless of real size
        monkeypatch.setattr(sink, "DLQ_ROTATE_COUNT", 3)

        _rotate_dlq_if_needed()

        assert (tmp_path / "alerts.jsonl.1").exists()
        assert dlq_path.exists()
        assert dlq_path.read_bytes() == b""  # freshly recreated, empty

    def test_rotate_dlq_if_needed_is_a_noop_when_under_limit(self, tmp_path, monkeypatch):
        import api.kafka_sink as sink

        dlq_path = tmp_path / "alerts.jsonl"
        dlq_path.write_text("small")
        monkeypatch.setattr(sink, "DLQ_PATH", str(dlq_path))
        monkeypatch.setattr(sink, "DLQ_MAX_SIZE_MB", 100)

        _rotate_dlq_if_needed()

        assert dlq_path.read_text() == "small"

    def test_rotate_dlq_if_needed_never_raises_on_filesystem_error(self, tmp_path, monkeypatch):
        import api.kafka_sink as sink

        dlq_path = tmp_path / "alerts.jsonl"
        dlq_path.write_text("x")
        monkeypatch.setattr(sink, "DLQ_PATH", str(dlq_path))
        monkeypatch.setattr(sink, "DLQ_MAX_SIZE_MB", 0)
        monkeypatch.setattr(sink.os.path, "getsize", MagicMock(side_effect=OSError("disk error")))
        _rotate_dlq_if_needed()  # must not raise


class TestRunSink:
    """run_sink() is a while-True consumer loop with no externally settable
    stop condition except its own SIGTERM/SIGINT handler -- so these tests
    drive it with a fake KafkaConsumer whose poll() sends the process a
    real SIGINT after the scenario's messages are exhausted, exercising
    the actual loop body (poll -> batch -> process_batch -> commit ->
    graceful-shutdown) rather than just the functions it calls."""

    def _run_with_messages(self, monkeypatch, message_batches, commit_side_effect=None, ingest_response=None):
        import os
        import signal
        import api.kafka_sink as sink

        calls = {"n": 0}
        committed_offsets = []
        ingest_calls = []

        def fake_poll(timeout_ms=1000):
            calls["n"] += 1
            if calls["n"] <= len(message_batches):
                return message_batches[calls["n"] - 1]
            os.kill(os.getpid(), signal.SIGINT)
            return {}

        fake_consumer = MagicMock()
        fake_consumer.poll.side_effect = fake_poll
        if commit_side_effect is not None:
            fake_consumer.commit.side_effect = commit_side_effect
        else:
            fake_consumer.commit.side_effect = lambda offsets: committed_offsets.append(offsets)

        monkeypatch.setattr(sink, "KafkaConsumer", MagicMock(return_value=fake_consumer))
        monkeypatch.setattr(sink, "get_dlq_producer", lambda: None)
        monkeypatch.setattr(sink.time, "sleep", lambda s: None)

        def fake_ingest(alert_dicts):
            ingest_calls.append(alert_dicts)
            return ingest_response or {"accepted": len(alert_dicts), "failed": []}

        monkeypatch.setattr(sink, "_ingest_via_api", fake_ingest)
        # start_http_server binds a real socket and leaves a background
        # thread listening for the rest of the process's life -- harmless
        # in production (called once), but a second test calling run_sink()
        # again would hit "Address already in use" on the same port.
        monkeypatch.setattr(sink, "start_http_server", lambda port: None)

        sink.run_sink()  # must return, not hang, once SIGINT is delivered
        return fake_consumer, committed_offsets, ingest_calls

    @staticmethod
    def _kafka_message(alert_id, offset):
        msg = MagicMock()
        msg.value = json.dumps({
            "alert_id": alert_id, "event_type": "dns", "timestamp": "t",
            "threat_class": "DGA", "severity": "high",
            "confidence_score": 0.9, "source_ip": "1.2.3.4",
        }).encode()
        msg.offset = offset
        return msg

    def test_run_sink_processes_a_batch_and_commits_then_shuts_down(self, monkeypatch):
        batch = {"tp0": [self._kafka_message("ALT-runsink-1", 0)]}
        consumer, committed, ingest_calls = self._run_with_messages(monkeypatch, [batch])

        assert len(committed) == 1
        assert committed[0]["tp0"].offset == 1
        consumer.close.assert_called_once_with(autocommit=False)

        assert len(ingest_calls) == 1
        assert ingest_calls[0][0]["alert_id"] == "ALT-runsink-1"

    def test_run_sink_advances_offset_past_a_poisoned_message(self, monkeypatch):
        poisoned = MagicMock()
        poisoned.value = b"not valid json"
        poisoned.offset = 7
        batch = {"tp0": [poisoned]}
        _, committed, _ = self._run_with_messages(monkeypatch, [batch])

        # A deserialization failure never reaches process_batch (it's
        # filtered in the poll loop itself) but must still advance past
        # the bad offset -- the "stale partition offsets" commit path.
        assert any(c.get("tp0") is not None and c["tp0"].offset == 8 for c in committed)

    def test_run_sink_survives_a_consumer_poll_error(self, monkeypatch):
        import api.kafka_sink as sink

        def flaky_poll(timeout_ms=1000):
            flaky_poll.calls = getattr(flaky_poll, "calls", 0) + 1
            if flaky_poll.calls == 1:
                raise RuntimeError("broker hiccup")
            import os
            import signal
            os.kill(os.getpid(), signal.SIGINT)
            return {}

        fake_consumer = MagicMock()
        fake_consumer.poll.side_effect = flaky_poll
        monkeypatch.setattr(sink, "KafkaConsumer", MagicMock(return_value=fake_consumer))
        monkeypatch.setattr(sink, "get_dlq_producer", lambda: None)
        monkeypatch.setattr(sink.time, "sleep", lambda s: None)
        monkeypatch.setattr(sink, "start_http_server", lambda port: None)

        sink.run_sink()  # must not crash on a poll() exception
