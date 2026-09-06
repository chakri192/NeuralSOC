"""scripts/replay_dlq.py had no test coverage. It reads api/kafka_sink.py's
local-disk DLQ format directly (JSONL: {"error", "alert", "timestamp"}
per line, written by write_to_file_dlq()) rather than importing that
module, since kafka_sink.py constructs a live KafkaConsumer at import
time -- these tests exercise the parsing/replay logic against real files
with a mocked KafkaProducer.
"""
import json
from unittest.mock import MagicMock, patch

from scripts.replay_dlq import load_dlq_entries, replay


def _write_dlq(path, entries):
    with open(path, "w", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")


class TestLoadDlqEntries:
    def test_loads_well_formed_entries(self, tmp_path):
        dlq = tmp_path / "alerts.jsonl"
        _write_dlq(dlq, [
            {"error": "e1", "alert": {"alert_id": "A1"}, "timestamp": 1},
            {"error": "e2", "alert": {"alert_id": "A2"}, "timestamp": 2},
        ])
        loaded = list(load_dlq_entries(str(dlq)))
        assert [e["alert"]["alert_id"] for _, e in loaded] == ["A1", "A2"]

    def test_skips_malformed_json_lines_without_raising(self, tmp_path):
        dlq = tmp_path / "alerts.jsonl"
        dlq.write_text('{"error": "e1", "alert": {"alert_id": "A1"}, "timestamp": 1}\nnot json\n')
        loaded = list(load_dlq_entries(str(dlq)))
        assert len(loaded) == 1

    def test_skips_entries_missing_the_alert_field(self, tmp_path):
        dlq = tmp_path / "alerts.jsonl"
        dlq.write_text('{"error": "e1", "timestamp": 1}\n')
        loaded = list(load_dlq_entries(str(dlq)))
        assert loaded == []

    def test_skips_blank_lines(self, tmp_path):
        dlq = tmp_path / "alerts.jsonl"
        dlq.write_text('\n\n{"error": "e1", "alert": {"alert_id": "A1"}, "timestamp": 1}\n\n')
        loaded = list(load_dlq_entries(str(dlq)))
        assert len(loaded) == 1


class TestReplay:
    def test_dry_run_does_not_construct_a_producer(self, tmp_path):
        dlq = tmp_path / "alerts.jsonl"
        _write_dlq(dlq, [{"error": "e1", "alert": {"alert_id": "A1"}, "timestamp": 1}])
        with patch("scripts.replay_dlq.KafkaProducer") as mock_producer_cls:
            count = replay(str(dlq), "localhost:9092", "security_alerts", dry_run=True)
        mock_producer_cls.assert_not_called()
        assert count == 1

    def test_publishes_each_alert_to_the_given_topic(self, tmp_path):
        dlq = tmp_path / "alerts.jsonl"
        _write_dlq(dlq, [
            {"error": "e1", "alert": {"alert_id": "A1"}, "timestamp": 1},
            {"error": "e2", "alert": {"alert_id": "A2"}, "timestamp": 2},
        ])
        fake_producer = MagicMock()
        with patch("scripts.replay_dlq.KafkaProducer", return_value=fake_producer):
            count = replay(str(dlq), "localhost:9092", "security_alerts")

        assert count == 2
        sent_alert_ids = [call.args[1]["alert_id"] for call in fake_producer.send.call_args_list]
        assert sent_alert_ids == ["A1", "A2"]
        assert all(call.args[0] == "security_alerts" for call in fake_producer.send.call_args_list)
        fake_producer.flush.assert_called_once()
        fake_producer.close.assert_called_once()

    def test_respects_limit(self, tmp_path):
        dlq = tmp_path / "alerts.jsonl"
        _write_dlq(dlq, [{"error": "e", "alert": {"alert_id": f"A{i}"}, "timestamp": i} for i in range(5)])
        fake_producer = MagicMock()
        with patch("scripts.replay_dlq.KafkaProducer", return_value=fake_producer):
            count = replay(str(dlq), "localhost:9092", "security_alerts", limit=2)
        assert count == 2
        assert fake_producer.send.call_count == 2

    def test_producer_is_closed_even_if_send_raises(self, tmp_path):
        dlq = tmp_path / "alerts.jsonl"
        _write_dlq(dlq, [{"error": "e", "alert": {"alert_id": "A1"}, "timestamp": 1}])
        fake_producer = MagicMock()
        fake_producer.send.side_effect = RuntimeError("broker unreachable")
        with patch("scripts.replay_dlq.KafkaProducer", return_value=fake_producer):
            try:
                replay(str(dlq), "localhost:9092", "security_alerts")
            except RuntimeError:
                pass
        fake_producer.close.assert_called_once()


class TestMain:
    def test_main_reports_zero_and_exits_cleanly_when_no_dlq_file_exists(self, tmp_path, capsys):
        from scripts.replay_dlq import main
        with patch("sys.argv", ["replay_dlq.py", "--dlq-file", str(tmp_path / "does-not-exist.jsonl")]):
            result = main()
        assert result == 0
        assert "nothing to replay" in capsys.readouterr().out

    def test_main_archives_the_dlq_file_when_requested(self, tmp_path, capsys):
        from scripts.replay_dlq import main
        dlq = tmp_path / "alerts.jsonl"
        _write_dlq(dlq, [{"error": "e", "alert": {"alert_id": "A1"}, "timestamp": 1}])
        with patch("scripts.replay_dlq.KafkaProducer", return_value=MagicMock()), \
             patch("sys.argv", ["replay_dlq.py", "--dlq-file", str(dlq), "--archive-after"]):
            main()
        assert not dlq.exists()
        assert list(tmp_path.glob("alerts.jsonl.replayed-*"))
