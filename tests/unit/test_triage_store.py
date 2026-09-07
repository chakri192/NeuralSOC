"""shared/triage_store.py is now a thin HTTP client for
api/routes/triage.py's tenant-scoped Postgres-backed endpoints (see
tests/unit/test_triage_routes.py for the server-side behavior) rather
than a local SQLite file. These tests verify the client builds the
right request and handles the response/errors correctly, mocking
`requests` directly -- the same pattern tests/unit/test_data_access.py
already uses for shared/data_access.py's HTTP calls.
"""
from unittest.mock import MagicMock, patch

import pytest
import requests

import shared.triage_store as triage_store


def _mock_response(json_body, status_code=200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_body
    if status_code >= 400:
        resp.raise_for_status.side_effect = requests.HTTPError(response=resp)
    else:
        resp.raise_for_status.side_effect = None
    return resp


def test_set_status_rejects_an_invalid_status_before_making_a_request():
    with patch("shared.triage_store.requests.post") as mock_post:
        with pytest.raises(ValueError):
            triage_store.set_status("tok", "INC-1", "not_a_real_status")
        mock_post.assert_not_called()


def test_set_status_posts_the_right_url_headers_and_body():
    with patch("shared.triage_store.requests.post", return_value=_mock_response({"status": "acknowledged"})) as mock_post:
        result = triage_store.set_status("my-jwt", "INC-1", triage_store.ACKNOWLEDGED, note="looking into it")

    mock_post.assert_called_once()
    args, kwargs = mock_post.call_args
    assert args[0] == f"{triage_store._API_URL}/triage/INC-1"
    assert kwargs["json"] == {"status": "acknowledged", "note": "looking into it"}
    assert kwargs["headers"] == {"Authorization": "Bearer my-jwt"}
    assert result == {"status": "acknowledged"}


def test_set_status_raises_on_an_http_error():
    with patch("shared.triage_store.requests.post", return_value=_mock_response({"detail": "nope"}, status_code=400)):
        with pytest.raises(requests.HTTPError):
            triage_store.set_status("tok", "INC-1", triage_store.CONFIRMED)


def test_get_status_gets_the_right_url_and_headers():
    with patch(
        "shared.triage_store.requests.get",
        return_value=_mock_response({"status": "open", "note": "", "actor": "", "updated_at": ""}),
    ) as mock_get:
        result = triage_store.get_status("my-jwt", "INC-1")

    mock_get.assert_called_once()
    args, kwargs = mock_get.call_args
    assert args[0] == f"{triage_store._API_URL}/triage/INC-1"
    assert kwargs["headers"] == {"Authorization": "Bearer my-jwt"}
    assert result["status"] == "open"


def test_get_all_statuses_gets_the_bulk_endpoint():
    with patch(
        "shared.triage_store.requests.get",
        return_value=_mock_response({"INC-1": {"status": "confirmed", "note": "", "actor": "a@x.com", "updated_at": "t"}}),
    ) as mock_get:
        result = triage_store.get_all_statuses("my-jwt")

    args, kwargs = mock_get.call_args
    assert args[0] == triage_store._API_URL + "/triage"
    assert kwargs["headers"] == {"Authorization": "Bearer my-jwt"}
    assert result == {"INC-1": {"status": "confirmed", "note": "", "actor": "a@x.com", "updated_at": "t"}}


def test_get_all_statuses_raises_on_a_network_error():
    with patch("shared.triage_store.requests.get", side_effect=requests.ConnectionError("unreachable")):
        with pytest.raises(requests.ConnectionError):
            triage_store.get_all_statuses("tok")
