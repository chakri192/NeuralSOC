"""api/mailer.py: SMTP delivery for invite/password-reset links. Mocks
smtplib.SMTP directly (no real network/credentials needed) -- the same
mocking-the-boundary style tests/unit/test_deps_redis_tls.py already
uses for a comparably infrastructure-shaped concern.
"""
from unittest.mock import MagicMock, patch

import pytest

import api.mailer as mailer


def test_email_configured_reflects_smtp_host(monkeypatch):
    monkeypatch.setattr(mailer, "SMTP_HOST", None)
    assert mailer.email_configured() is False
    monkeypatch.setattr(mailer, "SMTP_HOST", "smtp.example.com")
    assert mailer.email_configured() is True


def test_send_email_connects_starts_tls_logs_in_and_sends(monkeypatch):
    monkeypatch.setattr(mailer, "SMTP_HOST", "smtp.example.com")
    monkeypatch.setattr(mailer, "SMTP_PORT", 587)
    monkeypatch.setattr(mailer, "SMTP_USERNAME", "apikey")
    monkeypatch.setattr(mailer, "SMTP_PASSWORD", "secret")
    monkeypatch.setattr(mailer, "SMTP_FROM_ADDRESS", "T-SOC <no-reply@tsoc.example>")
    monkeypatch.setattr(mailer, "SMTP_USE_TLS", True)

    mock_server = MagicMock()
    mock_smtp_cls = MagicMock()
    mock_smtp_cls.return_value.__enter__.return_value = mock_server

    with patch("api.mailer.smtplib.SMTP", mock_smtp_cls):
        mailer.send_email("new@acme.example.com", "You've been invited", "https://app.tsoc.example/accept?token=x")

    mock_smtp_cls.assert_called_once_with("smtp.example.com", 587, timeout=mailer.SMTP_TIMEOUT_SEC)
    mock_server.starttls.assert_called_once()
    mock_server.login.assert_called_once_with("apikey", "secret")
    mock_server.sendmail.assert_called_once()
    args = mock_server.sendmail.call_args[0]
    assert args[0] == "T-SOC <no-reply@tsoc.example>"
    assert args[1] == ["new@acme.example.com"]
    assert "You've been invited" in args[2]
    assert "https://app.tsoc.example/accept?token=x" in args[2]


def test_send_email_skips_login_when_no_credentials_configured(monkeypatch):
    monkeypatch.setattr(mailer, "SMTP_HOST", "smtp.example.com")
    monkeypatch.setattr(mailer, "SMTP_USERNAME", None)
    monkeypatch.setattr(mailer, "SMTP_PASSWORD", None)
    monkeypatch.setattr(mailer, "SMTP_USE_TLS", True)

    mock_server = MagicMock()
    mock_smtp_cls = MagicMock()
    mock_smtp_cls.return_value.__enter__.return_value = mock_server

    with patch("api.mailer.smtplib.SMTP", mock_smtp_cls):
        mailer.send_email("new@acme.example.com", "subject", "body")

    mock_server.login.assert_not_called()
    mock_server.sendmail.assert_called_once()


def test_send_email_skips_starttls_when_disabled(monkeypatch):
    monkeypatch.setattr(mailer, "SMTP_HOST", "internal-relay.corp")
    monkeypatch.setattr(mailer, "SMTP_USE_TLS", False)
    monkeypatch.setattr(mailer, "SMTP_USERNAME", None)
    monkeypatch.setattr(mailer, "SMTP_PASSWORD", None)

    mock_server = MagicMock()
    mock_smtp_cls = MagicMock()
    mock_smtp_cls.return_value.__enter__.return_value = mock_server

    with patch("api.mailer.smtplib.SMTP", mock_smtp_cls):
        mailer.send_email("new@acme.example.com", "subject", "body")

    mock_server.starttls.assert_not_called()


def test_send_email_propagates_a_real_connection_failure(monkeypatch):
    import smtplib

    monkeypatch.setattr(mailer, "SMTP_HOST", "smtp.example.com")
    with patch("api.mailer.smtplib.SMTP", side_effect=smtplib.SMTPConnectError(421, "unreachable")):
        with pytest.raises(smtplib.SMTPConnectError):
            mailer.send_email("new@acme.example.com", "subject", "body")
