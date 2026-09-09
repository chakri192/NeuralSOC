"""Transactional email delivery for invite/password-reset links
(api/routes/auth.py's only caller).

SMTP, not a vendor SDK: SES, Postmark, SendGrid, Mailgun, and a
company's own internal relay all speak SMTP, so this works with
whichever one an operator already has an account with, or none at all
-- no new dependency, no vendor lock-in to pick before this can ship.

Deliberately best-effort at the call site, not here: send_email() lets
a real failure propagate (so it can be logged with full context by the
caller, who knows which signup/invite/reset it was for), but
api/routes/auth.py never lets that failure fail the HTTP response --
by the time _deliver_email() runs, the account/tenant/invite it's
about has already been committed to the database. Silently swallowing
a genuine delivery failure would just make it harder to debug when the
invitee (rightly) never got their email.
"""
import logging
import os
import smtplib
import ssl
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)

SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SMTP_FROM_ADDRESS = os.getenv("SMTP_FROM_ADDRESS", "T-SOC <no-reply@tsoc.example>")
# Every mainstream provider (SES, Postmark, SendGrid, Mailgun) supports
# STARTTLS on 587; an operator pointing this at a genuinely trusted
# internal relay that doesn't can opt out explicitly, the same pattern
# api/deps.py's REDIS_SSL already uses -- default secure, not default
# convenient.
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() in ("true", "1", "yes")
SMTP_TIMEOUT_SEC = 10


def email_configured() -> bool:
    return bool(SMTP_HOST)


def send_email(to: str, subject: str, body: str) -> None:
    """Raises on failure -- callers that need "never break the request
    this was triggered from" (api/routes/auth.py's _deliver_email) catch
    and log rather than letting it propagate further; this function
    itself doesn't hide a real send failure from its caller."""
    message = MIMEText(body)
    message["Subject"] = subject
    message["From"] = SMTP_FROM_ADDRESS
    message["To"] = to

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT_SEC) as server:
        if SMTP_USE_TLS:
            server.starttls(context=ssl.create_default_context())
        if SMTP_USERNAME and SMTP_PASSWORD:
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(SMTP_FROM_ADDRESS, [to], message.as_string())
