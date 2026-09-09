"""Login, logout, invite, and password-reset endpoints.

Built on the JWT toolkit that already existed in api/auth.py
(create_token/verify_token) and api/deps.py (require_scope) -- neither
was ever wired up to a real login flow before this; the only reachable
credential in production was the single static TSOC_API_KEY.

Password-reset and invite emails are stubbed for now: instead of calling
a transactional email provider (none is configured yet), the link is
logged at WARNING level so it's visible in server logs during
development/testing. Swap _deliver_email() for a real provider call once
one is chosen -- every caller of it already only cares that the
recipient "was notified," not how.
"""
import logging
import re
import secrets
from datetime import datetime, timezone
from typing import Optional

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import APIRouter, Depends, HTTPException, Request, status
from jwt import PyJWTError as JWTError
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from api.audit import record_audit_event
from api.auth import create_token, verify_token
from api.database import get_db
from api.deps import (
    clear_failed_logins,
    get_remote_address,
    is_locked_out,
    is_token_revoked,
    limiter,
    record_failed_login,
    require_scope,
    revoke_jti,
)
from api.models import ADMIN, ROLE_SCOPES, VALID_ROLES, Tenant, User

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

_hasher = PasswordHasher()

_RESET_TOKEN_EXPIRY_MIN = 60
_INVITE_TOKEN_EXPIRY_MIN = 60 * 24 * 7  # 7 days
_MFA_PENDING_EXPIRY_MIN = 5
_MIN_PASSWORD_LENGTH = 8
_SLUG_SANITIZE_RE = re.compile(r"[^a-z0-9]+")


def _deliver_email(to: str, subject: str, link: str) -> None:
    """STUB: no transactional email provider is configured yet. Logs the
    link instead of sending it -- replace with a real provider call
    (SES/Postmark/SendGrid/etc.) when one is chosen; nothing else in this
    file needs to change."""
    logger.warning("STUB EMAIL to=%s subject=%r link=%s", to, subject, link)


def _validate_email(value: str) -> str:
    value = value.strip().lower()
    if "@" not in value or value.startswith("@") or value.endswith("@"):
        raise ValueError("not a valid email address")
    return value


def _validate_password(value: str) -> str:
    # NIST 800-63B recommends a length minimum over composition rules
    # (forced digits/symbols/mixed-case push people toward predictable
    # patterns) -- 8 is its own stated minimum for user-chosen secrets.
    if len(value) < _MIN_PASSWORD_LENGTH:
        raise ValueError(f"password must be at least {_MIN_PASSWORD_LENGTH} characters")
    return value


def _slugify(name: str) -> str:
    slug = _SLUG_SANITIZE_RE.sub("-", name.strip().lower()).strip("-")
    return slug or "tenant"


def _unique_tenant_slug(db: Session, name: str) -> str:
    base = _slugify(name)
    slug = base
    while db.query(Tenant).filter(Tenant.slug == slug).first():
        slug = f"{base}-{secrets.token_hex(3)}"
    return slug


class LoginRequest(BaseModel):
    email: str
    password: str

    _normalize_email = field_validator("email")(_validate_email)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    # Also embedded in the JWT itself, but returned in the body too so a
    # caller (a CLI script minting a sensor token right after signup,
    # say) doesn't need to decode the token just to learn its own id.
    tenant_id: int


class LoginResponse(BaseModel):
    """login()'s actual response shape -- either a real session
    (access_token/tenant_id set, mfa_required False) or, for an admin
    with MFA enabled, a challenge to complete via POST /auth/mfa/verify
    (mfa_required True, mfa_token set, no access_token yet). A caller
    that only reads access_token from a successful login already breaks
    cleanly against the challenge case: the field is simply absent."""

    access_token: Optional[str] = None
    token_type: str = "bearer"
    tenant_id: Optional[int] = None
    mfa_required: bool = False
    mfa_token: Optional[str] = None


class LogoutRequest(BaseModel):
    token: str


class MfaEnrollResponse(BaseModel):
    secret: str
    otpauth_uri: str


class MfaConfirmBody(BaseModel):
    code: str


class MfaDisableBody(BaseModel):
    code: str


class MfaVerifyBody(BaseModel):
    mfa_token: str
    code: str


class PasswordResetRequestBody(BaseModel):
    email: str

    _normalize_email = field_validator("email")(_validate_email)


class PasswordResetConfirmBody(BaseModel):
    token: str
    new_password: str

    _check_password = field_validator("new_password")(_validate_password)


class SignupRequest(BaseModel):
    tenant_name: str
    email: str
    password: str

    _normalize_email = field_validator("email")(_validate_email)
    _check_password = field_validator("password")(_validate_password)

    @field_validator("tenant_name")
    @classmethod
    def _validate_tenant_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("tenant_name must not be empty")
        return value


class InviteRequest(BaseModel):
    email: str
    role: str = "analyst"

    _normalize_email = field_validator("email")(_validate_email)

    @field_validator("role")
    @classmethod
    def _validate_role(cls, value: str) -> str:
        if value not in VALID_ROLES:
            raise ValueError(f"role must be one of {sorted(VALID_ROLES)}")
        return value


def _issue_session_token(user: User) -> str:
    return create_token(
        scopes=ROLE_SCOPES[user.role],
        subject=str(user.id),
        tenant_id=user.tenant_id,
        user_id=user.id,
    )


@router.post("/signup", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
def signup(request: Request, body: SignupRequest, db: Session = Depends(get_db)):
    """Self-service tenant creation -- the only bootstrap path onto the
    platform that doesn't require someone else to already have an
    account: /login needs an existing user, and the invite endpoint
    needs an existing admin to call it. This is how every tenant's very
    first admin account comes to exist, including the first tenant ever.

    Creates a brand-new Tenant plus its first User (role=admin, active
    immediately -- unlike an invited user, they just proved they control
    this password by typing it themselves, so there's no accept-invite
    link to click)."""
    if db.query(User).filter(User.email == body.email).first():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="A user with that email already exists")

    tenant = Tenant(name=body.tenant_name, slug=_unique_tenant_slug(db, body.tenant_name))
    db.add(tenant)
    db.commit()
    db.refresh(tenant)

    user = User(
        tenant_id=tenant.id,
        email=body.email,
        password_hash=_hasher.hash(body.password),
        role=ADMIN,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    record_audit_event(
        db, "signup", tenant_id=tenant.id, actor_user_id=user.id, actor_label=user.email,
        target=tenant.slug, ip_address=get_remote_address(request),
    )
    return TokenResponse(access_token=_issue_session_token(user), tenant_id=tenant.id)


@router.post("/login", response_model=LoginResponse)
@limiter.limit("10/minute")
def login(request: Request, body: LoginRequest, db: Session = Depends(get_db)):
    # Same 401 regardless of "no such user" vs "wrong password" --
    # distinguishing the two would let an attacker enumerate valid
    # emails for free.
    invalid_credentials = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
    client_ip = get_remote_address(request)

    if is_locked_out(body.email):
        record_audit_event(db, "login.locked_out", actor_label=body.email, ip_address=client_ip)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts. Try again later.",
        )

    user = db.query(User).filter(User.email == body.email, User.is_active.is_(True)).first()
    if not user:
        record_failed_login(body.email)
        record_audit_event(db, "login.failure", actor_label=body.email, ip_address=client_ip)
        raise invalid_credentials

    try:
        _hasher.verify(user.password_hash, body.password)
    except VerifyMismatchError:
        record_failed_login(body.email)
        record_audit_event(
            db, "login.failure", tenant_id=user.tenant_id, actor_user_id=user.id,
            actor_label=user.email, ip_address=client_ip,
        )
        raise invalid_credentials

    clear_failed_logins(body.email)

    if user.mfa_enabled:
        # Password alone proves identity but not possession of the
        # enrolled authenticator -- no session token yet, and
        # last_login_at/the login.success audit entry both wait for
        # POST /auth/mfa/verify to actually complete the login.
        mfa_token = create_token(
            scopes=[], subject=str(user.id), user_id=user.id, tenant_id=user.tenant_id,
            purpose="mfa_pending", expiry_minutes=_MFA_PENDING_EXPIRY_MIN,
        )
        record_audit_event(
            db, "login.mfa_challenge", tenant_id=user.tenant_id, actor_user_id=user.id,
            actor_label=user.email, ip_address=client_ip,
        )
        return LoginResponse(mfa_required=True, mfa_token=mfa_token)

    user.last_login_at = datetime.now(timezone.utc)
    db.commit()

    record_audit_event(
        db, "login.success", tenant_id=user.tenant_id, actor_user_id=user.id,
        actor_label=user.email, ip_address=client_ip,
    )
    return LoginResponse(access_token=_issue_session_token(user), tenant_id=user.tenant_id)


@router.post("/mfa/verify", response_model=TokenResponse)
@limiter.limit("10/minute")
def verify_mfa(request: Request, body: MfaVerifyBody, db: Session = Depends(get_db)):
    """Second step of login for an MFA-enabled admin: exchanges the
    short-lived mfa_pending token from login() plus a current TOTP code
    for a real session token. Same 401 for every failure mode (expired
    challenge, wrong code, disabled account) -- no reason to help an
    attacker holding a stolen mfa_pending token distinguish them."""
    invalid = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired MFA challenge")
    try:
        payload = verify_token(body.mfa_token)
    except (JWTError, RuntimeError):
        raise invalid
    if payload.get("purpose") != "mfa_pending":
        raise invalid
    if is_token_revoked(payload.get("jti")):
        raise invalid

    user = db.query(User).filter(User.id == payload.get("user_id"), User.is_active.is_(True)).first()
    if not user or not user.mfa_enabled or not user.totp_secret:
        raise invalid

    client_ip = get_remote_address(request)
    if not pyotp.totp.TOTP(user.totp_secret).verify(body.code, valid_window=1):
        record_audit_event(
            db, "mfa.verify_failed", tenant_id=user.tenant_id, actor_user_id=user.id,
            actor_label=user.email, ip_address=client_ip,
        )
        raise invalid

    # Single-use: consume the mfa_pending token so it can't be replayed
    # for a second session even though it's short-lived, mirroring the
    # password-reset token's own consume-on-use pattern.
    jti = payload.get("jti")
    exp = payload.get("exp")
    if jti and exp:
        revoke_jti(jti, int(exp - datetime.now(timezone.utc).timestamp()))

    user.last_login_at = datetime.now(timezone.utc)
    db.commit()

    record_audit_event(
        db, "login.success", tenant_id=user.tenant_id, actor_user_id=user.id,
        actor_label=user.email, detail="mfa", ip_address=client_ip,
    )
    return TokenResponse(access_token=_issue_session_token(user), tenant_id=user.tenant_id)


@router.post("/mfa/enroll", response_model=MfaEnrollResponse)
def enroll_mfa(
    request: Request,
    db: Session = Depends(get_db),
    principal: dict = Depends(require_scope("users:manage")),
):
    """users:manage-gated -- the same scope invite_user/create_sensor_token
    require, which only ADMIN holds (ROLE_SCOPES). MFA is scoped to admin
    accounts specifically: they're the higher-value target, since they
    can invite/deactivate other users.

    Generates a new secret and stores it un-confirmed (mfa_enabled stays
    False) -- POST /auth/mfa/confirm with a real code from the
    authenticator app is what actually turns MFA on. Calling this again
    before confirming just replaces the pending secret, so scanning the
    wrong QR code isn't a dead end.
    """
    user = db.query(User).filter(User.id == principal.get("user_id")).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    secret = pyotp.random_base32()
    user.totp_secret = secret
    db.commit()

    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="T-SOC")
    record_audit_event(
        db, "mfa.enroll_started", tenant_id=user.tenant_id, actor_user_id=user.id,
        actor_label=user.email, ip_address=get_remote_address(request),
    )
    return MfaEnrollResponse(secret=secret, otpauth_uri=uri)


@router.post("/mfa/confirm", status_code=status.HTTP_204_NO_CONTENT)
def confirm_mfa(
    request: Request,
    body: MfaConfirmBody,
    db: Session = Depends(get_db),
    principal: dict = Depends(require_scope("users:manage")),
):
    user = db.query(User).filter(User.id == principal.get("user_id")).first()
    if not user or not user.totp_secret:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No pending MFA enrollment")
    if not pyotp.totp.TOTP(user.totp_secret).verify(body.code, valid_window=1):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid code")

    user.mfa_enabled = True
    db.commit()
    record_audit_event(
        db, "mfa.enabled", tenant_id=user.tenant_id, actor_user_id=user.id,
        actor_label=user.email, ip_address=get_remote_address(request),
    )


@router.post("/mfa/disable", status_code=status.HTTP_204_NO_CONTENT)
def disable_mfa(
    request: Request,
    body: MfaDisableBody,
    db: Session = Depends(get_db),
    principal: dict = Depends(require_scope("users:manage")),
):
    """Requires a current TOTP code, not just the caller's session token
    -- a stolen/hijacked session alone must not be enough to turn off
    the very control that's supposed to matter most for an admin
    account."""
    user = db.query(User).filter(User.id == principal.get("user_id")).first()
    if not user or not user.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA is not enabled")
    if not pyotp.totp.TOTP(user.totp_secret).verify(body.code, valid_window=1):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid code")

    user.mfa_enabled = False
    user.totp_secret = None
    db.commit()
    record_audit_event(
        db, "mfa.disabled", tenant_id=user.tenant_id, actor_user_id=user.id,
        actor_label=user.email, ip_address=get_remote_address(request),
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(body: LogoutRequest):
    try:
        payload = verify_token(body.token)
    except (JWTError, RuntimeError):
        # Already unusable (expired/malformed/bad signature) -- nothing
        # to revoke, and there's no principal to leak information about.
        return
    jti = payload.get("jti")
    exp = payload.get("exp")
    if jti and exp:
        ttl = int(exp - datetime.now(timezone.utc).timestamp())
        revoke_jti(jti, ttl)


@router.post("/password-reset/request", status_code=status.HTTP_202_ACCEPTED)
def request_password_reset(request: Request, body: PasswordResetRequestBody, db: Session = Depends(get_db)):
    # Always the same response whether or not the email matched a real
    # account -- otherwise this endpoint becomes a user-enumeration oracle.
    user = db.query(User).filter(User.email == body.email, User.is_active.is_(True)).first()
    if user:
        token = create_token(
            scopes=[],
            subject=str(user.id),
            user_id=user.id,
            purpose="password_reset",
            expiry_minutes=_RESET_TOKEN_EXPIRY_MIN,
        )
        _deliver_email(user.email, "Reset your T-SOC password", f"https://app.tsoc.example/reset-password?token={token}")
        record_audit_event(
            db, "password_reset.requested", tenant_id=user.tenant_id, actor_user_id=user.id,
            actor_label=user.email, ip_address=get_remote_address(request),
        )
    return {"detail": "If that email exists, a reset link has been sent."}


@router.post("/password-reset/confirm", status_code=status.HTTP_204_NO_CONTENT)
def confirm_password_reset(request: Request, body: PasswordResetConfirmBody, db: Session = Depends(get_db)):
    invalid_token = HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired reset token")
    try:
        payload = verify_token(body.token)
    except (JWTError, RuntimeError):
        raise invalid_token
    if payload.get("purpose") != "password_reset":
        raise invalid_token
    # This endpoint takes its token from the request body, not the
    # Authorization header, so it never passes through verify_auth's own
    # denylist check -- a valid-but-already-consumed reset/invite link
    # would otherwise decode successfully forever, since revoking a jti
    # doesn't touch the JWT's own signature/expiry. Check it explicitly.
    if is_token_revoked(payload.get("jti")):
        raise invalid_token

    user = db.query(User).filter(User.id == payload.get("user_id")).first()
    if not user:
        raise invalid_token

    user.password_hash = _hasher.hash(body.new_password)
    # Accepting an invite via this same flow (see invite_user's comment)
    # activates the account; a no-op for an already-active user resetting
    # their own password.
    was_pending_invite = not user.is_active
    user.is_active = True
    db.commit()

    # Single-use: consume the token immediately so a leaked (already-used)
    # reset link can't be replayed to set the password again.
    jti = payload.get("jti")
    exp = payload.get("exp")
    if jti and exp:
        revoke_jti(jti, int(exp - datetime.now(timezone.utc).timestamp()))

    record_audit_event(
        db, "invite.accepted" if was_pending_invite else "password_reset.confirmed",
        tenant_id=user.tenant_id, actor_user_id=user.id, actor_label=user.email,
        ip_address=get_remote_address(request),
    )


@router.post("/tenants/{tenant_id}/users/invite", status_code=status.HTTP_201_CREATED)
def invite_user(
    request: Request,
    tenant_id: int,
    body: InviteRequest,
    db: Session = Depends(get_db),
    principal: dict = Depends(require_scope("users:manage")),
):
    # require_scope only proves the caller holds users:manage somewhere --
    # it doesn't by itself prove THIS tenant. An admin's token is scoped
    # to their own tenant_id, so cross-tenant invites are rejected even
    # though the scope check above passed.
    if principal.get("tenant_id") != tenant_id and "*" not in principal.get("scopes", []):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot manage another tenant's users")

    if db.query(User).filter(User.email == body.email).first():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="A user with that email already exists")

    # No password yet -- set only once the invite link is accepted
    # (password-reset/confirm doubles as "accept invite" here: same
    # token purpose, same flow, one less thing to build and test twice).
    placeholder_hash = _hasher.hash(create_token(scopes=[]))
    user = User(tenant_id=tenant_id, email=body.email, password_hash=placeholder_hash, role=body.role, is_active=False)
    db.add(user)
    db.commit()
    db.refresh(user)

    record_audit_event(
        db, "user.invited", tenant_id=tenant_id, actor_user_id=principal.get("user_id"),
        target=body.email, detail=f"role={body.role}", ip_address=get_remote_address(request),
    )

    token = create_token(
        scopes=[],
        subject=str(user.id),
        user_id=user.id,
        tenant_id=tenant_id,
        purpose="password_reset",
        expiry_minutes=_INVITE_TOKEN_EXPIRY_MIN,
    )
    _deliver_email(user.email, "You've been invited to T-SOC", f"https://app.tsoc.example/accept-invite?token={token}")
    return {"id": user.id, "email": user.email, "role": user.role}
