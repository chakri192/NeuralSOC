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

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import APIRouter, Depends, HTTPException, Request, status
from jwt import PyJWTError as JWTError
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from api.auth import create_token, verify_token
from api.database import get_db
from api.deps import (
    clear_failed_logins,
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


class LogoutRequest(BaseModel):
    token: str


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

    return TokenResponse(access_token=_issue_session_token(user), tenant_id=tenant.id)


@router.post("/login", response_model=TokenResponse)
@limiter.limit("10/minute")
def login(request: Request, body: LoginRequest, db: Session = Depends(get_db)):
    # Same 401 regardless of "no such user" vs "wrong password" --
    # distinguishing the two would let an attacker enumerate valid
    # emails for free.
    invalid_credentials = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    if is_locked_out(body.email):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts. Try again later.",
        )

    user = db.query(User).filter(User.email == body.email, User.is_active.is_(True)).first()
    if not user:
        record_failed_login(body.email)
        raise invalid_credentials

    try:
        _hasher.verify(user.password_hash, body.password)
    except VerifyMismatchError:
        record_failed_login(body.email)
        raise invalid_credentials

    clear_failed_logins(body.email)
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()

    return TokenResponse(access_token=_issue_session_token(user), tenant_id=user.tenant_id)


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
def request_password_reset(body: PasswordResetRequestBody, db: Session = Depends(get_db)):
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
    return {"detail": "If that email exists, a reset link has been sent."}


@router.post("/password-reset/confirm", status_code=status.HTTP_204_NO_CONTENT)
def confirm_password_reset(body: PasswordResetConfirmBody, db: Session = Depends(get_db)):
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
    user.is_active = True
    db.commit()

    # Single-use: consume the token immediately so a leaked (already-used)
    # reset link can't be replayed to set the password again.
    jti = payload.get("jti")
    exp = payload.get("exp")
    if jti and exp:
        revoke_jti(jti, int(exp - datetime.now(timezone.utc).timestamp()))


@router.post("/tenants/{tenant_id}/users/invite", status_code=status.HTTP_201_CREATED)
def invite_user(
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
