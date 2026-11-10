"""Multi-tenant authentication & authorization (Step 4).

Two credential families are supported:

  * ``Authorization: Bearer <JWT>``  — dashboard UI users (email + password
    login issues a short-lived HS256 access token).
  * ``X-API-Key: <key>``             — programmatic/CLI users. Keys are random
    256-bit values shown exactly once at creation; only their SHA-256 hash is
    stored.

Configuration gate (``app/config.py``):

  * ``TRUSTLENS_AUTH_REQUIRED=false`` (default) — local/single-user/demo mode.
    No credentials are needed; every route behaves exactly as before. If a
    caller DOES present credentials they are validated (invalid ones are
    rejected with 401 rather than silently ignored), and a valid identity is
    attached as the report owner.
  * ``TRUSTLENS_AUTH_REQUIRED=true`` — all /api/v1/analyze and reports
    management routes require a valid identity (401 otherwise). Report reads
    are owner-or-public (`is_public`); DELETE and commit are owner-only (403
    otherwise); admins see and manage everything. ``GET /api/v1/verify/*``
    stays public so third parties can verify integrity hashes.

Security notes:
  * Passwords: PBKDF2-HMAC-SHA256, 390k iterations, per-user random salt
    (format ``pbkdf2_sha256$iterations$salt_hex$hash_hex``) — stdlib only.
  * Tokens: PyJWT HS256 with ``exp``/``iat``; the secret comes from
    TRUSTLENS_JWT_SECRET — use at least 32 bytes of entropy (RFC 7518 §3.2;
    PyJWT warns on shorter keys). An ephemeral random secret is generated
    with a loud warning when auth is required but no secret is configured —
    tokens then do not survive restarts.
  * API keys: 256-bit ``tl_…`` tokens; only ``sha256(key)`` is stored, keys
    are never logged.
"""
from __future__ import annotations

import hashlib
import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Optional

import jwt as pyjwt
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security.utils import get_authorization_scheme_param
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.exc import IntegrityError

from ..config import Settings
from ..storage import repository

logger = logging.getLogger("trustlens.auth")

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

_PBKDF2_ITERATIONS = 390_000
_API_KEY_PREFIX = "tl_"

_ephemeral_secret: Optional[str] = None


# ---- password hashing (stdlib PBKDF2) -------------------------------------------


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt),
                                 _PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${_PBKDF2_ITERATIONS}${salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iterations, salt, expected = stored.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                     bytes.fromhex(salt), int(iterations))
        return secrets.compare_digest(digest.hex(), expected)
    except (ValueError, TypeError):
        return False


# ---- API keys --------------------------------------------------------------------


def generate_api_key() -> str:
    """Random 256-bit key; the caller stores only sha256(key)."""
    return _API_KEY_PREFIX + secrets.token_urlsafe(32)


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


# ---- JWT ------------------------------------------------------------------------


def _jwt_secret(settings: Settings) -> str:
    global _ephemeral_secret
    if settings.jwt_secret:
        return settings.jwt_secret
    if _ephemeral_secret is None:
        _ephemeral_secret = secrets.token_urlsafe(48)
        logger.warning(
            "TRUSTLENS_JWT_SECRET is not set: an ephemeral secret was generated — "
            "issued tokens will not survive a restart. Set a stable secret for real use."
        )
    return _ephemeral_secret


def create_access_token(user_id: str, settings: Settings) -> str:
    return create_purpose_token(user_id, settings, purpose="access",
                                minutes=settings.access_token_expiry_minutes)


def create_purpose_token(user_id: str, settings: Settings, purpose: str, minutes: int) -> str:
    """Issue a purpose-scoped token (access | email_verify | password_reset).

    A token issued for one purpose is never accepted for another — a leaked
    verification token cannot be used as a session, and vice versa.
    """
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "purpose": purpose,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=minutes)).timestamp()),
    }
    return pyjwt.encode(payload, _jwt_secret(settings), algorithm="HS256")


def decode_purpose_token(token: str, settings: Settings, purpose: str) -> Optional[str]:
    """Returns the user id when the token is valid, unexpired, AND issued for
    `purpose`; None otherwise."""
    try:
        payload: dict[str, Any] = pyjwt.decode(
            token, _jwt_secret(settings), algorithms=["HS256"], options={"require": ["exp", "sub"]}
        )
        if payload.get("purpose") != purpose:
            return None
        sub = payload.get("sub")
        return sub if isinstance(sub, str) else None
    except pyjwt.PyJWTError:
        return None


def decode_access_token(token: str, settings: Settings) -> Optional[str]:
    """Returns the user id, or None when the token is invalid/expired/mis-scoped."""
    return decode_purpose_token(token, settings, purpose="access")


# ---- request identity ------------------------------------------------------------


def _resolve_identity(request: Request) -> Optional[dict]:
    """Resolve the caller from X-API-Key or Bearer JWT. Returns the user dict,
    None when no credentials were presented, and RAISES 401 when credentials
    were presented but are invalid."""
    settings: Settings = request.app.state.settings

    api_key = request.headers.get("x-api-key")
    if api_key:
        user = repository.get_user_by_api_key_hash(hash_api_key(api_key.strip()))
        if user is None:
            raise HTTPException(status_code=401, detail={
                "code": "invalid_credentials", "message": "Unknown API key."})
        return user

    authorization = request.headers.get("authorization")
    if authorization:
        scheme, token = get_authorization_scheme_param(authorization)
        if scheme.lower() != "bearer" or not token:
            raise HTTPException(status_code=401, detail={
                "code": "invalid_credentials", "message": "Authorization header must be 'Bearer <token>'."})
        user_id = decode_access_token(token.strip(), settings)
        if user_id is None:
            raise HTTPException(status_code=401, detail={
                "code": "invalid_credentials", "message": "Invalid or expired access token."})
        user = repository.get_user_by_id(user_id)
        if user is None:
            raise HTTPException(status_code=401, detail={
                "code": "invalid_credentials", "message": "Token user no longer exists."})
        return user

    return None  # no credentials presented


def get_current_user(request: Request) -> Optional[dict]:
    """FastAPI dependency. Auth-disabled mode: anonymous callers pass as None;
    auth-enabled mode: 401 without valid credentials."""
    settings: Settings = request.app.state.settings
    user = _resolve_identity(request)
    if user is None and settings.auth_required:
        raise HTTPException(status_code=401, detail={
            "code": "auth_required",
            "message": "Authentication required: supply 'Authorization: Bearer <token>' or 'X-API-Key'.",
        })
    return user


def get_registration_user(request: Request) -> Optional[dict]:
    """Identity dependency for the self-registration endpoint: anonymous
    callers are allowed through (the endpoint applies its own registration
    policy), but INVALID presented credentials are still rejected."""
    return _resolve_identity(request)


CurrentUser = Annotated[Optional[dict], Depends(get_current_user)]
RegistrationUser = Annotated[Optional[dict], Depends(get_registration_user)]


def is_admin(user: Optional[dict]) -> bool:
    return bool(user) and user["role"] == "admin"  # type: ignore[index]


def can_read_report(user: Optional[dict], meta: dict, settings: Settings) -> bool:
    """Owner, admin, anyone when auth is disabled, or when the report is public."""
    if not settings.auth_required or user is None:
        return True
    if is_admin(user):
        return True
    if meta.get("is_public"):
        return True
    return meta.get("owner_id") == user["id"]


def require_owner(user: Optional[dict], meta: dict, settings: Settings) -> None:
    """Strict ownership for DELETE/commit (403 per spec)."""
    if not settings.auth_required or user is None:
        return
    if is_admin(user):
        return
    if meta.get("owner_id") != user["id"]:
        raise HTTPException(status_code=403, detail={
            "code": "forbidden", "message": "Only the report owner can perform this action."})


# ---- auth endpoints --------------------------------------------------------------


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class TokenRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class ApiKeyRequest(BaseModel):
    enable: bool = True  # False disables the current key


@router.post(
    "/register",
    summary="Create a user (hardened bootstrap: admins come only from the seed; the API key is shown once)",
)
async def register(body: RegisterRequest, request: Request, user: RegistrationUser) -> dict:
    """Registration policy (configurable, never auto-admin):

      * demo mode (auth disabled): open, as before — role ``user``;
      * auth enabled + ``TRUSTLENS_ALLOW_OPEN_REGISTRATION=true``: open;
      * auth enabled: admins can create users directly;
      * bootstrap exception: when NO user exists at all, one registration is
        allowed (role ``user``) so a fresh deployment is never deadlocked —
        admin rights come exclusively from the seed (``app/storage/seed.py``).
    """
    settings: Settings = request.app.state.settings
    # Registration policy FIRST, email existence SECOND (audit M-C): the
    # reverse order made a closed deployment answer 409 for existing emails
    # and 403 for unknown ones — an unauthenticated email-enumeration oracle.
    # The duplicate-email race (two concurrent registrations) is mapped to
    # the same 409 below via the unique constraint (audit L-E).
    allowed = (
        (not settings.auth_required)
        or settings.allow_open_registration
        or is_admin(user)
        or repository.user_count() == 0
    )
    if not allowed:
        raise HTTPException(status_code=403, detail={
            "code": "registration_closed",
            "message": "Self-registration is disabled. Ask an administrator for an account "
                       "or set TRUSTLENS_ALLOW_OPEN_REGISTRATION=true.",
        })
    if repository.get_user_by_email(body.email) is not None:
        raise HTTPException(status_code=409, detail={
            "code": "email_taken", "message": "A user with this email already exists."})
    role = "user"  # admin rights are ONLY ever granted by the seed hook / CLI
    api_key = generate_api_key()
    try:
        created = repository.create_user(
            user_id=uuid.uuid4().hex,
            email=body.email.lower(),
            hashed_password=hash_password(body.password),
            api_key_hash=hash_api_key(api_key),
            role=role,
        )
    except IntegrityError:
        # Raced duplicate registration: the existence check above is not
        # atomic; the users.email unique constraint is the arbiter. Surface
        # the defined 409 instead of a generic 500 (audit L-E).
        raise HTTPException(status_code=409, detail={
            "code": "email_taken", "message": "A user with this email already exists."})
    token = create_access_token(created["id"], settings)
    verification_token = create_purpose_token(created["id"], settings, purpose="email_verify",
                                              minutes=24 * 60)
    logger.info("user registered (%s, role=%s) — no secrets are logged", created["email"], role)
    return {
        "user_id": created["id"], "email": created["email"], "role": created["role"],
        "access_token": token, "token_type": "bearer",
        "api_key": api_key,  # shown exactly once; only its hash is stored
        "verification_token": verification_token,
        "note": "No mailer is configured in this MVP: the email-verification token is returned "
                "here instead of being emailed (stub). POST /api/v1/auth/verify-email to use it.",
    }


@router.post("/token", summary="Email+password login -> bearer access token")
async def issue_token(body: TokenRequest, request: Request) -> dict:
    settings: Settings = request.app.state.settings
    user = repository.get_user_by_email(body.email)
    if user is None or not verify_password(body.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail={
            "code": "invalid_credentials", "message": "Email or password is incorrect."})
    return {"access_token": create_access_token(user["id"], settings), "token_type": "bearer",
            "user_id": user["id"], "role": user["role"]}


class VerifyEmailRequest(BaseModel):
    token: str = Field(min_length=10, max_length=4096)


@router.post("/verify-email", summary="Confirm an email-verification token (stub: no mailer)")
async def verify_email(body: VerifyEmailRequest, request: Request) -> dict:
    settings: Settings = request.app.state.settings
    user_id = decode_purpose_token(body.token, settings, purpose="email_verify")
    if user_id is None:
        raise HTTPException(status_code=400, detail={
            "code": "invalid_token", "message": "Verification token is invalid or expired."})
    if not repository.set_email_verified(user_id, True):
        raise HTTPException(status_code=404, detail={
            "code": "user_not_found", "message": "Token user no longer exists."})
    return {"verified": True}


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str = Field(min_length=10, max_length=4096)
    new_password: str = Field(min_length=8, max_length=128)


@router.post("/password-reset/request", summary="Request a password reset (never reveals whether the email exists)")
async def password_reset_request(body: PasswordResetRequest, request: Request) -> dict:
    """STUB: TrustLens has no mailer in this MVP. A single-use-purpose, 15-minute
    reset token is minted for the account when it exists; in development mode it
    is returned in the response (and an operator can mint one via
    ``python -m app.storage.seed --reset-token <email>`` in any mode). In
    production mode the token is discarded until a mailer is wired in.
    The response is identical for unknown emails (no user enumeration).
    """
    settings: Settings = request.app.state.settings
    user = repository.get_user_by_email(body.email)
    result: dict = {"sent": True,
                    "note": "No mailer is configured in this MVP; see docs/methodology.md §13."}
    if user is not None:
        reset_token = create_purpose_token(user["id"], settings, purpose="password_reset", minutes=15)
        if settings.environment != "production":
            result["reset_token"] = reset_token  # dev-mode stub transport
        else:
            # No email address in the log — addresses are PII and the log
            # must not become a side channel of "this account exists"
            # (audit L-F).
            logger.info("password reset requested (token discarded: no mailer configured)")
    return result


@router.post("/password-reset/confirm", summary="Set a new password with a valid reset token")
async def password_reset_confirm(body: PasswordResetConfirm, request: Request) -> dict:
    settings: Settings = request.app.state.settings
    user_id = decode_purpose_token(body.token, settings, purpose="password_reset")
    if user_id is None:
        raise HTTPException(status_code=400, detail={
            "code": "invalid_token", "message": "Reset token is invalid or expired."})
    if not repository.update_password(user_id, hash_password(body.new_password)):
        raise HTTPException(status_code=404, detail={
            "code": "user_not_found", "message": "Token user no longer exists."})
    return {"reset": True}


@router.post("/api-key", summary="Rotate (or disable) the caller's API key; the new key is shown once")
async def rotate_api_key(body: ApiKeyRequest, user: CurrentUser) -> dict:
    if user is None:
        raise HTTPException(status_code=401, detail={
            "code": "auth_required", "message": "Authentication required."})
    if not body.enable:
        repository.set_user_api_key_hash(user["id"], None)
        return {"enabled": False}
    api_key = generate_api_key()
    repository.set_user_api_key_hash(user["id"], hash_api_key(api_key))
    return {"enabled": True, "api_key": api_key}  # shown exactly once


@router.get("/me", summary="Identity of the caller")
async def whoami(user: CurrentUser) -> dict:
    if user is None:
        return {"authenticated": False, "mode": "auth_disabled"}
    return {"authenticated": True, "user_id": user["id"], "email": user["email"],
            "role": user["role"], "email_verified": bool(user.get("email_verified"))}
