"""Administrator bootstrap (hardened auth MVP).

Admin rights are never granted to the first arbitrary registration. Instead
the administrator account is created EXPLICITLY from configuration:

  * Startup: ``seed_initial_admin(settings)`` — called by the app lifespan.
    Idempotent: creates the admin only when the email does not exist yet; an
    existing account is left untouched (no password clobbering).
  * CLI: ``python -m app.storage.seed`` (reads TRUSTLENS_INITIAL_ADMIN_EMAIL /
    TRUSTLENS_INITIAL_ADMIN_PASSWORD from the environment / backend/.env).

Both paths log the outcome without ever logging the password.
"""
from __future__ import annotations

import logging
import sys
import uuid

from ..config import Settings
from . import repository
from .database import init_engine

logger = logging.getLogger("trustlens.seed")


def seed_initial_admin(settings: Settings) -> dict | None:
    """Create the configured initial admin account when it does not exist.

    Returns the created user dict, or None when nothing was created (unset
    configuration or an already-registered email).
    """
    email = (settings.initial_admin_email or "").strip().lower()
    password = settings.initial_admin_password or ""
    if not email or not password:
        return None
    if repository.get_user_by_email(email) is not None:
        logger.info("initial admin %s already exists — leaving the account untouched", email)
        return None
    from ..api.auth import hash_password  # local import: avoids an auth<->storage cycle

    user = repository.create_user(
        user_id=uuid.uuid4().hex,
        email=email,
        hashed_password=hash_password(password),
        api_key_hash=None,
        role="admin",
        email_verified=True,  # bootstrapped from trusted operator configuration
    )
    logger.info("initial admin account created for %s (set an API key via POST /api/v1/auth/api-key)", email)
    return user


def main(argv: list[str] | None = None) -> int:
    """CLI entry points:
      python -m app.storage.seed                                # create the initial admin
      python -m app.storage.seed --reset-token <email>          # mint a password-reset token
    """
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    argv = list(sys.argv[1:] if argv is None else argv)
    settings = Settings()
    # The CLI runs OUTSIDE the app lifespan, so nothing else has initialised
    # the engine/session factory — repository calls would otherwise crash with
    # "call init_engine() first" (audit M-B). Idempotent; also creates the
    # schema on a fresh database, which is what an operator bootstrapping a
    # new deployment wants.
    init_engine(settings)

    if argv and argv[0] == "--reset-token":
        if len(argv) < 2:
            print("usage: python -m app.storage.seed --reset-token <email>")
            return 1
        from ..api.auth import create_purpose_token
        user = repository.get_user_by_email(argv[1])
        if user is None:
            print(f"No user with email {argv[1]}")
            return 1
        print(create_purpose_token(user["id"], settings, purpose="password_reset", minutes=15))
        return 0

    user = seed_initial_admin(settings)
    if user is None:
        configured = bool((settings.initial_admin_email or "").strip())
        print("No admin created: " + ("account already exists" if configured
                                      else "set TRUSTLENS_INITIAL_ADMIN_EMAIL and TRUSTLENS_INITIAL_ADMIN_PASSWORD"))
        return 0 if configured else 1
    print(f"Admin created: {user['email']} (role={user['role']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
