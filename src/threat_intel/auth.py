"""Lightweight session auth: an HMAC-signed cookie, no external dependencies.

A single shared password (``APP_PASSWORD``) gates the API. On login the server
issues a signed token ``<expiry>.<hex-signature>`` stored in an httpOnly cookie.
Every protected request re-verifies the signature and expiry.

If ``APP_PASSWORD`` is unset, auth is disabled (local dev / tests) and a warning
is logged. Set it in production to require login.
"""

from __future__ import annotations

import hmac
import logging
import time
from hashlib import sha256

from .config import get_app_password, get_session_secret

logger = logging.getLogger("threat_intel.auth")

COOKIE_NAME = "ti_session"
SESSION_TTL_SECONDS = 7 * 24 * 3600  # 7 days


def auth_enabled() -> bool:
    """True when a password is configured. Otherwise the API is open."""
    enabled = bool(get_app_password())
    if not enabled:
        logger.warning("APP_PASSWORD is not set — API auth is DISABLED (open access).")
    return enabled


def _sign(expiry: int) -> str:
    secret = get_session_secret().encode()
    return hmac.new(secret, str(expiry).encode(), sha256).hexdigest()


def issue_token(ttl: int = SESSION_TTL_SECONDS) -> str:
    """Create a signed session token valid for ``ttl`` seconds."""
    expiry = int(time.time()) + ttl
    return f"{expiry}.{_sign(expiry)}"


def verify_token(token: str | None) -> bool:
    """Validate a session token's signature and expiry."""
    if not token or "." not in token:
        return False
    expiry_str, signature = token.rsplit(".", 1)
    try:
        expiry = int(expiry_str)
    except ValueError:
        return False
    if expiry < int(time.time()):
        return False
    return hmac.compare_digest(signature, _sign(expiry))


def password_matches(candidate: str) -> bool:
    """Constant-time comparison against the configured password."""
    expected = get_app_password()
    if not expected:
        return False
    return hmac.compare_digest(candidate.encode(), expected.encode())
