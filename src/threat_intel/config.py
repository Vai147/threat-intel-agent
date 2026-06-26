"""Configuration and Anthropic client construction."""

from __future__ import annotations

import os
from functools import lru_cache

from anthropic import Anthropic
from dotenv import load_dotenv

load_dotenv()

DEFAULT_MODEL = "claude-sonnet-4-6"
MAX_TOKENS = 4096
MAX_AGENT_TURNS = 10

# --- Live data source endpoints / defaults ----------------------------------
VT_BASE = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"

FEED_DEFAULT_DAYS = 3
FEED_DEFAULT_LIMIT = 10
# VirusTotal free tier allows ~4 requests/minute; space calls accordingly.
VT_MIN_INTERVAL_S = 16


def get_model() -> str:
    """Model id, overridable via THREAT_INTEL_MODEL."""
    return os.environ.get("THREAT_INTEL_MODEL", DEFAULT_MODEL)


def _require_env(name: str, where: str) -> str:
    """Read a required env var or fail with a clear, actionable message."""
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(
            f"{name} is not set, required for {where}. "
            f"Add it to .env (see .env.example)."
        )
    return value


def get_virustotal_key() -> str:
    """VirusTotal API key (free tier). Required by the live backend."""
    return _require_env("VIRUSTOTAL_API_KEY", "VirusTotal enrichment")


def get_abuseipdb_key() -> str:
    """AbuseIPDB API key (free tier). Required for IP enrichment."""
    return _require_env("ABUSEIPDB_API_KEY", "AbuseIPDB IP enrichment")


def get_threatfox_key() -> str:
    """abuse.ch ThreatFox Auth-Key (free). Required by the ThreatFox feed."""
    return _require_env("THREATFOX_AUTH_KEY", "the ThreatFox IOC feed")


def get_app_password() -> str:
    """Shared login password. Empty string means auth is disabled."""
    return os.environ.get("APP_PASSWORD", "")


def get_session_secret() -> str:
    """Secret used to sign session cookies.

    Falls back to a fixed dev value if unset — fine locally, but set
    SESSION_SECRET in production so tokens can't be forged.
    """
    return os.environ.get("SESSION_SECRET", "dev-insecure-session-secret")


@lru_cache(maxsize=1)
def get_client() -> Anthropic:
    """Anthropic client. Fails fast if the API key is missing."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError(
            "ANTHROPIC_API_KEY is not set. Copy .env.example to .env and add your key."
        )
    return Anthropic(api_key=api_key)