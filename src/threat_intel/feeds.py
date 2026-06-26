"""IOC feeds: pull real, recent indicators to investigate.

`IOCFeed` is the abstraction; `ThreatFoxFeed` pulls live IOCs from abuse.ch
ThreatFox. The agent treats whatever a feed returns as the queue of indicators
to enrich, replacing the "hand me one IOC" entry point with a real source.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

import httpx

from .config import (
    FEED_DEFAULT_DAYS,
    FEED_DEFAULT_LIMIT,
    THREATFOX_URL,
    get_threatfox_key,
)

# ThreatFox ioc_type values -> this project's IOC type enum.
_THREATFOX_TYPE_MAP: dict[str, str] = {
    "ip:port": "ip_address",
    "ip": "ip_address",
    "domain": "domain",
    "url": "url",
    "sha256_hash": "file_hash",
    "sha1_hash": "file_hash",
    "md5_hash": "file_hash",
    "email": "email",
}


@dataclass(frozen=True)
class FeedIOC:
    """One indicator pulled from a feed, normalized to project conventions."""

    value: str
    ioc_type: str
    malware: str | None = None
    confidence: int = 0
    first_seen: str | None = None


class IOCFeed(ABC):
    """A source of recent indicators to investigate."""

    @abstractmethod
    def recent(
        self,
        days: int = FEED_DEFAULT_DAYS,
        limit: int = FEED_DEFAULT_LIMIT,
    ) -> list[FeedIOC]:
        """Return up to `limit` IOCs seen in the last `days` days."""


def _normalize_value(raw_value: str, ioc_type: str) -> str:
    """Strip transport noise the agent's tools don't expect (e.g. IP ports)."""
    if ioc_type == "ip_address" and ":" in raw_value:
        return raw_value.rsplit(":", 1)[0]
    return raw_value


class ThreatFoxFeed(IOCFeed):
    """Recent IOCs from abuse.ch ThreatFox (free, requires an Auth-Key)."""

    def __init__(self, client: httpx.Client | None = None) -> None:
        self._client = client or httpx.Client(timeout=30.0)

    def recent(
        self,
        days: int = FEED_DEFAULT_DAYS,
        limit: int = FEED_DEFAULT_LIMIT,
    ) -> list[FeedIOC]:
        days = max(1, min(days, 7))  # ThreatFox accepts 1-7
        response = self._client.post(
            THREATFOX_URL,
            headers={"Auth-Key": get_threatfox_key()},
            json={"query": "get_iocs", "days": days},
        )
        response.raise_for_status()
        payload = response.json()
        if payload.get("query_status") != "ok":
            return []

        iocs = [self._to_feed_ioc(row) for row in payload.get("data", [])]
        iocs = [ioc for ioc in iocs if ioc is not None]
        iocs.sort(key=lambda i: i.confidence, reverse=True)
        return iocs[:limit]

    @staticmethod
    def _to_feed_ioc(row: dict) -> FeedIOC | None:
        ioc_type = _THREATFOX_TYPE_MAP.get(row.get("ioc_type", ""))
        if ioc_type is None:
            return None  # unsupported indicator type, skip
        raw_value = row.get("ioc", "")
        if not raw_value:
            return None
        return FeedIOC(
            value=_normalize_value(raw_value, ioc_type),
            ioc_type=ioc_type,
            malware=row.get("malware_printable") or row.get("malware"),
            confidence=int(row.get("confidence_level") or 0),
            first_seen=row.get("first_seen"),
        )
