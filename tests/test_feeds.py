"""Tests for the ThreatFox IOC feed (offline, fake http client)."""

import pytest

from threat_intel.feeds import FeedIOC, ThreatFoxFeed


class _FakeResponse:
    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data

    def raise_for_status(self):
        return None


class _FakeClient:
    """Captures the POST and returns a canned ThreatFox payload."""

    def __init__(self, payload):
        self._payload = payload
        self.last_post = None

    def post(self, url, headers=None, json=None):
        self.last_post = {"url": url, "headers": headers, "json": json}
        return _FakeResponse(self._payload)


_PAYLOAD = {
    "query_status": "ok",
    "data": [
        {"ioc": "45.66.230.10:443", "ioc_type": "ip:port", "malware_printable": "Cobalt Strike", "confidence_level": 75, "first_seen": "2026-06-23"},
        {"ioc": "evil-domain.test", "ioc_type": "domain", "malware_printable": "Emotet", "confidence_level": 100},
        {"ioc": "a" * 64, "ioc_type": "sha256_hash", "malware_printable": "Qakbot", "confidence_level": 50},
        {"ioc": "irc://nope", "ioc_type": "irc_channel", "confidence_level": 90},
    ],
}


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    monkeypatch.setenv("THREATFOX_AUTH_KEY", "test-key")


def test_recent_normalizes_and_sorts_by_confidence():
    feed = ThreatFoxFeed(client=_FakeClient(_PAYLOAD))

    iocs = feed.recent(days=2, limit=10)

    # Unsupported irc_channel dropped; 3 remain, highest confidence first.
    assert [i.value for i in iocs] == ["evil-domain.test", "45.66.230.10", "a" * 64]
    assert iocs[0] == FeedIOC(
        value="evil-domain.test", ioc_type="domain", malware="Emotet", confidence=100
    )


def test_ip_port_is_stripped_to_ip():
    feed = ThreatFoxFeed(client=_FakeClient(_PAYLOAD))
    iocs = feed.recent()
    ip = next(i for i in iocs if i.malware == "Cobalt Strike")
    assert ip.value == "45.66.230.10"
    assert ip.ioc_type == "ip_address"


def test_sha256_maps_to_file_hash():
    feed = ThreatFoxFeed(client=_FakeClient(_PAYLOAD))
    iocs = feed.recent()
    h = next(i for i in iocs if i.malware == "Qakbot")
    assert h.ioc_type == "file_hash"


def test_limit_is_honored():
    feed = ThreatFoxFeed(client=_FakeClient(_PAYLOAD))
    assert len(feed.recent(limit=1)) == 1


def test_days_clamped_into_range():
    fake = _FakeClient(_PAYLOAD)
    feed = ThreatFoxFeed(client=fake)
    feed.recent(days=99)
    assert fake.last_post["json"]["days"] == 7


def test_query_status_not_ok_returns_empty():
    feed = ThreatFoxFeed(client=_FakeClient({"query_status": "no_result", "data": []}))
    assert feed.recent() == []
