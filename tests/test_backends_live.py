"""Tests for LiveIntelBackend normalization (offline, fake http client)."""

import httpx
import pytest

from threat_intel.backends_live import LiveIntelBackend


class _FakeResponse:
    def __init__(self, data, error=False):
        self._data = data
        self._error = error

    def json(self):
        return self._data

    def raise_for_status(self):
        if self._error:
            raise httpx.HTTPError("boom")


class _RouterClient:
    """Routes GETs to canned responses by URL substring."""

    def __init__(self, routes):
        # routes: list of (substring, data) checked in order
        self._routes = routes

    def get(self, url, headers=None, params=None):
        for substring, data in self._routes:
            if substring in url:
                if data == "__error__":
                    return _FakeResponse({}, error=True)
                return _FakeResponse(data)
        return _FakeResponse({"data": {"attributes": {}}})


@pytest.fixture(autouse=True)
def _keys(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-key")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "abuse-key")


def _backend(routes):
    return LiveIntelBackend(client=_RouterClient(routes), min_interval_s=0)


# --- IP ----------------------------------------------------------------------

def test_ip_merges_abuseipdb_and_virustotal():
    routes = [
        ("/check", {"data": {
            "abuseConfidenceScore": 92,
            "countryCode": "RU",
            "isp": "EvilNet",
            "totalReports": 300,
            "usageType": "Data Center/Web Hosting/Transit proxy",
        }}),
        ("/ip_addresses/", {"data": {"attributes": {
            "asn": 12345,
            "last_analysis_stats": {"malicious": 7, "suspicious": 1, "harmless": 60},
            "tags": ["c2"],
        }}}),
    ]
    result = _backend(routes).lookup_ip_reputation("203.0.113.42")

    assert result["abuse_confidence_score"] == 92
    assert result["country"] == "RU"
    assert result["isp"] == "EvilNet"
    assert result["total_reports"] == 300
    assert result["is_known_proxy"] is True
    assert result["asn"] == "AS12345"
    assert "c2" in result["threat_types"]
    assert result["vt_malicious"] == 7
    assert "source_error" not in result


def test_ip_abuseipdb_error_is_captured_not_raised():
    routes = [
        ("/check", "__error__"),
        ("/ip_addresses/", {"data": {"attributes": {"last_analysis_stats": {}}}}),
    ]
    result = _backend(routes).lookup_ip_reputation("1.2.3.4")
    assert "AbuseIPDB" in result["source_error"]
    assert result["abuse_confidence_score"] is None  # degraded, still a dict


# --- File hash ---------------------------------------------------------------

def test_file_hash_normalization():
    routes = [
        ("/contacted_ips", {"data": [{"id": "9.9.9.9"}]}),
        ("/contacted_domains", {"data": [{"id": "bad.test"}]}),
        ("/files/", {"data": {"attributes": {
            "sha256": "deadbeef",
            "last_analysis_stats": {"malicious": 55, "harmless": 17},
            "popular_threat_classification": {"suggested_threat_label": "trojan.emotet"},
            "type_description": "Win32 DLL",
            "first_submission_date": 1733040000,
        }}}),
    ]
    result = _backend(routes).lookup_file_hash("abc123", "md5")

    assert result["detections"] == 55
    assert result["total_engines"] == 72
    assert result["detection_rate"] == "76.4%"
    assert result["malware_family"] == "trojan.emotet"
    assert result["severity"] == "critical"
    assert result["file_type"] == "Win32 DLL"
    assert result["first_seen"].startswith("2024-12-01")
    assert result["contacted_ips"] == ["9.9.9.9"]
    assert result["contacted_domains"] == ["bad.test"]


# --- Domain ------------------------------------------------------------------

def test_domain_normalization():
    routes = [
        ("/domains/", {"data": {"attributes": {
            "last_analysis_stats": {"malicious": 9},
            "categories": {"engineA": "phishing"},
            "registrar": "NameSilo",
            "creation_date": 1733040000,
            "last_https_certificate": {"issuer": {"O": "Let's Encrypt"}},
            "tags": ["typosquat"],
        }}}),
    ]
    result = _backend(routes).lookup_domain("evil.test")

    assert result["reputation_score"] == 9
    assert result["category"] == "phishing"
    assert result["registrar"] == "NameSilo"
    assert result["ssl_issuer"] == "Let's Encrypt"
    assert result["tags"] == ["typosquat"]


# --- MITRE inheritance -------------------------------------------------------

def test_mitre_techniques_inherited_from_mock():
    # No HTTP needed — proves the live backend reuses the static MITRE map.
    result = _backend([]).get_mitre_techniques("Emotet banking trojan")
    ids = [t["id"] for t in result["techniques"]]
    assert "T1071.001" in ids
