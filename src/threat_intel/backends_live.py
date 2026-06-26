"""Live enrichment backend using free threat-intel APIs.

`LiveIntelBackend` queries VirusTotal (hashes, domains, IPs) and AbuseIPDB (IP
reputation) and normalizes responses onto the same dict shapes `MockIntelBackend`
returns, so the agent and report code are unchanged. It subclasses
`MockIntelBackend` to inherit `get_mitre_techniques` — the free APIs don't map
free-text behavior to ATT&CK, and the static map already serves that tool.

Network/rate-limit/not-found errors degrade gracefully: each lookup returns a
best-effort dict with a `source_error` field instead of raising, so the agent
can still produce an assessment.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

import httpx

from .backends import MockIntelBackend
from .config import (
    ABUSEIPDB_BASE,
    VT_BASE,
    VT_MIN_INTERVAL_S,
    get_abuseipdb_key,
    get_virustotal_key,
)


def _epoch_to_iso(epoch: int | None) -> str | None:
    """Convert a Unix timestamp to ISO-8601 UTC, or None."""
    if not epoch:
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


class LiveIntelBackend(MockIntelBackend):
    """Real enrichment via VirusTotal + AbuseIPDB (free tiers)."""

    def __init__(
        self,
        client: httpx.Client | None = None,
        min_interval_s: float = VT_MIN_INTERVAL_S,
    ) -> None:
        self._client = client or httpx.Client(timeout=30.0)
        self._min_interval_s = min_interval_s
        self._last_vt_call = 0.0

    # --- HTTP helpers -------------------------------------------------------

    def _throttle_vt(self) -> None:
        """Space VirusTotal calls to respect the free-tier rate limit."""
        if self._min_interval_s <= 0:
            return
        elapsed = time.monotonic() - self._last_vt_call
        if elapsed < self._min_interval_s:
            time.sleep(self._min_interval_s - elapsed)

    def _vt_get(self, path: str) -> dict:
        """GET a VirusTotal v3 endpoint, returning the `data.attributes` dict."""
        self._throttle_vt()
        resp = self._client.get(
            f"{VT_BASE}{path}",
            headers={"x-apikey": get_virustotal_key()},
        )
        self._last_vt_call = time.monotonic()
        resp.raise_for_status()
        return resp.json().get("data", {}).get("attributes", {})

    def _vt_related(self, path: str, key: str) -> list[str]:
        """Fetch a VT relationship list (e.g. contacted_ips), best-effort."""
        try:
            self._throttle_vt()
            resp = self._client.get(
                f"{VT_BASE}{path}?limit=10",
                headers={"x-apikey": get_virustotal_key()},
            )
            self._last_vt_call = time.monotonic()
            resp.raise_for_status()
            return [item.get("id") for item in resp.json().get("data", []) if item.get("id")]
        except (httpx.HTTPError, ValueError, KeyError):
            return []

    def _abuseipdb_check(self, ip: str) -> dict:
        resp = self._client.get(
            f"{ABUSEIPDB_BASE}/check",
            headers={"Key": get_abuseipdb_key(), "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
        )
        resp.raise_for_status()
        return resp.json().get("data", {})

    # --- Overridden lookups -------------------------------------------------

    def lookup_ip_reputation(self, ip_address: str) -> dict:
        result = {
            "ip": ip_address,
            "country": None,
            "asn": None,
            "isp": None,
            "abuse_confidence_score": None,
            "total_reports": None,
            "threat_types": [],
            "known_malware_associations": [],
            "open_ports": [],
            "is_known_proxy": None,
            "first_seen": None,
        }
        try:
            abuse = self._abuseipdb_check(ip_address)
            result.update(
                country=abuse.get("countryCode"),
                isp=abuse.get("isp"),
                abuse_confidence_score=abuse.get("abuseConfidenceScore"),
                total_reports=abuse.get("totalReports"),
                is_known_proxy=abuse.get("usageType", "").lower().find("proxy") >= 0,
            )
            usage = abuse.get("usageType")
            if usage:
                result["threat_types"].append(usage)
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            result["source_error"] = f"AbuseIPDB: {exc}"

        try:
            attrs = self._vt_get(f"/ip_addresses/{ip_address}")
            stats = attrs.get("last_analysis_stats", {})
            result["asn"] = f"AS{attrs.get('asn')}" if attrs.get("asn") else result["asn"]
            result["vt_malicious"] = stats.get("malicious")
            result["vt_suspicious"] = stats.get("suspicious")
            for tag in attrs.get("tags", []):
                if tag not in result["threat_types"]:
                    result["threat_types"].append(tag)
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            result["source_error"] = f"{result.get('source_error', '')} VirusTotal: {exc}".strip()
        return result

    def lookup_file_hash(self, file_hash: str, hash_type: str) -> dict:
        result = {
            "hash": file_hash,
            "hash_type": hash_type,
            "sha256": None,
            "detections": None,
            "total_engines": None,
            "detection_rate": None,
            "malware_family": None,
            "malware_type": None,
            "severity": None,
            "file_type": None,
            "first_seen": None,
            "last_seen": None,
            "behavior_summary": None,
            "contacted_ips": [],
            "contacted_domains": [],
        }
        try:
            attrs = self._vt_get(f"/files/{file_hash}")
            stats = attrs.get("last_analysis_stats", {})
            detections = stats.get("malicious", 0)
            total = sum(stats.values()) or 0
            classification = attrs.get("popular_threat_classification", {})
            result.update(
                sha256=attrs.get("sha256"),
                detections=detections,
                total_engines=total,
                detection_rate=f"{round(detections / total * 100, 1)}%" if total else None,
                malware_family=classification.get("suggested_threat_label"),
                file_type=attrs.get("type_description"),
                first_seen=_epoch_to_iso(attrs.get("first_submission_date")),
                last_seen=_epoch_to_iso(attrs.get("last_analysis_date")),
                severity="critical" if detections > 40 else "high" if detections > 5 else "low",
            )
            result["contacted_ips"] = self._vt_related(
                f"/files/{file_hash}/contacted_ips", "contacted_ips"
            )
            result["contacted_domains"] = self._vt_related(
                f"/files/{file_hash}/contacted_domains", "contacted_domains"
            )
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            result["source_error"] = f"VirusTotal: {exc}"
        return result

    def lookup_domain(self, domain: str) -> dict:
        result = {
            "domain": domain,
            "reputation_score": None,
            "category": None,
            "active": None,
            "registrar": None,
            "registration_date": None,
            "hosting_provider": None,
            "hosting_country": None,
            "ip_addresses": [],
            "ssl_issuer": None,
            "similar_domains_found": 0,
            "tags": [],
        }
        try:
            attrs = self._vt_get(f"/domains/{domain}")
            stats = attrs.get("last_analysis_stats", {})
            categories = attrs.get("categories", {})
            cert = attrs.get("last_https_certificate", {})
            result.update(
                reputation_score=stats.get("malicious"),
                category=next(iter(categories.values()), None),
                registrar=attrs.get("registrar"),
                registration_date=_epoch_to_iso(attrs.get("creation_date")),
                ssl_issuer=(cert.get("issuer") or {}).get("O"),
                tags=attrs.get("tags", []),
            )
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            result["source_error"] = f"VirusTotal: {exc}"
        return result
