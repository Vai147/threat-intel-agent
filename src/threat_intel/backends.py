"""Threat-intelligence data sources behind a single interface.

`MockIntelBackend` returns deterministic fixture data for known indicators and
plausible generated data otherwise. The fixtures form one correlated scenario
(IP -> malware -> MITRE, hash -> contacted IPs/domains) so a single IOC fans
out into a multi-source investigation.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod

# --- Fixtures ----------------------------------------------------------------

_IP_FIXTURES: dict[str, dict] = {
    "203.0.113.42": {
        "ip": "203.0.113.42",
        "country": "Russia",
        "asn": "AS48666",
        "isp": "MnogoByte LLC",
        "abuse_confidence_score": 87,
        "total_reports": 1243,
        "threat_types": ["botnet_c2", "malware_distribution", "brute_force"],
        "known_malware_associations": ["Emotet", "Trickbot"],
        "open_ports": [443, 8080, 4444],
        "is_known_proxy": True,
        "first_seen": "2025-08-15T00:00:00Z",
    },
}

_HASH_FIXTURES: dict[str, dict] = {
    "d131dd02c5e6eec4693d9a0698aff95c": {
        "hash": "d131dd02c5e6eec4693d9a0698aff95c",
        "hash_type": "md5",
        "sha256": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
        "detections": 58,
        "total_engines": 72,
        "detection_rate": "80.6%",
        "malware_family": "Emotet",
        "malware_type": "banking_trojan",
        "severity": "critical",
        "file_type": "PE32 executable (DLL)",
        "first_seen": "2025-12-01T08:30:00Z",
        "last_seen": "2026-03-09T22:14:00Z",
        "behavior_summary": (
            "Drops secondary payload via regsvr32, establishes persistence via "
            "registry Run key, beacons to C2 over HTTPS on non-standard ports."
        ),
        "contacted_ips": ["203.0.113.42", "203.0.113.88"],
        "contacted_domains": ["update-service-cdn.ru"],
    },
}

_DOMAIN_FIXTURES: dict[str, dict] = {
    "secure-bankofamerica-login.com": {
        "domain": "secure-bankofamerica-login.com",
        "reputation_score": 98,
        "category": "phishing",
        "active": True,
        "registrar": "NameSilo LLC",
        "registration_date": "2026-02-28T00:00:00Z",
        "hosting_provider": "BulletProof Hosting Ltd",
        "hosting_country": "Moldova",
        "ip_addresses": ["192.0.2.55", "192.0.2.56"],
        "ssl_issuer": "Let's Encrypt",
        "similar_domains_found": 12,
        "tags": ["phishing-kit", "credential-harvest", "typosquat"],
    },
}

_MITRE_FIXTURES: dict[str, dict] = {
    "emotet": {
        "techniques": [
            {
                "id": "T1071.001",
                "name": "Web Protocols",
                "tactic": "Command and Control",
                "description": "Adversaries communicate using application-layer web protocols to blend with normal traffic.",
            },
            {
                "id": "T1547.001",
                "name": "Registry Run Keys / Startup Folder",
                "tactic": "Persistence",
                "description": "Adversaries achieve persistence by adding programs to registry Run keys.",
            },
            {
                "id": "T1218.010",
                "name": "Regsvr32",
                "tactic": "Defense Evasion",
                "description": "Adversaries abuse regsvr32.exe to proxy execution of malicious code.",
            },
        ],
        "associated_groups": ["Wizard Spider", "TA542"],
        "detection_suggestions": [
            "Monitor for unusual outbound HTTPS to non-standard ports",
            "Alert on regsvr32 invoking remote scriptlets",
            "Audit new registry Run key entries",
        ],
    },
    "phishing": {
        "techniques": [
            {
                "id": "T1566.002",
                "name": "Spearphishing Link",
                "tactic": "Initial Access",
                "description": "Adversaries send malicious links to harvest credentials.",
            },
            {
                "id": "T1056.003",
                "name": "Web Portal Capture",
                "tactic": "Collection",
                "description": "Adversaries capture credentials entered into a cloned web portal.",
            },
        ],
        "associated_groups": ["APT28"],
        "detection_suggestions": [
            "Monitor for newly registered look-alike domains",
            "Inspect referrers landing on credential forms",
        ],
    },
}


class IntelBackend(ABC):
    """Data-access interface the agent depends on.

    Subclass this and implement the four methods to plug in real providers.
    """

    @abstractmethod
    def lookup_ip_reputation(self, ip_address: str) -> dict: ...

    @abstractmethod
    def lookup_file_hash(self, file_hash: str, hash_type: str) -> dict: ...

    @abstractmethod
    def lookup_domain(self, domain: str) -> dict: ...

    @abstractmethod
    def get_mitre_techniques(self, query: str) -> dict: ...


def _stable_int(seed: str, lo: int, hi: int) -> int:
    """Deterministic int in [lo, hi] derived from a seed string."""
    digest = hashlib.sha256(seed.encode()).digest()
    span = hi - lo + 1
    return lo + (int.from_bytes(digest[:4], "big") % span)


class MockIntelBackend(IntelBackend):
    """Returns fixture data for known IOCs, generated data otherwise."""

    def lookup_ip_reputation(self, ip_address: str) -> dict:
        if ip_address in _IP_FIXTURES:
            return _IP_FIXTURES[ip_address]
        score = _stable_int(ip_address, 0, 100)
        return {
            "ip": ip_address,
            "country": "Unknown",
            "asn": "AS0",
            "isp": "Unknown",
            "abuse_confidence_score": score,
            "total_reports": _stable_int(ip_address + "r", 0, 500),
            "threat_types": ["scanner"] if score > 50 else [],
            "known_malware_associations": [],
            "open_ports": [80, 443],
            "is_known_proxy": False,
            "first_seen": None,
        }

    def lookup_file_hash(self, file_hash: str, hash_type: str) -> dict:
        if file_hash in _HASH_FIXTURES:
            return _HASH_FIXTURES[file_hash]
        detections = _stable_int(file_hash, 0, 72)
        return {
            "hash": file_hash,
            "hash_type": hash_type,
            "sha256": None,
            "detections": detections,
            "total_engines": 72,
            "detection_rate": f"{round(detections / 72 * 100, 1)}%",
            "malware_family": "unknown" if detections else "none",
            "malware_type": None,
            "severity": "high" if detections > 40 else "low",
            "file_type": "unknown",
            "first_seen": None,
            "last_seen": None,
            "behavior_summary": "No fixture data; treat as unverified.",
            "contacted_ips": [],
            "contacted_domains": [],
        }

    def lookup_domain(self, domain: str) -> dict:
        if domain in _DOMAIN_FIXTURES:
            return _DOMAIN_FIXTURES[domain]
        score = _stable_int(domain, 0, 100)
        return {
            "domain": domain,
            "reputation_score": score,
            "category": "suspicious" if score > 60 else "uncategorized",
            "active": True,
            "registrar": "Unknown",
            "registration_date": None,
            "hosting_provider": "Unknown",
            "hosting_country": "Unknown",
            "ip_addresses": [],
            "ssl_issuer": None,
            "similar_domains_found": 0,
            "tags": [],
        }

    def get_mitre_techniques(self, query: str) -> dict:
        key = query.lower()
        for fixture_key, data in _MITRE_FIXTURES.items():
            if fixture_key in key:
                return data
        return {
            "techniques": [],
            "associated_groups": [],
            "detection_suggestions": [
                f"No mapped techniques for '{query}'. Refine the behavior description."
            ],
        }
