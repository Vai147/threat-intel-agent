"""Tool schemas exposed to Claude.

Four threat-intelligence lookup tools. Schema-driven: descriptions guide the
model's decision on which source to query and in what order.
"""

from __future__ import annotations

TOOLS: list[dict] = [
    {
        "name": "lookup_ip_reputation",
        "description": (
            "Query IP reputation database for geolocation, ISP/ASN, abuse "
            "history, open ports, and known malware associations."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "ip_address": {
                    "type": "string",
                    "description": "IPv4 or IPv6 address to investigate",
                }
            },
            "required": ["ip_address"],
        },
    },
    {
        "name": "lookup_file_hash",
        "description": (
            "Query file reputation service with a cryptographic hash. Returns "
            "detection rate, malware family, behavior summary, and contacted "
            "IPs/domains."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "file_hash": {
                    "type": "string",
                    "description": "The file hash value",
                },
                "hash_type": {
                    "type": "string",
                    "enum": ["md5", "sha1", "sha256"],
                },
            },
            "required": ["file_hash", "hash_type"],
        },
    },
    {
        "name": "lookup_domain",
        "description": (
            "Investigate domain reputation including registration, DNS, SSL, "
            "hosting provider, and threat categorization."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Domain name to investigate",
                }
            },
            "required": ["domain"],
        },
    },
    {
        "name": "get_mitre_techniques",
        "description": (
            "Map observed behaviors or malware families to MITRE ATT&CK "
            "techniques, associated threat groups, and detection suggestions."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Behavior, malware family, or attack pattern description",
                }
            },
            "required": ["query"],
        },
    },
]

TOOL_NAMES = frozenset(tool["name"] for tool in TOOLS)
