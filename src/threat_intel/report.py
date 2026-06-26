"""Structured report generation.

Converts the analyst's free-text assessment into JSON matching REPORT_SCHEMA.
"""

from __future__ import annotations

import json

from .config import MAX_TOKENS, get_client, get_model

REPORT_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "ioc": {"type": "string"},
        "ioc_type": {
            "type": "string",
            "enum": ["ip_address", "file_hash", "domain", "url", "email"],
        },
        "severity": {
            "type": "string",
            "enum": ["critical", "high", "medium", "low", "informational"],
        },
        "confidence": {"type": "integer", "description": "0-100 confidence score"},
        "threat_classification": {"type": "string"},
        "summary": {"type": "string"},
        "related_malware": {"type": "array", "items": {"type": "string"}},
        "related_threat_groups": {"type": "array", "items": {"type": "string"}},
        "mitre_techniques": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "technique_id": {"type": "string"},
                    "technique_name": {"type": "string"},
                    "tactic": {"type": "string"},
                },
            },
        },
        "recommended_actions": {"type": "array", "items": {"type": "string"}},
        "related_iocs": {"type": "array", "items": {"type": "string"}},
    },
}

_REPORT_SYSTEM = (
    "Convert the analyst's findings into a structured JSON report matching the "
    "provided schema EXACTLY. Include ONLY schema fields. Return ONLY valid "
    "JSON, no markdown fences."
)


def _extract_json(text: str) -> str:
    """Strip optional markdown fences and return the raw JSON string."""
    if "```json" in text:
        return text.split("```json", 1)[1].split("```", 1)[0].strip()
    if "```" in text:
        return text.split("```", 1)[1].split("```", 1)[0].strip()
    return text.strip()


def generate_structured_report(analysis: str, ioc: str, ioc_type: str) -> dict:
    """Transform a free-text analysis into a structured report dict."""
    client = get_client()
    response = client.messages.create(
        model=get_model(),
        max_tokens=MAX_TOKENS,
        system=_REPORT_SYSTEM,
        messages=[
            {
                "role": "user",
                "content": (
                    f"IOC: {ioc} (type: {ioc_type})\n\n"
                    f"Analysis:\n{analysis}\n\n"
                    f"Schema:\n{json.dumps(REPORT_SCHEMA, indent=2)}\n\n"
                    "Return JSON directly with no markdown formatting."
                ),
            }
        ],
    )
    raw = response.content[0].text
    return json.loads(_extract_json(raw))
