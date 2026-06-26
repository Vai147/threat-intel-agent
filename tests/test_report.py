"""Tests for report helpers that don't require the API."""

from threat_intel.report import REPORT_SCHEMA, _extract_json


def test_extract_json_with_json_fence():
    text = 'prefix\n```json\n{"a": 1}\n```\nsuffix'
    assert _extract_json(text) == '{"a": 1}'


def test_extract_json_with_bare_fence():
    text = '```\n{"b": 2}\n```'
    assert _extract_json(text) == '{"b": 2}'


def test_extract_json_without_fence():
    text = '  {"c": 3}  '
    assert _extract_json(text) == '{"c": 3}'


def test_schema_exposes_expected_fields():
    props = REPORT_SCHEMA["properties"]
    for field in ("ioc", "severity", "confidence", "mitre_techniques", "recommended_actions"):
        assert field in props
