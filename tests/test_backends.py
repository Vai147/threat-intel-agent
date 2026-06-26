"""Tests for the mock intel backend."""

from threat_intel.backends import MockIntelBackend


def test_known_ip_returns_fixture():
    # Arrange
    backend = MockIntelBackend()

    # Act
    result = backend.lookup_ip_reputation("203.0.113.42")

    # Assert
    assert result["abuse_confidence_score"] == 87
    assert "Emotet" in result["known_malware_associations"]


def test_unknown_ip_is_deterministic():
    # Arrange
    backend = MockIntelBackend()

    # Act
    first = backend.lookup_ip_reputation("198.51.100.7")
    second = backend.lookup_ip_reputation("198.51.100.7")

    # Assert
    assert first == second
    assert 0 <= first["abuse_confidence_score"] <= 100


def test_known_hash_reveals_contacted_infrastructure():
    # Arrange
    backend = MockIntelBackend()

    # Act
    result = backend.lookup_file_hash("d131dd02c5e6eec4693d9a0698aff95c", "md5")

    # Assert — pivot targets the agent can follow up on
    assert result["malware_family"] == "Emotet"
    assert "203.0.113.42" in result["contacted_ips"]
    assert "update-service-cdn.ru" in result["contacted_domains"]


def test_known_phishing_domain_returns_fixture():
    # Arrange
    backend = MockIntelBackend()

    # Act
    result = backend.lookup_domain("secure-bankofamerica-login.com")

    # Assert
    assert result["category"] == "phishing"
    assert "typosquat" in result["tags"]


def test_mitre_maps_emotet_to_techniques():
    # Arrange
    backend = MockIntelBackend()

    # Act
    result = backend.get_mitre_techniques("Emotet banking trojan persistence")

    # Assert
    ids = [t["id"] for t in result["techniques"]]
    assert "T1071.001" in ids
    assert result["associated_groups"]


def test_mitre_unknown_query_returns_empty_with_hint():
    # Arrange
    backend = MockIntelBackend()

    # Act
    result = backend.get_mitre_techniques("totally unmapped behavior xyz")

    # Assert
    assert result["techniques"] == []
    assert result["detection_suggestions"]
