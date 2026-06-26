"""Tests for the agent loop using a scripted fake Claude client."""

from types import SimpleNamespace

import pytest

from threat_intel import agent
from threat_intel.agent import _dispatch, _first_text, run_threat_intel_agent
from threat_intel.backends import MockIntelBackend


# --- dispatch ---------------------------------------------------------------

def test_dispatch_routes_to_backend():
    backend = MockIntelBackend()
    result = _dispatch(backend, "lookup_ip_reputation", {"ip_address": "203.0.113.42"})
    assert '"abuse_confidence_score": 87' in result


def test_dispatch_unknown_tool():
    backend = MockIntelBackend()
    result = _dispatch(backend, "nope", {})
    assert "Unknown tool" in result


def test_dispatch_missing_argument():
    backend = MockIntelBackend()
    result = _dispatch(backend, "lookup_ip_reputation", {})
    assert "Missing required argument" in result


def test_first_text_falls_back():
    blocks = [SimpleNamespace(type="tool_use")]
    assert _first_text(blocks) == "No analysis generated."


# --- agent loop with a fake client ------------------------------------------

def _tool_use_block(name, inp, block_id):
    return SimpleNamespace(type="tool_use", name=name, input=inp, id=block_id)


def _text_block(text):
    return SimpleNamespace(type="text", text=text)


class _FakeClient:
    """Replays a queue of scripted responses on each .messages.create call."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = 0
        self.messages = SimpleNamespace(create=self._create)

    def _create(self, **_kwargs):
        self.calls += 1
        return self._responses.pop(0)


@pytest.fixture
def patch_client(monkeypatch):
    def _install(responses):
        fake = _FakeClient(responses)
        monkeypatch.setattr(agent, "get_client", lambda: fake)
        monkeypatch.setattr(agent, "get_model", lambda: "fake-model")
        return fake

    return _install


def test_agent_runs_tool_then_finishes(patch_client):
    # Arrange — one tool_use turn, then an end_turn with the analysis.
    responses = [
        SimpleNamespace(
            stop_reason="tool_use",
            content=[_tool_use_block("lookup_ip_reputation", {"ip_address": "203.0.113.42"}, "t1")],
        ),
        SimpleNamespace(
            stop_reason="end_turn",
            content=[_text_block("High severity. Confidence: high.")],
        ),
    ]
    patch_client(responses)

    # Act
    result = run_threat_intel_agent("203.0.113.42", "ip_address")

    # Assert
    assert result.analysis == "High severity. Confidence: high."
    assert result.turns_used == 2
    assert result.hit_turn_limit is False
    assert result.tool_calls == [
        {"tool": "lookup_ip_reputation", "input": {"ip_address": "203.0.113.42"}}
    ]


def test_agent_finishes_immediately(patch_client):
    responses = [
        SimpleNamespace(stop_reason="end_turn", content=[_text_block("Benign.")])
    ]
    patch_client(responses)

    result = run_threat_intel_agent("198.51.100.7", "ip_address")

    assert result.analysis == "Benign."
    assert result.tool_calls == []
    assert result.turns_used == 1


def test_agent_hits_turn_limit(patch_client, monkeypatch):
    # Arrange — always ask for a tool so it never ends.
    monkeypatch.setattr(agent, "MAX_AGENT_TURNS", 3)
    forever = [
        SimpleNamespace(
            stop_reason="tool_use",
            content=[_tool_use_block("lookup_domain", {"domain": "x.com"}, f"t{i}")],
        )
        for i in range(3)
    ]
    patch_client(forever)

    # Act
    result = run_threat_intel_agent("x.com", "domain")

    # Assert
    assert result.hit_turn_limit is True
    assert result.turns_used == 3
    assert len(result.tool_calls) == 3
