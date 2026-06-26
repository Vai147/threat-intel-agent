"""The agent loop: Claude investigates an IOC by calling intel tools.

Mirrors the cookbook loop — Claude picks tools, the backend executes them,
results feed back, and the loop runs until Claude finishes (`end_turn`) or the
turn budget is exhausted.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass, field

from .backends import IntelBackend, MockIntelBackend
from .config import MAX_AGENT_TURNS, MAX_TOKENS, get_client, get_model
from .tools import TOOLS

SYSTEM_PROMPT = """You are a senior threat intelligence analyst. When given an \
Indicator of Compromise (IOC), you systematically investigate it by:

1. Identifying the IOC type and querying the most relevant intelligence source first
2. Analyzing initial results to determine follow-up queries
3. Cross-referencing findings across multiple sources when related indicators are found
4. Mapping observed behaviors and malware families to MITRE ATT&CK techniques
5. Synthesizing all findings into clear, evidence-based assessments

Always query multiple sources when possible. If an IP lookup reveals associated \
malware, look up the MITRE techniques for that malware. If a hash lookup reveals \
contacted domains or IPs, investigate those too.

State your confidence level (low/medium/high) and explain what evidence supports it."""


@dataclass
class AgentResult:
    """Outcome of an investigation."""

    analysis: str
    tool_calls: list[dict] = field(default_factory=list)
    turns_used: int = 0
    hit_turn_limit: bool = False


def _dispatch(backend: IntelBackend, tool_name: str, tool_input: dict) -> str:
    """Route a tool call to the backend and JSON-encode the result."""
    handlers = {
        "lookup_ip_reputation": lambda inp: backend.lookup_ip_reputation(inp["ip_address"]),
        "lookup_file_hash": lambda inp: backend.lookup_file_hash(
            inp["file_hash"], inp["hash_type"]
        ),
        "lookup_domain": lambda inp: backend.lookup_domain(inp["domain"]),
        "get_mitre_techniques": lambda inp: backend.get_mitre_techniques(inp["query"]),
    }
    handler = handlers.get(tool_name)
    if handler is None:
        return json.dumps({"error": f"Unknown tool: {tool_name}"})
    try:
        return json.dumps(handler(tool_input), indent=2)
    except KeyError as exc:
        return json.dumps({"error": f"Missing required argument: {exc}"})


def _first_text(content: list) -> str:
    """First text block of a response, or a fallback string."""
    return next(
        (block.text for block in content if getattr(block, "type", None) == "text"),
        "No analysis generated.",
    )


def iter_threat_intel_agent(
    ioc: str,
    ioc_type: str,
    backend: IntelBackend | None = None,
) -> Iterator[dict]:
    """Run the investigation, yielding progress events as it happens.

    Event shapes:
        {"type": "tool_call",   "tool": str, "input": dict}
        {"type": "tool_result", "tool": str}
        {"type": "complete",    "analysis": str, "tool_calls": list,
                                "turns_used": int, "hit_turn_limit": bool}

    This is the core loop. `run_threat_intel_agent` consumes it for callers that
    only want the final result; the API consumes it to stream live progress.
    """
    backend = backend or MockIntelBackend()
    client = get_client()
    model = get_model()

    user_message = (
        "Investigate this indicator of compromise and provide a threat assessment:\n"
        f"  IOC: {ioc}\n"
        f"  Type: {ioc_type}\n\n"
        "Query all relevant intelligence sources, cross-reference findings, "
        "map to MITRE ATT&CK where applicable, and provide an assessment with "
        "severity rating, confidence score, and recommended response actions."
    )
    messages: list[dict] = [{"role": "user", "content": user_message}]
    tool_calls_made: list[dict] = []

    for turn in range(1, MAX_AGENT_TURNS + 1):
        response = client.messages.create(
            model=model,
            max_tokens=MAX_TOKENS,
            system=SYSTEM_PROMPT,
            tools=TOOLS,
            messages=messages,
        )

        if response.stop_reason == "tool_use":
            messages.append({"role": "assistant", "content": response.content})
            tool_results = []
            for block in response.content:
                if getattr(block, "type", None) != "tool_use":
                    continue
                tool_calls_made.append({"tool": block.name, "input": block.input})
                yield {"type": "tool_call", "tool": block.name, "input": block.input}
                result = _dispatch(backend, block.name, block.input)
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result,
                    }
                )
                yield {"type": "tool_result", "tool": block.name}
            messages.append({"role": "user", "content": tool_results})
            continue

        # end_turn or any non-tool stop: investigation complete.
        yield {
            "type": "complete",
            "analysis": _first_text(response.content),
            "tool_calls": tool_calls_made,
            "turns_used": turn,
            "hit_turn_limit": False,
        }
        return

    yield {
        "type": "complete",
        "analysis": "Investigation hit the turn limit before completing.",
        "tool_calls": tool_calls_made,
        "turns_used": MAX_AGENT_TURNS,
        "hit_turn_limit": True,
    }


def run_threat_intel_agent(
    ioc: str,
    ioc_type: str,
    backend: IntelBackend | None = None,
) -> AgentResult:
    """Investigate an IOC and return the analyst's free-text assessment.

    Args:
        ioc: The indicator value (IP, hash, domain, url, email).
        ioc_type: One of ip_address, file_hash, domain, url, email.
        backend: Data source. Defaults to MockIntelBackend.
    """
    final: dict | None = None
    for event in iter_threat_intel_agent(ioc, ioc_type, backend):
        if event["type"] == "complete":
            final = event

    if final is None:  # defensive; the loop always emits a complete event
        return AgentResult(analysis="No analysis generated.")
    return AgentResult(
        analysis=final["analysis"],
        tool_calls=final["tool_calls"],
        turns_used=final["turns_used"],
        hit_turn_limit=final["hit_turn_limit"],
    )
