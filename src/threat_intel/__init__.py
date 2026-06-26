"""Threat intelligence enrichment agent.

A Claude-powered agent that investigates Indicators of Compromise (IOCs) by
querying threat intelligence sources, cross-referencing findings, mapping to
MITRE ATT&CK, and producing structured reports.
"""

from .agent import iter_threat_intel_agent, run_threat_intel_agent
from .report import generate_structured_report

__all__ = [
    "run_threat_intel_agent",
    "iter_threat_intel_agent",
    "generate_structured_report",
]

__version__ = "0.1.0"
