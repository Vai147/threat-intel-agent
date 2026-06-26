"""Command-line entry point.

The `feed` command pulls real recent IOCs and investigates each one.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .agent import run_threat_intel_agent
from .backends import IntelBackend, MockIntelBackend
from .config import FEED_DEFAULT_DAYS, FEED_DEFAULT_LIMIT
from .report import generate_structured_report

IOC_TYPES = ["ip_address", "file_hash", "domain", "url", "email"]


def _build_backend(name: str) -> IntelBackend:
    """Construct the enrichment backend by name (lazy import for live deps)."""
    if name == "live":
        from .backends_live import LiveIntelBackend

        return LiveIntelBackend()
    return MockIntelBackend()


def _print_analysis(ioc: str, ioc_type: str, result) -> None:
    print("=" * 70)
    print(f"IOC: {ioc}  ({ioc_type})")
    print(
        f"Tools called: {len(result.tool_calls)} | Turns: {result.turns_used}")
    if result.hit_turn_limit:
        print("WARNING: investigation hit the turn limit.")
    print("=" * 70)
    print(result.analysis)


def _cmd_investigate(args: argparse.Namespace) -> int:
    backend = _build_backend(args.backend)
    result = run_threat_intel_agent(args.ioc, args.ioc_type, backend=backend)
    _print_analysis(args.ioc, args.ioc_type, result)

    if args.json or args.out:
        report = generate_structured_report(
            result.analysis, args.ioc, args.ioc_type)
        rendered = json.dumps(report, indent=2)
        if args.out:
            Path(args.out).write_text(rendered, encoding="utf-8")
            print(f"\nStructured report written to {args.out}")
        else:
            print("\n--- Structured Report ---")
            print(rendered)
    return 0


def _cmd_feed(args: argparse.Namespace) -> int:
    from .feeds import ThreatFoxFeed

    feed = ThreatFoxFeed()
    iocs = feed.recent(days=args.days, limit=args.limit)
    if not iocs:
        print("No IOCs returned by the feed.")
        return 0

    print(f"Pulled {len(iocs)} IOC(s) from {args.source}. Investigating...\n")
    backend = _build_backend(args.backend)
    out_dir = Path(args.out) if args.out else None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)

    for idx, feed_ioc in enumerate(iocs, start=1):
        print(f"[{idx}/{len(iocs)}] {feed_ioc.value} ({feed_ioc.ioc_type})"
              f" — malware={feed_ioc.malware} conf={feed_ioc.confidence}")
        result = run_threat_intel_agent(
            feed_ioc.value, feed_ioc.ioc_type, backend=backend
        )
        if out_dir:
            report = generate_structured_report(
                result.analysis, feed_ioc.value, feed_ioc.ioc_type
            )
            safe = feed_ioc.value.replace("/", "_").replace(":", "_")
            (out_dir / f"{idx:02d}_{safe}.json").write_text(
                json.dumps(report, indent=2), encoding="utf-8"
            )
        else:
            _print_analysis(feed_ioc.value, feed_ioc.ioc_type, result)
            print()

    if out_dir:
        print(f"\nReports written to {out_dir}/")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="threat-intel",
        description="Investigate Indicators of Compromise with a Claude agent.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    inv = sub.add_parser("investigate", help="Investigate a single IOC")
    inv.add_argument("ioc", help="The indicator value (IP, hash, domain, ...)")
    inv.add_argument("--type", dest="ioc_type",
                     choices=IOC_TYPES, required=True)
    inv.add_argument("--backend", choices=["mock", "live"], default="mock")
    inv.add_argument("--json", action="store_true",
                     help="Also emit the JSON report")
    inv.add_argument("--out", metavar="FILE",
                     help="Write the JSON report to FILE")
    inv.set_defaults(func=_cmd_investigate)

    feed = sub.add_parser(
        "feed", help="Pull real IOCs from a feed and investigate each")
    feed.add_argument("--source", choices=["threatfox"], default="threatfox")
    feed.add_argument("--days", type=int,
                      default=FEED_DEFAULT_DAYS, help="Lookback 1-7")
    feed.add_argument("--limit", type=int, default=FEED_DEFAULT_LIMIT)
    feed.add_argument("--backend", choices=["mock", "live"], default="mock")
    feed.add_argument("--out", metavar="DIR",
                      help="Write one JSON report per IOC into DIR")
    feed.set_defaults(func=_cmd_feed)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        return args.func(args)
    except RuntimeError as exc:  # missing keys, etc.
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
