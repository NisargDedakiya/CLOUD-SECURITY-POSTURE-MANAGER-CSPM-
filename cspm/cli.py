"""Command-line interface for the CSPM scanner."""

from __future__ import annotations

import argparse
import json
import sys

from cspm.engine import ScanEngine
from cspm.models import Cloud, Severity

_SEV_COLORS = {
    Severity.CRITICAL: "\033[95m",
    Severity.HIGH: "\033[91m",
    Severity.MEDIUM: "\033[93m",
    Severity.LOW: "\033[94m",
    Severity.INFO: "\033[90m",
}
_RESET = "\033[0m"


def _parse_clouds(values: list[str] | None) -> list[Cloud]:
    if not values:
        return list(Cloud)
    return [Cloud(v.lower()) for v in values]


def _print_table(result, use_color: bool) -> None:
    summary = result.summary()
    print("=" * 70)
    print("  CLOUD SECURITY POSTURE REPORT")
    print("=" * 70)
    print(f"  Resources scanned : {summary['resources_scanned']}")
    print(f"  Checks run        : {summary['checks_run']}")
    print(f"  Posture score     : {summary['posture_score']}%")
    print(f"  Total findings    : {summary['total_findings']}")
    sev = summary["by_severity"]
    print(
        "  By severity       : "
        f"CRIT={sev['critical']} HIGH={sev['high']} "
        f"MED={sev['medium']} LOW={sev['low']}"
    )
    print("-" * 70)
    for f in result.failed:
        color = _SEV_COLORS.get(f.severity, "") if use_color else ""
        reset = _RESET if use_color else ""
        print(f"  {color}[{f.severity.value.upper():8}]{reset} {f.title}")
        print(f"      {f.cloud.value}:{f.resource_type} {f.resource_id}")
        print(f"      fix: {f.remediation}")
    if not result.failed:
        print("  No failing findings. \U0001F389")
    print("=" * 70)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cspm", description="Cloud Security Posture Manager")
    parser.add_argument(
        "--cloud",
        action="append",
        choices=[c.value for c in Cloud],
        help="Restrict scan to specific cloud(s). Repeatable. Default: all.",
    )
    parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format.",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Use live cloud APIs instead of mock sample data.",
    )
    parser.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        help="Exit non-zero if any finding at or above this severity exists.",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    args = parser.parse_args(argv)

    engine = ScanEngine(clouds=_parse_clouds(args.cloud), mock=not args.live)
    result = engine.scan()

    if args.format == "json":
        print(json.dumps(result.to_dict(), indent=2))
    else:
        _print_table(result, use_color=not args.no_color and sys.stdout.isatty())

    if args.fail_on:
        threshold = Severity(args.fail_on)
        if any(f.severity.rank >= threshold.rank for f in result.failed):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
