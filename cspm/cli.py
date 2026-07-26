"""Command-line interface for the CSPM audit engine.

Runs the AWS audit engine directly. With ``--demo`` it uses an in-memory fake
AWS account (intentionally insecure) so you can see the full pipeline —
findings + compliance scoring — without real credentials.
"""

from __future__ import annotations

import argparse
import json
import sys

from cspm.auditors.aws import AWSAuditor
from cspm.compliance import compute_scores, remediation_priority

_SEV_COLORS = {
    "critical": "\033[95m",
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[94m",
    "info": "\033[90m",
}
_RESET = "\033[0m"


def _build_auditor(args) -> AWSAuditor:
    if args.demo:
        from cspm.fakes import FakeAWSSession

        return AWSAuditor(session=FakeAWSSession())
    return AWSAuditor(role_arn=args.role_arn, external_id=args.external_id)


def _print_table(findings, use_color: bool) -> None:
    failed_ids = {f.check_id for f in findings}
    scores = compute_scores(failed_ids)
    print("=" * 72)
    print("  AWS SECURITY AUDIT — Tool 6 CSPM")
    print("=" * 72)
    print(f"  Findings: {len(findings)}")
    print("  Compliance scores:")
    for fw, data in scores.items():
        print(f"    {fw:14} {data['score']:5}%  "
              f"({data['checks_passed']}/{data['checks_applicable']} controls)")
    print("-" * 72)
    for f in remediation_priority(findings):
        color = _SEV_COLORS.get(f.severity, "") if use_color else ""
        reset = _RESET if use_color else ""
        print(f"  {color}[{f.severity.upper():8}]{reset} {f.check}")
        print(f"      {f.resource}")
        print(f"      fix: {f.remediation}")
    if not findings:
        print("  No findings. \U0001F389")
    print("=" * 72)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cspm", description="CSPM AWS audit engine")
    parser.add_argument("--demo", action="store_true", help="Use in-memory fake AWS account.")
    parser.add_argument("--role-arn", help="Cross-account role ARN (live mode).")
    parser.add_argument("--external-id", help="STS external id (live mode).")
    parser.add_argument("--format", choices=["table", "json"], default="table")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args(argv)

    if not args.demo and not args.role_arn:
        parser.error("provide --role-arn for live mode, or --demo for sample data.")

    findings = _build_auditor(args).run_all()

    if args.format == "json":
        failed_ids = {f.check_id for f in findings}
        print(json.dumps(
            {
                "findings": [vars(f) for f in findings],
                "compliance": compute_scores(failed_ids),
            },
            indent=2,
        ))
    else:
        _print_table(findings, use_color=not args.no_color and sys.stdout.isatty())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
