"""Compliance scoring, evidence export, and remediation prioritization (6.3).

Scoring model (spec): compliance score = checks_passed / checks_applicable per
framework. A framework control is "applicable" if some audit check maps to it;
it is "failed" if any finding exists for a mapped check, otherwise "passed".
"""

from __future__ import annotations

from datetime import datetime, timezone

from cspm.compliance.mappings import SEED_MAPPINGS


def _applicable_checks(framework: str) -> set[str]:
    return {cid for cid, fw in SEED_MAPPINGS.items() if framework in fw}


def compute_scores(failed_check_ids: set[str]) -> dict[str, dict]:
    """Per-framework compliance percentage from the set of failed check ids.

    ``failed_check_ids`` is the distinct set of check_ids that produced findings.
    """
    scores: dict[str, dict] = {}
    frameworks = {fw for m in SEED_MAPPINGS.values() for fw in m}
    for framework in sorted(frameworks):
        applicable = _applicable_checks(framework)
        if not applicable:
            continue
        failed = applicable & failed_check_ids
        passed = applicable - failed
        pct = round((len(passed) / len(applicable)) * 100, 1)
        scores[framework] = {
            "score": pct,
            "checks_applicable": len(applicable),
            "checks_passed": len(passed),
            "checks_failed": len(failed),
            "failed_checks": sorted(failed),
        }
    return scores


def controls_for_check(check_id: str) -> dict[str, list[str]]:
    return SEED_MAPPINGS.get(check_id, {})


def remediation_priority(findings: list) -> list:
    """Sort findings so those touching the most framework controls come first.

    Ties break by severity. ``findings`` are auditor Finding objects or dict-like
    records exposing ``check_id`` and ``severity``.
    """
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    def score(f):
        check_id = getattr(f, "check_id", None) or f.get("check_id", "")
        severity = getattr(f, "severity", None) or f.get("severity", "info")
        control_count = sum(len(v) for v in SEED_MAPPINGS.get(check_id, {}).values())
        return (control_count, sev_rank.get(severity, 0))

    return sorted(findings, key=score, reverse=True)


def evidence_report(framework: str, findings: list) -> dict:
    """Auditor-ready evidence: control, result, timestamp, resource id."""
    applicable = _applicable_checks(framework)
    failed_by_check: dict[str, list] = {}
    for f in findings:
        cid = getattr(f, "check_id", None) or f.get("check_id", "")
        if cid in applicable:
            failed_by_check.setdefault(cid, []).append(f)

    now = datetime.now(timezone.utc).isoformat()
    controls = []
    for check_id in sorted(applicable):
        offenders = failed_by_check.get(check_id, [])
        result = "fail" if offenders else "pass"
        for control_id in SEED_MAPPINGS[check_id].get(framework, []):
            controls.append(
                {
                    "control_id": control_id,
                    "check_id": check_id,
                    "result": result,
                    "timestamp": now,
                    "resources": [
                        getattr(f, "resource", None) or f.get("resource")
                        for f in offenders
                    ],
                }
            )
    scores = compute_scores(set(failed_by_check))
    return {
        "framework": framework,
        "generated_at": now,
        "score": scores.get(framework, {}).get("score", 100.0),
        "controls": controls,
    }
