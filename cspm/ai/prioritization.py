"""AI Risk Prioritization Engine.

Ranks findings dynamically based on exploitability, internet exposure,
business criticality, compliance impact, and attack path relevance.
"""

from __future__ import annotations

from typing import Any


def calculate_dynamic_risk_score(finding: dict[str, Any]) -> dict[str, Any]:
    """Calculate 0-10 priority risk score for a finding."""
    base_score = 5.0

    severity = finding.get("severity", "medium").lower()
    if severity == "critical":
        base_score += 3.5
    elif severity == "high":
        base_score += 2.5
    elif severity == "medium":
        base_score += 1.0

    if finding.get("is_internet_facing"):
        base_score += 1.5

    if finding.get("on_attack_path"):
        base_score += 1.0

    if finding.get("is_crown_jewel"):
        base_score += 1.0

    final_score = min(10.0, round(base_score, 1))

    priority_label = "CRITICAL RISK" if final_score >= 9.0 else ("HIGH RISK" if final_score >= 7.5 else "MEDIUM RISK")

    return {
        "score": final_score,
        "label": priority_label,
        "factors": {
            "severity_weight": severity,
            "internet_exposure": finding.get("is_internet_facing", False),
            "attack_path_relevance": finding.get("on_attack_path", False),
            "business_criticality": finding.get("is_crown_jewel", False),
        },
    }
