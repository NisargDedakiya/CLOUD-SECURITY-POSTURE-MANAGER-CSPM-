"""Structural drift detection using deepdiff (spec 6.4).

Compares a fresh set of normalized resource snapshots against an approved
baseline. Uses a structural deep-diff (not a raw string diff) so key ordering
and formatting never trigger false positives.
"""

from __future__ import annotations

from dataclasses import dataclass

from deepdiff import DeepDiff

# Resource types whose changes are security-sensitive and must alert immediately
# (drift alert re-routes to the 'critical' Celery queue per spec 6.4).
SECURITY_SENSITIVE_TYPES = {
    "iam_policy",
    "iam_role",
    "iam_user",
    "s3_bucket",
    "security_group",
    "network_security_group",
    "firewall_rule",
    "kms_key",
}


@dataclass
class DriftDiff:
    resource_id: str
    resource_type: str
    drift_type: str  # created | deleted | changed | permission_changed
    before_state: dict | None
    after_state: dict | None

    @property
    def security_sensitive(self) -> bool:
        return is_security_sensitive(self.resource_type)


def is_security_sensitive(resource_type: str | None) -> bool:
    return (resource_type or "") in SECURITY_SENSITIVE_TYPES


def _classify_change(resource_type: str, before: dict, after: dict) -> str:
    """Distinguish a permission change from a generic config change."""
    perm_keys = {"ingress", "egress", "policy", "acl", "iam", "security_rules"}
    diff = DeepDiff(before, after, ignore_order=True)
    changed_paths = " ".join(str(k) for k in diff.affected_root_keys) if diff else ""
    if any(pk in changed_paths.lower() for pk in perm_keys):
        return "permission_changed"
    if is_security_sensitive(resource_type):
        # For sensitive resources, any structural change is treated as permission-level.
        return "permission_changed"
    return "changed"


def diff_snapshots(
    baseline: dict[str, dict], current: dict[str, dict]
) -> list[DriftDiff]:
    """Return the list of drift events between baseline and current snapshots.

    Snapshots are ``{resource_id: {"type": ..., ...config...}}``.
    """
    drifts: list[DriftDiff] = []
    base_keys = set(baseline)
    cur_keys = set(current)

    for rid in cur_keys - base_keys:
        cfg = current[rid]
        drifts.append(
            DriftDiff(rid, cfg.get("type", "unknown"), "created", None, cfg)
        )

    for rid in base_keys - cur_keys:
        cfg = baseline[rid]
        drifts.append(
            DriftDiff(rid, cfg.get("type", "unknown"), "deleted", cfg, None)
        )

    for rid in base_keys & cur_keys:
        before, after = baseline[rid], current[rid]
        if DeepDiff(before, after, ignore_order=True):
            rtype = after.get("type", before.get("type", "unknown"))
            drifts.append(
                DriftDiff(rid, rtype, _classify_change(rtype, before, after), before, after)
            )

    return drifts
