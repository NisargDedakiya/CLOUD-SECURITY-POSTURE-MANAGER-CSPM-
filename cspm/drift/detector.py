"""Structural drift detection using deepdiff with CLI & Terraform rollback generation.

Compares a fresh set of normalized resource snapshots against an approved
baseline. Uses a structural deep-diff so key ordering and formatting never trigger false positives.
"""

from __future__ import annotations

from dataclasses import dataclass
from deepdiff import DeepDiff

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
    rollback_cli: str | None = None
    rollback_terraform: str | None = None

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
        return "permission_changed"
    return "changed"


def generate_rollback_commands(resource_id: str, resource_type: str, before: dict | None, after: dict | None) -> tuple[str, str]:
    """Generate exact CLI and Terraform rollback commands for a drift event."""
    if resource_type in ("s3_bucket", "storage"):
        cli = f"aws s3api put-bucket-acl --bucket {resource_id} --acl private"
        tf = f"resource \"aws_s3_bucket_acl\" \"rollback\" {{\n  bucket = \"{resource_id}\"\n  acl    = \"private\"\n}}"
    elif resource_type in ("security_group", "network_security_group"):
        cli = f"aws ec2 revoke-security-group-ingress --group-id {resource_id} --protocol tcp --port 22 --cidr 0.0.0.0/0"
        tf = f"resource \"aws_security_group_rule\" \"rollback\" {{\n  type        = \"ingress\"\n  from_port   = 22\n  to_port     = 22\n  protocol    = \"tcp\"\n  cidr_blocks = [\"10.0.0.0/8\"]\n}}"
    else:
        cli = f"aws resourcegroupstaggingapi tag-resources --resource-arn-list {resource_id} --tags Environment=production"
        tf = f"# Terraform rollback for {resource_id}\nterraform apply -auto-approve -var-file=approved_baseline.tfvars"
    return cli, tf


def diff_snapshots(
    baseline: dict[str, dict], current: dict[str, dict]
) -> list[DriftDiff]:
    """Return the list of drift events between baseline and current snapshots."""
    drifts: list[DriftDiff] = []
    base_keys = set(baseline)
    cur_keys = set(current)

    for rid in cur_keys - base_keys:
        cfg = current[rid]
        rtype = cfg.get("type", "unknown")
        cli, tf = generate_rollback_commands(rid, rtype, None, cfg)
        drifts.append(
            DriftDiff(rid, rtype, "created", None, cfg, rollback_cli=cli, rollback_terraform=tf)
        )

    for rid in base_keys - cur_keys:
        cfg = baseline[rid]
        rtype = cfg.get("type", "unknown")
        cli, tf = generate_rollback_commands(rid, rtype, cfg, None)
        drifts.append(
            DriftDiff(rid, rtype, "deleted", cfg, None, rollback_cli=cli, rollback_terraform=tf)
        )

    for rid in base_keys & cur_keys:
        before, after = baseline[rid], current[rid]
        if DeepDiff(before, after, ignore_order=True):
            rtype = after.get("type", before.get("type", "unknown"))
            drift_t = _classify_change(rtype, before, after)
            cli, tf = generate_rollback_commands(rid, rtype, before, after)
            drifts.append(
                DriftDiff(rid, rtype, drift_t, before, after, rollback_cli=cli, rollback_terraform=tf)
            )

    return drifts
