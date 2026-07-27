"""Static compliance mapping seed data (spec 6.3).

Each audit ``check_id`` maps to one or more framework control ids. This is a
static seed populated once from the published CIS / SOC 2 / ISO 27001 / PCI DSS
control lists — it is not user-editable data.
"""

from __future__ import annotations

FRAMEWORKS = ["cis_aws_v2", "soc2", "iso27001", "pci_dss_v4"]

# check_id -> {framework: [control_ids]}
SEED_MAPPINGS: dict[str, dict[str, list[str]]] = {
    "aws_iam_root_mfa": {
        "cis_aws_v2": ["1.5"],
        "soc2": ["CC6.1"],
        "iso27001": ["A.9.4.2"],
        "pci_dss_v4": ["8.4.2"],
    },
    "aws_iam_password_policy": {
        "cis_aws_v2": ["1.8"],
        "soc2": ["CC6.1"],
        "iso27001": ["A.9.4.3"],
        "pci_dss_v4": ["8.3.6"],
    },
    "aws_iam_access_key_age": {
        "cis_aws_v2": ["1.14"],
        "soc2": ["CC6.1"],
        "pci_dss_v4": ["8.3.9"],
    },
    "aws_iam_wildcard_policies": {
        "cis_aws_v2": ["1.16"],
        "soc2": ["CC6.3"],
        "iso27001": ["A.9.2.3"],
    },
    "aws_s3_public_access_block": {
        "cis_aws_v2": ["2.1.5"],
        "soc2": ["CC6.1"],
        "iso27001": ["A.13.1.3"],
        "pci_dss_v4": ["1.3.1"],
    },
    "aws_s3_encryption": {
        "cis_aws_v2": ["2.1.1"],
        "soc2": ["CC6.7"],
        "iso27001": ["A.10.1.1"],
        "pci_dss_v4": ["3.5.1"],
    },
    "aws_sg_open_ssh_rdp": {
        "cis_aws_v2": ["5.2"],
        "soc2": ["CC6.6"],
        "iso27001": ["A.13.1.1"],
        "pci_dss_v4": ["1.2.1"],
    },
    "aws_ec2_imdsv2": {
        "cis_aws_v2": ["5.6"],
        "soc2": ["CC6.6"],
    },
    "aws_rds_public_access": {
        "cis_aws_v2": ["2.3.3"],
        "soc2": ["CC6.6"],
        "pci_dss_v4": ["1.3.1"],
    },
    "aws_rds_encryption": {
        "cis_aws_v2": ["2.3.1"],
        "soc2": ["CC6.7"],
        "pci_dss_v4": ["3.5.1"],
    },
    "aws_cloudtrail_enabled": {
        "cis_aws_v2": ["3.1"],
        "soc2": ["CC7.2"],
        "iso27001": ["A.12.4.1"],
        "pci_dss_v4": ["10.2.1"],
    },
    "aws_kms_key_rotation": {
        "cis_aws_v2": ["3.8"],
        "soc2": ["CC6.7"],
        "pci_dss_v4": ["3.6.1"],
    },
    "aws_guardduty_enabled": {
        "cis_aws_v2": ["4.16"],
        "soc2": ["CC7.1"],
        "iso27001": ["A.12.4.1"],
    },
    "aws_s3_versioning": {"cis_aws_v2": ["2.1.3"], "soc2": ["A1.2"]},
    "aws_s3_access_logging": {
        "cis_aws_v2": ["3.6"],
        "soc2": ["CC7.2"],
        "pci_dss_v4": ["10.2.1"],
    },
    "aws_ebs_default_encryption": {
        "cis_aws_v2": ["2.2.1"],
        "soc2": ["CC6.7"],
        "pci_dss_v4": ["3.5.1"],
    },
    "aws_ebs_volume_encryption": {
        "cis_aws_v2": ["2.2.1"],
        "soc2": ["CC6.7"],
        "iso27001": ["A.10.1.1"],
    },
    "aws_iam_user_mfa": {
        "cis_aws_v2": ["1.10"],
        "soc2": ["CC6.1"],
        "pci_dss_v4": ["8.4.2"],
    },
    "aws_cloudtrail_log_validation": {
        "cis_aws_v2": ["3.2"],
        "soc2": ["CC7.2"],
        "iso27001": ["A.12.4.3"],
    },
    "aws_vpc_flow_logs": {
        "cis_aws_v2": ["3.9"],
        "soc2": ["CC7.2"],
        "pci_dss_v4": ["10.2.1"],
    },
    "aws_rds_backup_retention": {"cis_aws_v2": ["2.3.2"], "soc2": ["A1.2"]},
    "aws_rds_deletion_protection": {"soc2": ["A1.2"]},
    "aws_secretsmanager_rotation": {
        "cis_aws_v2": ["3.8"],
        "soc2": ["CC6.7"],
        "pci_dss_v4": ["3.6.1"],
    },
}


def seed_mappings(db) -> int:
    """Populate the compliance_mappings table if empty. Returns rows inserted."""
    from cspm.models import ComplianceMapping

    if db.query(ComplianceMapping).first() is not None:
        return 0
    count = 0
    for check_id, frameworks in SEED_MAPPINGS.items():
        for framework, controls in frameworks.items():
            for control_id in controls:
                db.add(
                    ComplianceMapping(
                        check_id=check_id, framework=framework, control_id=control_id
                    )
                )
                count += 1
    db.commit()
    return count
