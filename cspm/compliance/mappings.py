"""Static compliance mapping seed data with commercial framework expansions.

Supports CIS (AWS/GCP/Azure), SOC 2, ISO 27001, PCI DSS v4, FedRAMP, GDPR, CCPA, DORA, NIS2, and CSA CCM.
"""

from __future__ import annotations

FRAMEWORKS = [
    "cis_aws_v2", "cis_gcp_v2", "cis_azure_v2", "soc2", "iso27001", "pci_dss_v4",
    "fedramp_high", "gdpr", "ccpa", "dora", "nis2", "csa_ccm"
]

# check_id -> {framework: [control_ids]}
SEED_MAPPINGS: dict[str, dict[str, list[str]]] = {
    "aws_iam_root_mfa": {
        "cis_aws_v2": ["1.5"],
        "soc2": ["CC6.1"],
        "iso27001": ["A.9.4.2"],
        "pci_dss_v4": ["8.4.2"],
        "fedramp_high": ["IA-2(1)"],
        "gdpr": ["Art-32"],
        "dora": ["Art-9"],
        "csa_ccm": ["IAM-02"],
    },
    "aws_iam_password_policy": {
        "cis_aws_v2": ["1.8"],
        "soc2": ["CC6.1"],
        "iso27001": ["A.9.4.3"],
        "pci_dss_v4": ["8.3.6"],
        "fedramp_high": ["IA-5(1)"],
        "csa_ccm": ["IAM-03"],
    },
    "aws_iam_access_key_age": {
        "cis_aws_v2": ["1.14"],
        "soc2": ["CC6.1"],
        "pci_dss_v4": ["8.3.9"],
        "fedramp_high": ["AC-2"],
    },
    "aws_iam_wildcard_policies": {
        "cis_aws_v2": ["1.16"],
        "soc2": ["CC6.3"],
        "iso27001": ["A.9.2.3"],
        "fedramp_high": ["AC-6"],
        "dora": ["Art-9"],
    },
    "aws_s3_public_access_block": {
        "cis_aws_v2": ["2.1.5"],
        "soc2": ["CC6.1"],
        "iso27001": ["A.13.1.3"],
        "pci_dss_v4": ["1.3.1"],
        "fedramp_high": ["AC-3"],
        "gdpr": ["Art-32"],
        "ccpa": ["Sec-1798.100"],
        "nis2": ["Art-21"],
        "csa_ccm": ["DSP-01"],
    },
    "aws_s3_encryption": {
        "cis_aws_v2": ["2.1.1"],
        "soc2": ["CC6.7"],
        "iso27001": ["A.10.1.1"],
        "pci_dss_v4": ["3.5.1"],
        "fedramp_high": ["SC-28"],
        "gdpr": ["Art-32"],
        "ccpa": ["Sec-1798.100"],
        "csa_ccm": ["EKM-01"],
    },
    "aws_sg_open_ssh_rdp": {
        "cis_aws_v2": ["5.2"],
        "soc2": ["CC6.6"],
        "iso27001": ["A.13.1.1"],
        "pci_dss_v4": ["1.2.1"],
        "fedramp_high": ["SC-7"],
        "dora": ["Art-9"],
        "nis2": ["Art-21"],
    },
    "aws_ec2_imdsv2": {
        "cis_aws_v2": ["5.6"],
        "soc2": ["CC6.6"],
        "fedramp_high": ["SI-4"],
    },
    "aws_rds_public_access": {
        "cis_aws_v2": ["2.3.3"],
        "soc2": ["CC6.6"],
        "pci_dss_v4": ["1.3.1"],
        "fedramp_high": ["AC-3"],
        "gdpr": ["Art-32"],
    },
    "aws_rds_encryption": {
        "cis_aws_v2": ["2.3.1"],
        "soc2": ["CC6.7"],
        "pci_dss_v4": ["3.5.1"],
        "fedramp_high": ["SC-28"],
        "gdpr": ["Art-32"],
    },
    "aws_cloudtrail_enabled": {
        "cis_aws_v2": ["3.1"],
        "soc2": ["CC7.2"],
        "iso27001": ["A.12.4.1"],
        "pci_dss_v4": ["10.2.1"],
        "fedramp_high": ["AU-2"],
        "dora": ["Art-10"],
        "nis2": ["Art-21"],
    },
    "aws_kms_key_rotation": {
        "cis_aws_v2": ["3.8"],
        "soc2": ["CC6.7"],
        "pci_dss_v4": ["3.6.1"],
        "fedramp_high": ["SC-12"],
    },
    "aws_guardduty_enabled": {
        "cis_aws_v2": ["4.16"],
        "soc2": ["CC7.1"],
        "iso27001": ["A.12.4.1"],
        "fedramp_high": ["SI-4"],
        "dora": ["Art-10"],
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
