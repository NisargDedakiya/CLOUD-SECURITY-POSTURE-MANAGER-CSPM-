"""Guarded remediation guidance.

Maps a check_id to concrete, copy-pasteable fixes (Terraform + AWS CLI). This is
*advisory* — CSPM is read-only and never mutates cloud resources. Auto-apply, if
ever built, would gate on an explicit approval workflow.
"""

from __future__ import annotations

# check_id -> {"terraform": ..., "cli": ..., "docs": ...}
REMEDIATIONS: dict[str, dict[str, str]] = {
    "aws_s3_public_access_block": {
        "cli": (
            "aws s3api put-public-access-block --bucket <BUCKET> "
            "--public-access-block-configuration "
            "BlockPublicAcls=true,IgnorePublicAcls=true,"
            "BlockPublicPolicy=true,RestrictPublicBuckets=true"
        ),
        "terraform": (
            'resource "aws_s3_bucket_public_access_block" "this" {\n'
            "  bucket                  = <BUCKET>\n"
            "  block_public_acls       = true\n"
            "  block_public_policy     = true\n"
            "  ignore_public_acls      = true\n"
            "  restrict_public_buckets = true\n}"
        ),
        "docs": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
    },
    "aws_s3_encryption": {
        "cli": (
            "aws s3api put-bucket-encryption --bucket <BUCKET> "
            "--server-side-encryption-configuration "
            '\'{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}\''
        ),
        "terraform": (
            'resource "aws_s3_bucket_server_side_encryption_configuration" "this" {\n'
            "  bucket = <BUCKET>\n  rule {\n"
            "    apply_server_side_encryption_by_default { sse_algorithm = \"aws:kms\" }\n  }\n}"
        ),
        "docs": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-encryption-faq.html",
    },
    "aws_sg_open_ssh_rdp": {
        "cli": (
            "aws ec2 revoke-security-group-ingress --group-id <SG_ID> "
            "--protocol tcp --port 22 --cidr 0.0.0.0/0"
        ),
        "terraform": "# Remove the 0.0.0.0/0 ingress rule for ports 22/3389 from the security group.",
        "docs": "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html",
    },
    "aws_iam_root_mfa": {
        "cli": "# Enable MFA on the root user in the IAM console (cannot be scripted for root).",
        "terraform": "# Root MFA is configured manually in the AWS console.",
        "docs": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html",
    },
    "aws_rds_public_access": {
        "cli": "aws rds modify-db-instance --db-instance-identifier <DB> --no-publicly-accessible --apply-immediately",
        "terraform": "# Set publicly_accessible = false on the aws_db_instance resource.",
        "docs": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.html",
    },
    "aws_guardduty_enabled": {
        "cli": "aws guardduty create-detector --enable --region <REGION>",
        "terraform": 'resource "aws_guardduty_detector" "this" { enable = true }',
        "docs": "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_settingup.html",
    },
}

_GENERIC = {
    "cli": "",
    "terraform": "",
    "docs": "",
}


def remediation_for(check_id: str) -> dict[str, str]:
    """Return remediation snippets for a check_id (empty strings if unknown)."""
    return REMEDIATIONS.get(check_id, _GENERIC)
