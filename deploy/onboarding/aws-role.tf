# Aegis CSPM — read-only cross-account audit role (Terraform equivalent).
# Usage:
#   terraform apply \
#     -var aegis_account_id=123456789012 \
#     -var external_id=<from the Aegis Connect dialog>

variable "aegis_account_id" {
  type        = string
  description = "Aegis platform AWS account ID allowed to assume this role."
}

variable "external_id" {
  type        = string
  description = "Per-org External ID from the Aegis Connect AWS dialog."
  sensitive   = true
}

variable "role_name" {
  type    = string
  default = "AegisCSPMAuditRole"
}

data "aws_iam_policy_document" "trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.aegis_account_id}:root"]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.external_id]
    }
  }
}

resource "aws_iam_role" "aegis_audit" {
  name                 = var.role_name
  description          = "Read-only role assumed by Aegis CSPM for security auditing."
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600
  tags = {
    managed-by = "aegis-cspm"
    purpose    = "read-only-security-audit"
  }
}

resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.aegis_audit.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "view_only" {
  role       = aws_iam_role.aegis_audit.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}

output "role_arn" {
  description = "Paste into the Aegis Connect AWS dialog."
  value       = aws_iam_role.aegis_audit.arn
}
