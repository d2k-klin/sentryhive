# SentryHive client-onboarding role (Terraform).
#
# A CLIENT deploys this in THEIR account to grant a consultant read-only audit
# access. Mirrors iam/audit-role.cfn.yaml. Least-privilege: AWS-managed
# SecurityAudit + ViewOnlyAccess plus a small set of extra read permissions the
# bundled scanners need. No write/delete/data-plane actions.
#
# Usage:
#   terraform apply \
#     -var 'trusted_principal_arn=arn:aws:iam::<CONSULTANT_ACCOUNT_ID>:root' \
#     -var 'external_id=<shared-secret>'
#
# Then hand the consultant the role ARN (output below); they run:
#   sentryhive scan --role-arn <role_arn> --external-id <shared-secret>

variable "trusted_principal_arn" {
  type        = string
  description = "ARN allowed to assume this role (the consultant's account root or a specific principal)."
}

variable "external_id" {
  type        = string
  description = "Shared secret required when assuming the role (recommended for third-party access)."
  default     = ""
}

variable "role_name" {
  type    = string
  default = "SentryHiveAudit"
}

data "aws_iam_policy_document" "assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [var.trusted_principal_arn]
    }

    dynamic "condition" {
      for_each = var.external_id == "" ? [] : [var.external_id]
      content {
        test     = "StringEquals"
        variable = "sts:ExternalId"
        values   = [condition.value]
      }
    }
  }
}

data "aws_iam_policy_document" "extra_read" {
  statement {
    sid    = "SentryHiveIamPolicyAnalysis"
    effect = "Allow"
    actions = [
      "iam:GenerateCredentialReport",
      "iam:GetAccountAuthorizationDetails",
      "iam:GetCredentialReport",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "SentryHiveEksReadOnly"
    effect = "Allow"
    actions = [
      "eks:DescribeCluster",
      "eks:ListClusters",
      "eks:DescribeNodegroup",
      "eks:ListNodegroups",
      "eks:DescribeAddon",
      "eks:ListAddons",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role" "sentryhive_audit" {
  name                 = var.role_name
  assume_role_policy   = data.aws_iam_policy_document.assume.json
  max_session_duration = 3600

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/SecurityAudit",
    "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess",
  ]
}

resource "aws_iam_role_policy" "extra_read" {
  name   = "SentryHiveExtraReadOnly"
  role   = aws_iam_role.sentryhive_audit.id
  policy = data.aws_iam_policy_document.extra_read.json
}

output "role_arn" {
  description = "Pass this to SentryHive via --role-arn"
  value       = aws_iam_role.sentryhive_audit.arn
}
