# main.tf
# This is a simple S3 bucket configuration for a compliant environment.
terraform {
  required_version = ">= 1.6"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

provider "aws" {
  region = "us-east-1"

    default_tags {
    tags = {
      Project         = var.project_name
      Environment     = var.environment
      ManagedBy       = "terraform"
      ComplianceScope = "cge-p-lab"
    }
  }
}

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

locals {
  effective_suffix = var.bucket_suffix != "" ? var.bucket_suffix : random_id.bucket_suffix.hex
  primary_name     = "${var.project_name}-${var.environment}-data-${local.effective_suffix}"
  log_name         = "${var.project_name}-${var.environment}-logs-${local.effective_suffix}"
  trail_name       = "cgep-lab-cloudtrail-${local.effective_suffix}"

}


resource "aws_kms_key" "main" {
  description             = "Customer-managed key for encrypting sensitive data"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  
  tags = {
    Environment = var.environment
    Purpose     = "data-encryption"
  }
}
# KMS key generated:
resource "aws_kms_alias" "main_alias" {
  name          = "alias/aws_acme_key"
  target_key_id = aws_kms_key.main.id
}
resource "aws_s3_bucket" "primary" {
  bucket = local.primary_name
}

# SC-28: Protection of information at rest.

resource "aws_s3_bucket_server_side_encryption_configuration" "primary" {
  bucket = aws_s3_bucket.primary.id

  # KMS added:
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.id
    }
    bucket_key_enabled = true
  }
}

# CM-6: Versioning preserves prior object states for recovery and audit.
resource "aws_s3_bucket_versioning" "primary" {
  bucket = aws_s3_bucket.primary.id
  versioning_configuration {
    status = "Enabled"
  }
}

# AC-3: Access control, explicit deny on every public access vector.
resource "aws_s3_bucket_public_access_block" "primary" {
  bucket                  = aws_s3_bucket.primary.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# AU-3 / AU-6: Content of audit records + audit review.
resource "aws_s3_bucket" "log" {
  bucket = local.log_name
}

resource "aws_s3_bucket_ownership_controls" "log" {
  bucket = aws_s3_bucket.log.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "log" {
  depends_on = [aws_s3_bucket_ownership_controls.log]
  bucket     = aws_s3_bucket.log.id
  acl        = "log-delivery-write"
}

resource "aws_s3_bucket_versioning" "log" {
  bucket = aws_s3_bucket.log.id
  versioning_configuration {
    status = "Enabled"
  }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "log" {
  bucket = aws_s3_bucket.log.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.id
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "log" {
  bucket                  = aws_s3_bucket.log.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "primary" {
  bucket        = aws_s3_bucket.primary.id
  target_bucket = aws_s3_bucket.log.id
  target_prefix = "access-logs/"
}

resource "aws_s3_bucket" "trail" {
  bucket        = local.trail_name
  force_destroy = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.id
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_caller_identity" "current" {}
data "aws_iam_policy_document" "trail" {
  statement {
    sid       = "AWSCloudTrailAclCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/cgep-lab-mgmt"]
    }
  }

  statement {
    sid       = "AWSCloudTrailWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/cgep-lab-mgmt"]
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = data.aws_iam_policy_document.trail.json
}

resource "aws_cloudtrail" "mgmt" {
  name                          = "cgep-lab-mgmt"
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  depends_on = [aws_s3_bucket_policy.trail]
}

resource "aws_securityhub_account" "this" {}

resource "aws_securityhub_standards_subscription" "nist_800_53" {
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/nist-800-53/v/5.0.0"
  depends_on    = [aws_securityhub_account.this]
}

resource "aws_securityhub_standards_subscription" "fsbp" {
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.this]
}