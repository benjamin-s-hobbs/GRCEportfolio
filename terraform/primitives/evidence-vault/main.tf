# terraform/primitives/evidence-vault/main.tf
# This is a simple S3 bucket configuration for an evidence vault.
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
      Environment     = "evidence"
      ManagedBy       = "terraform"
      ComplianceScope = "cge-p-lab"
    }
  }
}

resource "random_id" "suffix" { byte_length = 4 }

locals {
  vault_name = "${var.project_name}-grc-evidence-vault-${random_id.suffix.hex}"
  vault_log  = "${var.project_name}-grc-evidence-vault-logs${random_id.suffix.hex}"
}

resource "aws_kms_key" "main" {
  description             = "Customer-managed key for encrypting sensitive data"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Environment = "evidence"
    Purpose     = "data-encryption"
  }
}

resource "aws_kms_key" "main" {
  # checkov:skip=CKV2_AWS_64: "Accepted risk: KMS key configuration reviewed and deemed appropriate for the environment."
  description             = "Customer-managed key for encrypting sensitive data"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Environment = "evidence"
    Purpose     = "data-encryption"
  }
}

resource "aws_kms_alias" "main_alias" {
  name          = "alias/aws_acme_key"
  target_key_id = aws_kms_key.main.key_id
}

resource "aws_s3_bucket" "vault" {
  # checkov:skip=CKV2_AWS_62: "Accepted risk: S3 buckets event notifications enabled deferred to next sprint."
  # checkov:skip=CKV_AWS_18: "Accepted risk: S3 bucket configuration reviewed and deemed appropriate for the environment."
  # checkov:skip=CKV_AWS_144: "Accepted risk: S3 buckets cross-region replication enablement deferred to next sprint."
  # checkov:skip=CKV2_AWS_61: "Accepted risk: S3 bucket lifecycle policies reviewed and accepted."
  bucket              = local.vault_name
  object_lock_enabled = true # MUST be set at bucket creation
}

resource "aws_s3_bucket_versioning" "vault" {
  bucket = aws_s3_bucket.vault.id
  versioning_configuration { status = "Enabled" } # Object Lock requires versioning
}

resource "aws_s3_bucket_object_lock_configuration" "vault" {
  bucket = aws_s3_bucket.vault.id

  rule {
    default_retention {
      mode = var.lock_mode # GOVERNANCE for labs, COMPLIANCE for production
      days = var.retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.vault]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "vault" {
  bucket = aws_s3_bucket.vault.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.key_id
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "vault" {
  bucket                  = aws_s3_bucket.vault.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Refuse bucket deletion from anyone except the account root.
data "aws_caller_identity" "current" {}

resource "aws_s3_bucket_policy" "vault" {
  bucket = aws_s3_bucket.vault.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyBucketDeletion"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:DeleteBucket"
      Resource  = aws_s3_bucket.vault.arn
      Condition = {
        StringNotEquals = {
          "aws:PrincipalArn" = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
      }
    }]
  })
}

# AU-3 / AU-6: Content of audit records + audit review.
resource "aws_s3_bucket" "vault_log" {
  # checkov:skip=CKV2_AWS_62: "Accepted risk: S3 buckets event notifications enabled deferred to next sprint."
  # checkov:skip=CKV_AWS_144: "Accepted risk: S3 buckets cross-region replication enablement deferred to next sprint."
  bucket = local.vault_log.id

  lifecycle {
    prevent_destroy = false # set to "true" for use in production
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "vault_log_lifecycle" {
  bucket = aws_s3_bucket.vault_log.id

  rule {
    id     = "log-retention-and-cleanup"
    status = "Enabled"

    # Cleans up failed uploads to save storage costs
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    # Automatically deletes logs older than 1 year (365 days)
    expiration {
      days = 365
    }
  }
}
resource "aws_s3_bucket_versioning" "vault_log" {
  bucket = aws_s3_bucket.vault_log.id
  versioning_configuration {
    status = "Enabled"
  }
}
resource "aws_s3_bucket_ownership_controls" "vault_log" {
  # checkov:skip=CKV2_AWS_65: "Accepted risk: S3 buckets access control lists disablement deferred to next sprint."
  bucket = aws_s3_bucket.vault_log.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "vault_log" {
  depends_on = [aws_s3_bucket_ownership_controls.vault_log]
  bucket     = aws_s3_bucket.vault_log.id
  acl        = "log-delivery-write"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "vault_log" {
  bucket = aws_s3_bucket.vault_log.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.key_id
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "vault_log" {
  bucket                  = aws_s3_bucket.vault_log.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "primary" {
  bucket        = aws_s3_bucket.primary.id
  target_bucket = aws_s3_bucket.vault_log.id
  target_prefix = "access-logs/"
}


data "aws_caller_identity" "current" {}
resource "aws_s3_bucket_policy" "vault_log" {
  bucket = aws_s3_bucket.vault_log.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyBucketDeletion"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:DeleteBucket"
      Resource  = aws_s3_bucket.vault_log.arn
      Condition = {
        StringNotEquals = {
          "aws:PrincipalArn" = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
      }
    }]
  })
}
