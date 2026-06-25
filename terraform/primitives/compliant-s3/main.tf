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
}

resource "aws_kms_key" "main" {
  # checkov:skip=CKV2_AWS_64: "Accepted risk: KMS key configuration reviewed and deemed appropriate for the environment."
  description             = "Customer-managed key for encrypting sensitive data"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Environment = var.environment
    Purpose     = "data-encryption"
  }
}

resource "aws_kms_alias" "main_alias" {
  name          = "alias/aws_acme_key"
  target_key_id = aws_kms_key.main.key_id
}

resource "aws_s3_bucket" "primary" {
  # checkov:skip=CKV2_AWS_62: "Accepted risk: S3 buckets event notifications enabled deferred to next sprint."
  # checkov:skip=CKV2_AWS_144: "Accepted risk: S3 buckets cross-region replication enablement deferred to next sprint."
  bucket = local.primary_name

  lifecycle {
    prevent_destroy = false # set to "true" for use in production
  }
}

# SC-28: Protection of information at rest.
# AES-256 keeps this lab simple. The commented block below shows how you'd
# switch to KMS-managed keys, covered in a later lab.
resource "aws_s3_bucket_server_side_encryption_configuration" "primary" {
  bucket = aws_s3_bucket.primary.id

  # KMS teaser:
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.key_id
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
  # checkov:skip=CKV2_AWS_62: "Accepted risk: S3 buckets event notifications enabled deferred to next sprint."
  # checkov:skip=CKV2_AWS_144: "Accepted risk: S3 buckets cross-region replication enablement deferred to next sprint."
  bucket = local.log_name

  lifecycle {
    prevent_destroy = false # set to "true" for use in production
  }
}

resource "aws_s3_bucket_versioning" "log" {
  bucket = aws_s3_bucket.log.id
  versioning_configuration {
    status = "Enabled"
  }
}
resource "aws_s3_bucket_ownership_controls" "log" {
  # checkov:skip=CKV2_AWS_65: "Accepted risk: S3 buckets access control lists disablement deferred to next sprint."
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

resource "aws_s3_bucket_server_side_encryption_configuration" "log" {
  bucket = aws_s3_bucket.log.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.key_id
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

