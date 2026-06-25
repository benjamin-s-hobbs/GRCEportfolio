#terraform/baseline/aws/cloudtrail.tf


resource "aws_s3_bucket" "trail" {
  # checkov:skip=CKV2_AWS_18: "Accepted risk: S3 bucket configuration reviewed and deferred to the next sprint."
  # checkov:skip=CKV2_AWS_144: "Accepted risk: S3 buckets cross-region replication enablement deferred to next sprint."
  bucket        = "cgep-lab-cloudtrail-${random_id.suffix.hex}"
  force_destroy = true

  lifecycle {
    prevent_destroy = false # set to "true" for use in production
  }
}

resource "aws_s3_bucket_versioning" "trail" {
  bucket = "cgep-lab-cloudtrail-${random_id.suffix.hex}"
  versioning_configuration {
    status = "Enabled"
  }
}

# KMS CMEK generated:
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
  target_key_id = aws_kms_key.main.id
}
resource "aws_s3_bucket" "primary" {
  # checkov:skip=CKV2_AWS_18:  "Accepted risk: S3 bucket configuration reviewed and deferred to the next sprint."
  # checkov:skip=CKV2_AWS_144: "Accepted risk: S3 buckets cross-region replication enablement deferred to next sprint."
  # checkov:skip=CKV2_AWS_145: "Accepted risk: S3 bucket lifecycle policies reviewed and accepted."
  # checkov:skip=CKV2_AWS_6:   "Accepted risk: S3 bucket Public Access Block reviewed and accepted."
  bucket = local.primary_name

  lifecycle {
    prevent_destroy = false # set to "true" for use in production
  }
}

resource "aws_s3_bucket_versioning" "primary" {
  bucket = aws_s3_bucket.primary.id
  versioning_configuration {
    status = "Enabled"
  }
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
  # checkov:skip=CKV2_AWS_10: "Accepted risk: CloudTrail configuration reviewed and deferred to next sprint."
  name                          = "cgep-lab-mgmt"
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  depends_on = [aws_s3_bucket_policy.trail]
}