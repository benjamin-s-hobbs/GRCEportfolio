# HIPAA Security Rule: Encryption Safeguards (for AWS)
# METADATA
# title: Sensitive Data Encryption at Rest 
# description: "Every aws_s3_bucket must have an aws_s3_bucket_server_side_encryption_configuration that references it."
# custom:
#   control_id: 164.312(a)(2)(iv)
#   framework: nist-800-66 r2 (HIPAA Security Rule)
#   severity: high
#   remediation: "Add aws_s3_bucket_server_side_encryption_configuration { bucket = aws_s3_bucket.<name>.id ... } for the bucket."
package aws.compliance.hipaa.s3_cmk_encryption

import rego.v1

# Match by Terraform reference in `configuration`, not by literal bucket name in
# `planned_values`. At plan time the bucket name is often "(known after apply)".

# HIPAA Security Rule: Encryption Safeguards
# Requires S3 buckets to use Customer-Managed Keys (CMK) via AWS KMS.
default allow := false

allow if {
    count(violations) == 0
}

# Rule 1: Catch buckets completely missing an encryption configuration resource
violations[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    bucket_name := resource.name
    
    # Check if this bucket lacks a corresponding encryption configuration resource
    not has_encryption_resource(bucket_name)

    msg := sprintf("HIPAA Violation: S3 bucket '%v' is missing a dedicated encryption configuration resource.", [bucket_name])
}

# Rule 2: Verify the encryption configuration uses 'aws:kms' and a custom key ID
violations[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    
    rules := resource.change.after.rule[_]
    sse_config := rules.apply_server_side_encryption_by_default[_]
    
    # Violation if it does not use KMS
    sse_config.sse_algorithm != "aws:kms"
    
    msg := sprintf("HIPAA Violation: S3 encryption configuration '%v' does not use 'aws:kms'. Standard S3 encryption (AES256) is forbidden. Customer-Managed Keys (CMK) must be used.", [resource.address])
}

violations[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    
    rules := resource.change.after.rule[_]
    sse_config := rules.apply_server_side_encryption_by_default[_]
    
    # Enforce KMS, but catch cases where the specific key ID is missing (defaults to AWS-managed key)
    sse_config.sse_algorithm == "aws:kms"
    not has_custom_key(sse_config)
    
    msg := sprintf("HIPAA Violation: S3 encryption configuration '%v' is using the default AWS-managed key ('aws/s3'). A Customer-Managed Key (CMK) ARN must be specified.", [resource.address])
}

# --- Helper Functions ---

# Helper to verify if an encryption resource points to the bucket
has_encryption_resource(bucket_name) if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    contains(resource.change.after.bucket, bucket_name)
}

# Helper to check that kms_master_key_id is populated and not using the default AWS-managed alias
has_custom_key(sse_config) if {
    key_id := sse_config.kms_master_key_id
    key_id != ""
    not contains(key_id, "alias/aws/s3")
}
