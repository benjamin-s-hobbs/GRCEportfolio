# HIPAA Security Rule: Encryption Safeguards (for AWS)
# METADATA
# title: Sensitive Data Encryption at Rest
# description: "Every aws_s3_bucket must have an aws_s3_bucket_server_side_encryption_configuration that references it."
# custom:
#   control_id: 164.312(a)(2)(iv)
#   framework: nist-800-66 r2 (HIPAA Security Rule)
#   severity: high
#   remediation: "Add aws_s3_bucket_server_side_encryption_configuration { bucket =
#                 aws_s3_bucket.<name>.id ... } for the bucket."
package aws.hipaa.s3_cmk_encryption

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
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket"
	bucket_name := resource.name

	# Check if this bucket lacks a corresponding encryption configuration resource
	not has_encryption_resource(bucket_name)

	msg := sprintf("HIPAA 164.312(a)(2)(iv): '%v' is missing an encryption configuration resource.", [bucket_name])
}

# Rule 2: Verify the encryption configuration uses 'aws:kms' and a custom key ID
violations[msg] if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket_server_side_encryption_configuration"

	some rules in resource.change.after.rule
	some sse_config in rules.apply_server_side_encryption_by_default

	# Violation if it does not use KMS
	sse_config.sse_algorithm != "aws:kms"

	# Provide a detailed violation message
	msg := sprintf("HIPAA 164.312(a)(2)(iv): '%v' does not use 'aws:kms'. Customer-Managed Keys (CMK) must be used.", [resource.address])
}

violations[msg] if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket_server_side_encryption_configuration"

	some rules in resource.change.after.rule
	some sse_config in rules.apply_server_side_encryption_by_default

	# Enforce KMS, but catch cases where the specific key ID is
	# missing (defaults to AWS-managed key)
	sse_config.sse_algorithm == "aws:kms"
	not has_custom_key(sse_config)

	msg := sprintf(
		"HIPAA 164.312(a)(2)(iv): '%v' A Customer-Managed Key (CMK) ARN must be specified.",
		[resource.address],
	)
}

# --- Helper Functions ---

# Helper to verify if an encryption resource points to the bucket
has_encryption_resource(bucket_name) if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket_server_side_encryption_configuration"
	contains(resource.change.after.bucket, bucket_name)
}

# Helper to check that kms_master_key_id is populated and not
# using the default AWS-managed alias
has_custom_key(sse_config) if {
	some key_id in sse_config.kms_master_key_id
	key_id != ""
	not contains(key_id, "alias/aws/s3")
}
