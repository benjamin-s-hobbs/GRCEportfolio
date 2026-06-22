# HIPAA Security Rule: CMEK Policy (for AWS)
# METADATA
# title: CMEK Policy for Resources
# description: "Every resource that is encrypted must 
#              use a Customer-Managed Encryption Key (CMEK) 
#              instead of a default encryption key."
# custom:
#   control_id: 164.312(a)(2)(iv)
#   framework: nist-800-66 r2 (HIPAA Security Rule)
#   severity: high
#   remediation: "Add aws_s3_bucket_server_side_encryption_configuration { bucket = aws_s3_bucket.<name>.id ... } for the bucket."
package aws.hipaa.resource_cmek

import rego.v1
# Match by Terraform reference in `configuration`, not by literal bucket name in
# `planned_values`. At plan time the bucket name is often "(known after apply)".
default allow := false

allow if {
	count(deny) == 0
}

deny contains msg if {
	some config in input.configuration.root_module.resources
	config.type == "aws_dynamodb_table"
                    

	not has_dynamodb_custom_key_ref(config)

	msg := sprintf(
		"HIPAA 164.312(a)(2)(iv): '%v' is missing a Customer-Managed Key (CMK) reference.",
		[config.address],
	)
}

# --- Helper Functions ---

# Helper to check if a DynamoDB table references a custom KMS key
has_dynamodb_custom_key_ref(config) if {
	# Look inside the server_side_encryption block
	some sse in config.expressions.server_side_encryption
	
	# Verify that a KMS key reference actually exists
	refs := sse.kms_key_arn.references
	count(refs) > 0
}