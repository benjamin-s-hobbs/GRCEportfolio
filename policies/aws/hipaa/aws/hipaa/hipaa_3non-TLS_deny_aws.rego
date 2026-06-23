# hipaa_3non-TLS_deny_aws.rego
# METADATA
# title: Secure Transport Enabled 
# description: "S3 Bucket policies must explicitly deny non-TLS requests."
# custom:
#   control_id: 164.312(e)(1)
#   framework: nist-800-66 r2 (HIPAA Security Rule)
#   severity: critical
#   remediation: Add a bucket policy condition denying s3:* when aws:SecureTransport is false."
package aws.hipaa.tls_deny

import rego.v1

# Match by Terraform reference in `configuration`, not by literal bucket name in
# `planned_values`. At plan time the bucket name is often "(known after apply)".
default allow := false

allow if {
	count(deny) == 0
}

deny contains msg if {
    some config in input.configuration.root_module.resources
    config.type == "aws_s3_bucket_policy"

    not enforces_secure_transport(config)

    msg:= sprintf("HIPAA 164.312(e)(1): %v does not enforce aws:SecureTransport.", [config.address])
}

# --- Helper Functions ---

enforces_secure_transport(config) if {    
    # Ensure the policy string contains the explicit deny check
    # Access the policy from the configuration
    policy_string := config.expressions.policy.constant_value
    contains(policy_string, "aws:SecureTransport")
}

enforces_secure_transport(config) if {
	# 1. Grab the references from the bucket policy
	some ref in config.expressions.policy.references
	startswith(ref, "data.aws_iam_policy_document.")
	
	# 2. Find the matching data block in the configuration
	some data_block in input.configuration.root_module.resources
	data_block.type == "aws_iam_policy_document"
	startswith(ref, data_block.address)
	
	# 3. Check if the IAM document contains the SecureTransport condition
	some statement in data_block.expressions.statement
	some condition in statement.condition
	
	# 4. Verify it's a Deny effect looking for SecureTransport == false
	statement.effect.constant_value == "Deny"
	condition.variable.constant_value == "aws:SecureTransport"
	condition.values.constant_value[_] == "false" 
}