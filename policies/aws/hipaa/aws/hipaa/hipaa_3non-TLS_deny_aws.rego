#hipaa_3non-TLS_deny_aws.rego
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
    some config in input.configuration.root.module.resources
    config.type == "aws_s3_bucket_policy"

    not has_secure_transport(config)

    "msg": sprintf("Bucket policy %v does not enforce aws:SecureTransport.", [config.address])
}

# --- Helper Functions ---

has_secure_transport(config) if {
    
    # Ensure the policy string contains the explicit deny check
    # Access the policy from the configuration
    policy_string := config.expressions.policy.constant_value
    contains(policy_string, "aws:SecureTransport")
}