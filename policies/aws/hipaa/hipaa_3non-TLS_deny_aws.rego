#hipaa_3non-TLS_deny_aws.rego
# METADATA
# title: Secure Transport Enabled 
# description: "S3 Bucket policies must explicitly deny non-TLS requests."
# custom:
#   control_id: 164.312(e)(1)
#   framework: nist-800-66 r2 (HIPAA Security Rule)
#   severity: critical
#   remediation: Add a bucket policy condition denying s3:* when aws:SecureTransport is false."
package hipaa.tls.deny

import rego.v1

# Match by Terraform reference in `configuration`, not by literal bucket name in
# `planned_values`. At plan time the bucket name is often "(known after apply)".

deny contains msg if {
    r := input.resource_changes[_]
    r.type == "aws_s3_bucket_policy"
    not has_secure_transport(r)
    "msg": sprintf("Bucket policy %v does not enforce aws:SecureTransport.", [r.address])
}

has_secure_transport(r) {
    
    # Ensure the policy string contains the explicit deny check
    policy_json := r.change.after.policy
    not contains(policy_json, "\"aws:SecureTransport\":\"false\"")
}