# hipaa_3non-TLS_deny_aws.rego
# METADATA
# title: S3 Secure Transport Enforcement
# description: "S3 buckets must enforce aws:SecureTransport to ensure encryption in transit."
# custom:
#   control_id: 164.312(e)(1)
#   framework: nist-800-66 r2 (HIPAA Security Rule)
#   severity: high
#   remediation: "Attach an aws_s3_bucket_policy using a data.aws_iam_policy_document that denies requests where aws:SecureTransport is false."
package aws.hipaa.tls_deny

import rego.v1

deny contains msg if {
    some bp in input.configuration.root_module.resources
    bp.type == "aws_s3_bucket_policy"
    
    # Fails if the bucket policy doesn't link to a compliant data document
    not policy_enforces_secure_transport(bp)
    
    msg := sprintf("HIPAA 164.312(e)(1): %v does not enforce aws:SecureTransport.", [bp.address])
}

policy_enforces_secure_transport(bp) if {
    # 1. Find all IAM policy documents in the configuration
    some doc in input.configuration.root_module.resources
    doc.mode == "data"
    doc.type == "aws_iam_policy_document"
    
    # 2. Confirm this specific document is referenced by the bucket policy
    some ref in bp.expressions.policy.references
    ref == doc.address
    
    # 3. Verify the document has the correct structural conditions
    some stmt in doc.expressions.statement
    stmt.effect.constant_value == "Deny"
    
    some cond in stmt.condition
    cond.variable.constant_value == "aws:SecureTransport"
    cond.test.constant_value == "Bool"
    
    some val in cond.values.constant_value
    val == "false"
}

