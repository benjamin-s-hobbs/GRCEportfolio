# hipaa_7roles_leastpriv_aws.rego
# HIPAA IAM Least Privilege
# METADATA
# title: IAM Least Privilege
# description: "IAM roles must not be provisioned with wildcard (*) permissions."
# custom:
#   control_id: 164.312(a)(1)
#   framework: nist-800-66 r2 (HIPAA Security Rule)
#   severity: critical
#   remediation: "Scope IAM policy Action and Resource blocks to specific, required ARNs and API calls."
package aws.hipaa.least_privilege

import rego.v1

# Match by Terraform reference in `configuration`, not by literal bucket name in
# `planned_values`. At plan time the bucket name is often "(known after apply)".


deny contains msg if {
    some r in input.configuration.root_module.resources
    r.type == "aws_iam_role_policy"

    # 1. Find the referenced data document to evaluate structure securely
    some doc in input.configuration.root_module.resources
    doc.mode == "data"
    doc.type == "aws_iam_policy_document"
    
    some ref in r.expressions.policy.references
    ref == doc.address
    
    # 2. Check if the document has wildcard actions inside an Allow block
    has_wildcard_allow(doc)
    
    msg := sprintf("HIPAA 164.312(a)(1): IAM Role Policy %v grants wildcard permissions (*). Scope to specific API actions.", [r.address])
}

has_wildcard_allow(doc) if {
    some stmt in doc.expressions.statement
    
    is_allow(stmt)
    
    some action in stmt.actions.constant_value
    contains(action, "*")
}

# Helper successfully flags explicit "Allow" blocks
is_allow(stmt) if {
    stmt.effect.constant_value == "Allow"
}

# Helper successfully flags implicit "Allow" blocks (Terraform's default if omitted)
is_allow(stmt) if {
    not stmt.effect
}
