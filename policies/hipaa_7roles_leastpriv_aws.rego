# HIPAA IAM Least Privilege
# METADATA
# title: IAM Least Privilege
# description: "IAM roles must not be provisioned with wildcard (*) permissions."
# custom:
#   control_id: 164.312(a)(1)
#   framework: nist-800-66 r2 (HIPAA Security Rule)
#   severity: critical
#   remediation: "Scope IAM policy Action and Resource blocks to specific, required ARNs and API calls."
package hipaa.least_privilege

import rego.v1

# Match by Terraform reference in `configuration`, not by literal bucket name in
# `planned_values`. At plan time the bucket name is often "(known after apply)".

deny contains msg if {
    r := input.resource_changes[_]
    r.type == "aws_iam_role_policy"
    contains(policy_json, "\"Action\":\"*\"")
    policy_json := r.change.after.policy
    "msg": sprintf("IAM Policy %v contains wildcard permissions.", [r.address])
} 
