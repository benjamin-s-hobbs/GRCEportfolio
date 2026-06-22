# hipaa_5lmbda_in_securevpc_aws.rego
# METADATA
# title: Lambda VPC Isolation
# description: "Compute functions must run inside a customer-owned secure VPC architecture."
# custom:
#   control_id: 164.312(e)(1)
#   framework: nist-800-66 r2 (HIPAA Security Rule)
#   severity: high
#   remediation: "Add a vpc_config block referencing valid subnet_ids and security_group_ids."
package hipaa.lambda_vpc

import rego.v1

# Match by Terraform reference in `configuration`, not by literal bucket name in
# `planned_values`. At plan time the bucket name is often "(known after apply)".


deny contains msg if {
    r := input.configuration.root_module.resources[_]
    r.type == "aws_lambda_function"
    not has_vpc_config(r)
    "msg": sprintf("Lambda function %v is missing VPC network configuration.", [r.address])
}


has_vpc_config(r) {
    # Check that it references an aws_subnet array
    ref := r.expressions.vpc_config[_].subnet_ids.references[_]
    startswith(ref, "aws_subnet.")
}