# hipaa_5lmbda_in_securevpc_aws.rego
# METADATA
# title: Lambda VPC Isolation
# description: "Compute functions must run inside a customer-owned secure VPC architecture."
# custom:
#   control_id: 164.312(e)(1)
#   framework: nist-800-66 r2 (HIPAA Security Rule)
#   severity: high
#   remediation: "Add a vpc_config block referencing valid subnet_ids and security_group_ids."
package aws.hipaa.lambda_vpc

import rego.v1

# Match by Terraform reference in `configuration`, not by literal bucket name in
# `planned_values`. At plan time the bucket name is often "(known after apply)".

deny contains msg if {
    some r in input.configuration.root_module.resources
    r.type == "aws_lambda_function"

    not has_vpc_config(r)

    msg := sprintf("HIPAA 164.312(e)(1):Lambda function %v is missing valid VPC network configuration.", [r.address])
}


has_vpc_config(r) if {
    some vpc_conf in r.expressions.vpc_config
    
    # Check that it references at least one subnet
    some subnet_ref in vpc_conf.subnet_ids.references
    startswith(subnet_ref, "aws_subnet.")
    
    # Check that it also references at least one security group
    some sg_ref in vpc_conf.security_group_ids.references
    startswith(sg_ref, "aws_security_group.")
}