# HIPAA "API Gateway Logging"
# METADATA
# title: "API Gateway Logging"
# description: "API Gateway stages must export access logs to CloudWatch."
# custom:
#   control_id: 164.312(1)(c)
#   framework: nist-800-66 r2 (HIPAA Security Rule)
#   severity: medium
#   remediation: "Add an access_log_settings block inside the aws_api_gateway_stage resource."
package aws.hipaa.apigw_logging

import rego.v1

# Match by Terraform reference in `configuration`, not by literal bucket name in
# `planned_values`. At plan time the bucket name is often "(known after apply)".


}

deny contains msg if {
    some r in input.configuration.root_module.resources
    r.type == "aws_api_gateway_stage"
    
    not r.expressions.access_log_settings
    
    msg := sprintf("HIPAA 164.312(b): API Gateway Stage %v is missing CloudWatch access log configuration.", [r.address])
}