# hipaa_9apigw_waf_aws.rego
# METADATA
# title: API Gateway WAF
# description: "API Gateway stages must be protected by a Web Application Firewall (WAF)."
# custom:
#   control_id: 164.312(b)
#   framework: nist-800-66 r2 (HIPAA Security Rule)
#   severity: high
#   remediation: "Create an aws_wafv2_web_acl_association linking the API Gateway stage to a WAF ACL."
package hipaa.apigw_waf

import rego.v1

deny contains msg if {
    some stage in input.configuration.root_module.resources
    stage.type == "aws_api_gateway_stage"
    
    not stage_has_waf(stage)
    
    msg := sprintf("HIPAA 164.312(b): API Gateway Stage %v is not associated with a WAF.", [stage.address])
}

stage_has_waf(stage) if {
    some assoc in input.configuration.root_module.resources
    assoc.type == "aws_wafv2_web_acl_association"
    
    # Verify the WAF association is attached to this specific API Gateway stage
    some ref in assoc.expressions.resource_arn.references
    ref == stage.address
}