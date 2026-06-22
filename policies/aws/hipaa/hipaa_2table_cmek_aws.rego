# HIPAA CMEK Policy for AWS
# METADATA
# title: CMEK Policy for Resources
# description: "Every resource that is encrypted must 
#              use a Customer-Managed Encryption Key (CMEK) 
#              instead of a default encryption key."
# custom:
#   control_id: 164.312(a)(2)(iv)
#   framework: nist-800-66 r2 (HIPAA Security Rule)
#   severity: high
#   remediation: "Add aws_s3_bucket_server_side_encryption_configuration { bucket = aws_s3_bucket.<name>.id ... } for the bucket."
package aws.hipaa.resource_cmek

import rego.v1
# Match by Terraform reference in `configuration`, not by literal bucket name in
# `planned_values`. At plan time the bucket name is often "(known after apply)".


deny contains msg if {
    some r in input.configuration.root_module.resources
    r.type == "aws_dynamodb_table"
    not has_cmek(r)
    "msg": sprintf("HIPAA 164.312(a)(2)(iv):  %v does not reference a valid CMEK.", [r.address])
} 

has_cmek(r) {
    # Verify the table references a custom KMS key ARN
    some ref in r.expressions.server_side_encryption.kms_key_arn.references
    startswith(ref, "aws_kms_key.")
}