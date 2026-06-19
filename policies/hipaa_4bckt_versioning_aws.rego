#hipaa_4bckt_versioning_aws.rego
# HIPAA Encryption Policy for AWS
# METADATA
# title: S3 Object versioning
# description: "Versioning must be enabled on storage resources to prevent destructive overwrites."
# custom:
#   control_id: 164.312(c)(1)
#   framework: nist-800-66 r2 (HIPAA Security Rule)
#   severity: medium
#   remediation: "Ensure aws_s3_bucket_versioning status is set to 'Enabled'."
package hipaa.bucket_versioning

import rego.v1

# Match by Terraform reference in `configuration`, not by literal bucket name in
# `planned_values`. At plan time the bucket name is often "(known after apply)".

deny contains msg if {
    r := input.configuration.root_module.resources[_]
    r.type == "aws_s3_bucket_versioning"
    not has_versioning(r)
    "msg": sprintf("Bucket versioning %v is not explicitly Enabled.", [r.address])
}

has_versioning(r) {
    r := input.configuration.root_module.resources[_]
    r.type == "aws_s3_bucket_versioning"
    status := r.expressions.versioning_configuration[_].status.constant_value
    status != "Enabled"
}