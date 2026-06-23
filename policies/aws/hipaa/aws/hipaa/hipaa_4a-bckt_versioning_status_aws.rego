# hipaa_4a-bckt_versioning_status_aws.rego
# HIPAA Encryption Policy for AWS
# METADATA
# title: S3 Object versioning status
# description: "Versioning must be enabled on storage resources to prevent destructive overwrites."
# custom:
#   control_id: 164.308(a)(7)
#   framework: nist-800-66 r2 (HIPAA Security Rule)
#   severity: medium
#   remediation: "Ensure aws_s3_bucket_versioning status is set to 'Enabled'."
package aws.hipaa.bucket_versioning_status

import rego.v1

# Match by Terraform reference in `configuration`, not by literal bucket name in
# `planned_values`. At plan time the bucket name is often "(known after apply)".



deny contains msg if {
    some r in input.configuration.root_module.resources
    r.type == "aws_s3_bucket_versioning"
    
    # Deny if the helper evaluates to false
    not is_versioning_enabled(r)

    msg := sprintf("HIPAA 164.308(a)(7): S3 bucket versioning configuration for %v must be set to 'Enabled'.", [r.address])
}


# Helper returns true ONLY if the configuration is explicitly set to Enabled
is_versioning_enabled(r) if {
    some v in r.expressions.versioning_configuration
    v.status.constant_value == "Enabled"
}

