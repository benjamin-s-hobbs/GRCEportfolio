# hipaa_4b-bckt_versioning_exists_aws.rego
# METADATA
# title: S3 Object Versioning Exists
# description: "Every S3 bucket must have an associated versioning resource."
# custom:
#   control_id: 164.308(a)(7)
#   framework: nist-800-66 r2 (HIPAA Security Rule)
#   severity: high
#   remediation: "Add an aws_s3_bucket_versioning resource linked to the bucket."
package aws.hipaa.bucket_versioning_exists

import rego.v1

deny contains msg if {
    some bucket in input.configuration.root_module.resources
    bucket.type == "aws_s3_bucket"
    
    # Deny if no versioning resource successfully links back to this bucket
    not bucket_has_versioning(bucket)
    
    msg := sprintf("HIPAA 164.308(a)(7): S3 bucket %v is missing an associated aws_s3_bucket_versioning resource.", [bucket.address])
}

# The versioning block explicitly references the bucket's Terraform address
# (e.g., bucket = aws_s3_bucket.my_bucket.id)
bucket_has_versioning(bucket) if {
    some v in input.configuration.root_module.resources
    v.type == "aws_s3_bucket_versioning"
    
    some ref in v.expressions.bucket.references
    ref == bucket.address
}

# Both blocks reference the same exact local variable 

bucket_has_versioning(bucket) if {
    some v in input.configuration.root_module.resources
    v.type == "aws_s3_bucket_versioning"
    
    v.expressions.bucket.references == bucket.expressions.bucket.references
}

# The resource names identically match 
# (e.g., aws_s3_bucket.vault and aws_s3_bucket_versioning.vault)
bucket_has_versioning(bucket) if {
    some v in input.configuration.root_module.resources
    v.type == "aws_s3_bucket_versioning"
    
    v.name == bucket.name
}