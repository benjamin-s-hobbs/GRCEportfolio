package hipaa.bucket_versioning

test_versioning_suspended {
    res := deny with input as { "configuration": { "root_module": { "resources": [
        { "address": "aws_s3_bucket_versioning.vault", "type": "aws_s3_bucket_versioning", "expressions": { "versioning_configuration": [{ "status": { "constant_value": "Suspended" } }] } }
    ]}}}
    count(res) == 1
}

test_versioning_enabled {
    res := deny with input as { "configuration": { "root_module": { "resources": [
        { "address": "aws_s3_bucket_versioning.vault", "type": "aws_s3_bucket_versioning", "expressions": { "versioning_configuration": [{ "status": { "constant_value": "Enabled" } }] } }
    ]}}}
    count(res) == 0
}