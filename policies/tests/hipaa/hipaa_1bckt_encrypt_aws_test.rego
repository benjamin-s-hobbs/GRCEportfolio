# hipaa_1bckt_encrypt_aws_test.rego

package hipaa.bucket_encryption

test_bucket_missing_encryption {
    res := deny with input as { "configuration": { "root_module": { "resources": [
        { "address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket" }
    ]}}}
    count(res) == 1
}

test_bucket_has_encryption {
    res := deny with input as { "configuration": { "root_module": { "resources": [
        { "address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket" },
        { "address": "aws_s3_bucket_server_side_encryption_configuration.uploads", "type": "aws_s3_bucket_server_side_encryption_configuration", "expressions": { "bucket": { "references": ["aws_s3_bucket.uploads"] } } }
    ]}}}
    count(res) == 0
}