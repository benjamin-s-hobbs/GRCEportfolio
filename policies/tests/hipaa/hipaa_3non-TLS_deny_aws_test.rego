package hipaa.tls_deny

test_policy_missing_tls {
    res := deny with input as { "resource_changes": [
        { "address": "aws_s3_bucket_policy.uploads", "type": "aws_s3_bucket_policy", "change": { "after": { "policy": "{\"Statement\": []}" } } }
    ]}
    count(res) == 1
}

test_policy_has_tls {
    res := deny with input as { "resource_changes": [
        { "address": "aws_s3_bucket_policy.uploads", "type": "aws_s3_bucket_policy", "change": { "after": { "policy": "{\"Condition\": {\"Bool\": {\"aws:SecureTransport\":\"false\"}}}" } } }
    ]}
    count(res) == 0
}