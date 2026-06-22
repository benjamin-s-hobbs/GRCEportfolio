package hipaa.least_privilege

test_policy_has_wildcard {
    res := deny with input as { "resource_changes": [
        { "address": "aws_iam_role_policy.intake", "type": "aws_iam_role_policy", "change": { "after": { "policy": "{\"Action\":\"*\",\"Resource\":\"*\"}" } } }
    ]}
    count(res) == 1
}

test_policy_no_wildcard {
    res := deny with input as { "resource_changes": [
        { "address": "aws_iam_role_policy.intake", "type": "aws_iam_role_policy", "change": { "after": { "policy": "{\"Action\":[\"s3:PutObject\"],\"Resource\":\"arn\"}" } } }
    ]}
    count(res) == 0
}