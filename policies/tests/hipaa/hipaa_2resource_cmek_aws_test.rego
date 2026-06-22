package hipaa.resource_cmek

test_dynamo_missing_cmek {
    res := deny with input as { "configuration": { "root_module": { "resources": [
        { "address": "aws_dynamodb_table.intake", "type": "aws_dynamodb_table", "expressions": {} }
    ]}}}
    count(res) == 1
}

test_dynamo_has_cmek {
    res := deny with input as { "configuration": { "root_module": { "resources": [
        { "address": "aws_dynamodb_table.intake", "type": "aws_dynamodb_table", "expressions": { "server_side_encryption": [{ "kms_key_arn": { "references": ["aws_kms_key.key.arn"] } }] } }
    ]}}}
    count(res) == 0
}