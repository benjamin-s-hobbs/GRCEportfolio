package hipaa.apigw_logging

test_apigw_missing_logs {
    res := deny with input as { "configuration": { "root_module": { "resources": [
        { "address": "aws_api_gateway_stage.prod", "type": "aws_api_gateway_stage", "expressions": {} }
    ]}}}
    count(res) == 1
}

test_apigw_has_logs {
    res := deny with input as { "configuration": { "root_module": { "resources": [
        { "address": "aws_api_gateway_stage.prod", "type": "aws_api_gateway_stage", "expressions": { "access_log_settings": [{ "destination_arn": { "references": ["aws_cloudwatch_log_group.apigw_logs.arn"] } }] } }
    ]}}}
    count(res) == 0
}