package hipaa.lambda_vpc

test_lambda_no_vpc {
    res := deny with input as { "configuration": { "root_module": { "resources": [
        { "address": "aws_lambda_function.intake", "type": "aws_lambda_function", "expressions": {} }
    ]}}}
    count(res) == 1
}

test_lambda_with_vpc {
    res := deny with input as { "configuration": { "root_module": { "resources": [
        { "address": "aws_lambda_function.intake", "type": "aws_lambda_function", "expressions": { "vpc_config": [{ "subnet_ids": { "references": ["aws_subnet.private"] } }] } }
    ]}}}
    count(res) == 0
}