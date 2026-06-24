# Infrastructure Governance Policies (OPA/Rego)

This directory contains the Open Policy Agent (OPA) Rego rules used by Conftest to evaluate our Terraform plan against the **HIPAA Security Rule (NIST 800-66 r2)**. 

These policies act as an automated governance gate in our CI/CD pipeline, ensuring no infrastructure is deployed unless it mathematically proves adherence to required technical safeguards.

## Policy Matrix

The following table maps our custom Rego policies to their respective HIPAA control IDs, severity levels, and required remediations.

| Policy File | Capability Evaluated | Control ID | Severity | Required Remediation |
| :--- | :--- | :--- | :--- | :--- |
| **`hipaa_1bckt_encrypt_aws.rego`** | Sensitive Data Encryption at Rest (S3) | 164.312(a)(2)(iv) | High | Attach an `aws_s3_bucket_server_side_encryption_configuration` to the bucket using a Customer-Managed Key (CMK) via `aws:kms`. |
| **`hipaa_2table_cmek_aws.rego`** | Sensitive Data Encryption at Rest (DynamoDB) | 164.312(a)(2)(iv) | High | Explicitly reference a Customer-Managed Key (CMK) ARN in the DynamoDB `server_side_encryption` block. |
| **`hipaa_3non-TLS_deny_aws.rego`** | S3 Secure Transport Enforcement | 164.312(e)(1) | High | Attach an `aws_s3_bucket_policy` utilizing an IAM policy document that explicitly denies requests where `aws:SecureTransport` is false. |
| **`hipaa_4b-bckt_versioning_exists_aws.rego`** | S3 Object Versioning | 164.308(a)(7) | High | Create an `aws_s3_bucket_versioning` resource linked to the bucket and explicitly set the status to `Enabled`. |
| **`hipaa_5lmbda_in_securevpc_aws.rego`** | Lambda VPC Isolation | 164.312(e)(1) | High | Add a `vpc_config` block to the Lambda function referencing valid `subnet_ids` and `security_group_ids` within a customer-owned VPC. |
| **`hipaa_7roles_leastpriv_aws.rego`** | IAM Least Privilege | 164.312(a)(1) | Critical | Scope IAM policy `Action` and `Resource` blocks to specific, required ARNs and API calls. Remove all wildcard (`*`) permissions. |
| **`hipaa_8apigw_logs_aws.rego`** | API Gateway Logging | 164.312(b) | Medium | Add an `access_log_settings` block inside the `aws_api_gateway_stage` resource to export execution logs to CloudWatch. |
| **`hipaa_9apigw_waf_aws.rego`** | API Gateway WAF | 164.312(b) | High | Create an `aws_wafv2_web_acl_association` linking the active API Gateway stage to a configured Web Application Firewall. |

## Execution

These policies are designed to evaluate the structured `configuration` block of a Terraform plan JSON. This prevents "known after apply" string interpolation errors from failing the pipeline during the plan phase.

They are executed automatically via the `grc-gate` GitHub Actions workflow.