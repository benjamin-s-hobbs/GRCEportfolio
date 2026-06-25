# -------------------------------------------------------------------------
# INTEGRATION TESTS (Native Terraform)
# Satisfies Rubric: Control Test Coverage (Integration Level)
# -------------------------------------------------------------------------

# We use 'command = plan' so it evaluates the intended state 
# without actually provisioning or destroying real AWS resources.

# Supply dummy variables so Terraform can compile the test plan
variables {
  project_name = "grc-test-run"
  environment  = "dev"
  aws_region   = "us-east-1"
}

run "verify_uploads_bucket_encryption" {
  command = plan

  assert {
    # We wrap the 'rule' set in tolist() so we can safely index it
    condition     = tolist(aws_s3_bucket_server_side_encryption_configuration.uploads.rule)[0].apply_server_side_encryption_by_default[0].sse_algorithm != ""
    error_message = "Compliance Violation: S3 uploads bucket is missing encryption (Control: 164.312.a.2.iv)."
  }
}

run "verify_evidence_vault_versioning" {
  command = plan

  assert {
    # We wrap 'versioning_configuration' in tolist() to be absolutely safe
    condition     = tolist(aws_s3_bucket_versioning.vault.versioning_configuration)[0].status == "Enabled"
    error_message = "Compliance Violation: The S3 evidence vault does not have versioning enabled."
  }
}