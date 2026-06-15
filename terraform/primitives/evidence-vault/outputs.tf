# terraform/primitives/evidence-vault/outputs.tf
# This is a simple S3 bucket configuration for an evidence vault (outputs).
output "vault_name" {
  value       = aws_s3_bucket.vault.id
  description = "S3 bucket name of the evidence vault. Feed this to capture-evidence.sh --vault."
}

output "kms_key_arn"    { value = aws_kms_key.main.arn }