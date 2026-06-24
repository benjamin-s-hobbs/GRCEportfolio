# Terraform/Primitives

## Compliant gcs (GCP)

This module enforces the following NIST SP 800-53r5 controls on a single S3 storage bucket in AWS:

* SC-28: Protection of information at rest

* AU-3 /AU-6: Content of audit records + audit review

* CM-6: Versioning preserves prior object states for recovery and audit purposes.

* AC-3: Access Control, explicitly denying public access.
