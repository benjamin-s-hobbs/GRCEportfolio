# OSCAL Compliance Documentation

This directory contains the Open Security Controls Assessment Language (OSCAL) artifacts for the Acme Health Patient Intake API. These documents provide a machine-readable, audit-ready map between our statutory compliance requirements and the codified infrastructure that enforces them.

## Component Definitions

The component definitions translate our technical Terraform baselines into defined security capabilities.

| OSCAL Component | Source Module | Description |
| :--- | :--- | :--- |
| **Patient Intake API Governance Baseline** | `terraform/main.tf` | Establishes audit-defensible guardrails around the Patient Intake API workload, enforcing encryption at rest, secure transport, versioning, network isolation, and least-privilege IAM. |

## Control Mappings (HIPAA Security Rule)

The baseline component explicitly satisfies the following technical safeguards under NIST SP 800-66 r2 (HIPAA Security Rule):

* **164.312.a.2.iv (Encryption and Decryption):** Enforces customer-managed KMS keys on the S3 evidence vault, S3 uploads bucket, and the DynamoDB intake table.
* **164.312.e.1 (Transmission Security):** Enforces `aws:SecureTransport` across all buckets and isolates compute resources (Lambda) within a private VPC subnet.
* **164.308.a.7 (Contingency Plan):** Enforces S3 Object Versioning on PHI and compliance data to prevent destructive overwrites.
* **164.312.a.1 (Access Control):** Scopes the Lambda execution role to exact API actions and resource ARNs, eliminating wildcard permissions.
* **164.312.b (Audit Controls):** Routes API Gateway execution and access logs to CloudWatch and attaches a Web Application Firewall (WAFv2).

## Evidence Architecture

We follow an "Infrastructure as Security" model. Gaps are closed directly in the Terraform codebase, and Open Policy Agent (OPA/Rego) mathematically verifies those configurations in the CI/CD pipeline.

Continuous compliance evidence is cryptographically signed and stored in our immutable S3 Governance Vault.

| Evidence Type | Location / URI |
| :--- | :--- |
| **Pipeline Bundles** | `s3://cgep-lab-grc-evidence-vault-0748579d/runs/` |
| **Latest Attestation** | `s3://cgep-lab-grc-evidence-vault-0748579d/runs/LATEST/evidence-LATEST.tar.gz` |
| **Source Code Reference** | [GRCEportfolio/terraform/main.tf](https://github.com/benjamin-s-hobbs/GRCEportfolio/terraform/main.tf) |

**Note on Catalog Source:** Because an official OSCAL catalog for the HIPAA Security Rule does not currently exist in the NIST repository, the structural catalog reference points to the NIST 800-53 Rev 5 standard, while internal `control-id` values accurately reflect the HIPAA mandate.
