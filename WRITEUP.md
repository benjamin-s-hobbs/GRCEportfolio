<!-- Adding Writeup Document for Capstone Project to explain decision choices and provide insight to first 
principles thinking applied to this project. -->

# Acme Health: Patient Intake API Governance & Compliance

## Design Decisions

### 1.Primary Framework: HIPAA Security Rule

Our immediate legal and operational mandate is protecting Patient Health Information (PHI). Therefore, the HIPAA Security Rule is the primary framework for this baseline.

* The "Why": While SOC 2 Trust Services Criteria and CMMC Level 2 are highly valuable business accelerators, they are "nice-to-haves" at this stage. Without strict adherence to HIPAA technical safeguards, operating this API is a legal liability.

* The Roadmap: This baseline establishes the floor. In the next 90 days, we will map these existing controls to CMMC Level 2 to unblock U.S. government sector contracts, followed by future sprints later in the year to conduct a SOC 2 readiness assessment.

### 2.Remediation Strategy: Infrastructure as Security

I chose to technically close all identified gaps directly within the Terraform baseline, rather than relying solely on Rego policies to catch them.

* The "Why": Security should be realized in the system's actual configuration ("Secure by Default"). The infrastructure itself must dictate what is permitted. The Rego policy suite acts as an automated, audit-defensible verification layer to ensure those baselines are never regressed by future commits.

### 3.Evidence Vault & Immutability

The compliance evidence vault utilizes S3 Object Lock configured in GOVERNANCE mode rather than COMPLIANCE mode.

* The "Why": Crawl, walk, run. While COMPLIANCE mode offers ultimate audit-grade immutability, GOVERNANCE mode provides the necessary proof-of-concept protection while preventing irreversible lock-in. This allows the CTO and engineering teams to request architectural adjustments to the vault strategy before we lock the bucket configurations permanently for production.

### 4. Cryptographic Chain of Custody

To ensure the output of the compliance pipeline is audit-grade, the deployment process enforces a strict cryptographic chain of custody. Every successful evaluation generates a locked, verifiable record of the infrastructure's state.

The integrity of this chain is built upon four fundamental properties, each proven by specific artifacts generated during GitHub Actions Run `28046655979`:

| Custody Property | Definition | Proving Artifact(s) |
| :--- | :--- | :--- |
| **Authenticity** | Cryptographic proof of origin and authorization. Validates *who* or *what* created the evidence. | **`*.sig.bundle`**: A Sigstore Cosign keyless signature bound to the GitHub Actions OIDC identity. It proves the evidence was generated exclusively by the trusted `grc-gate` CI/CD workflow, not a human operator. |
| **Integrity** | Cryptographic proof that the evidence has not been tampered with or corrupted since its creation. | **`*.sha256`**: The SHA-256 checksum file. Verifying the `.tar.gz` bundle against this hash mathematically guarantees that not a single byte of the Terraform plan or Rego test results has been altered. |
| **Timeliness** | Proof of provenance, linking the evidence to a specific moment in time and a specific codebase state. | **`receipt.json`**: This metadata file bridges the pipeline to the version control system. By capturing the exact `run_id` and Git `commit` SHA, it provides an immutable timeline of when the gap was closed and which code changes closed it. |
| **Preservation** | Architectural proof that the evidence is protected against deletion, overwrite, or ransomware. | **S3 Object Lock (Governance Mode)**: The destination bucket (`cgep-lab-grc-evidence-vault-0748579d`) enforces Write Once, Read Many (WORM) storage. The `version_id` tracked in the receipt ensures the exact file iteration is preserved, even if subsequent runs upload files with identical names. |

#### Verification Execution

As demonstrated by the `capstone-chain.txt` output (located in GRCEportfolio/evidence/lab-7-1/capstone-chain.txt), an independent script can successfully pull the `receipt.json`, download the corresponding `evidence-*.tar.gz` bundle alongside its hash and signature, and mathematically validate the entire chain without requiring direct access to the GitHub repository or AWS control plane. The resulting `CHAIN INTACT` output confirms the baseline meets non-repudiation standards.

### 5.Key Design Decisions & Trade-offs

To meet the 30-day Minimum Viable Product (MVP) deadline without sacrificing auditability, several intentional architectural trade-offs were made:

* RESTful API Conversion for Native WAF: The starter workload was updated to utilize an AWS REST API rather than an HTTP API. This trade-off allowed for clean, native integration with AWS WAFv2 directly on the API Gateway stage, avoiding the complexity and global propagation delays of standing up a CloudFront distribution just to attach a firewall.

* AWS Region (us-east-1): Selected for rapid deployment, universal service availability, and future anticipation of CMMC Level 2 federal compliance requirements.

* Single AWS Account MVP: A single AWS account is utilized for this 30-day proof-of-concept. While a dedicated, isolated "Evidence/Audit" AWS account—completely inaccessible to CI/CD engineers—is the industry standard target state, implementing cross-account OIDC and KMS trust policies would have jeopardized the CTO's delivery deadline.

* Manual Pipeline Approval Gate: The GitHub Actions pipeline requires a manual approval gate post-plan and post-policy check before applying to main. Automation is powerful, but organizational trust must be earned first. Once leadership is comfortable with the Rego policy enforcement, we can graduate to fully automated continuous deployment in future sprints.

## Known Limitations & Gaps

* OSCAL Catalog Source Mapping: Because NIST does not currently publish an official, machine-readable OSCAL catalog for the HIPAA Security Rule (SP 800-66 r2), the component-definition.json maintains a structural link to the NIST 800-53 Rev 5 catalog, while utilizing proper HIPAA control IDs internally.

* Future Sprint Opportunities: In a future sprint, Acme Health should author and open-source a dedicated HIPAA OSCAL catalog. This resolves the technical validation mismatch and positions the company as a differentiator and thought-leader in the healthcare GRC engineering space.

* Lambda Egress Exception: The aws_security_group for the Lambda function contains an open egress rule (0.0.0.0/0). This is an accepted risk, documented in the IaC via tfsec:ignore, as the function relies on the NAT Gateway to reach the public AWS APIs for KMS and DynamoDB. Future iterations will replace this with dedicated, private VPC Endpoints. This current configuration will be noted in the ACME Health Risk Register with a treatment plan for future remediation.

## Control Coverage

HIPAA 164.308(a)(7)

HIPAA 164.312(a)(1)

HIPAA 164.312(a)(2)(iv)

HIPAA 164.312(b)

HIPAA 164.312(e)(1)
