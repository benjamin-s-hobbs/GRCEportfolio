# GRCEportfolio: Automated Governance & Compliance Pipeline

## 📌 Executive Summary

Imagine inheriting a legacy, non-compliant web application that handles highly sensitive medical data. Your task isn't to spend months rewriting the application from scratch; your task is to immediately secure it, make it audit-ready, and ensure it complies with strict regulatory frameworks.

This repository demonstrates exactly that.

It takes a deliberately vulnerable baseline application (an "Acme Health" Patient Intake API) and wraps it in a modern, automated **Governance, Risk, and Compliance (GRC)** pipeline. By turning security policies into code, this project proves that we can automatically enforce compliance for frameworks like **HIPAA, SOC 2, and CMMC Level 2** before a single piece of infrastructure is ever deployed.

---

## 🏗️ What This Repository Demonstrates

This project showcases a "Shift-Left" security approach, meaning security checks happen early and automatically in the development process. It is built on four core layers:

1. **The Secure Infrastructure Baseline (Terraform)**
   * *What it is:* Code that automatically provisions secure cloud resources.
   * *The Business Value:* Instead of manually clicking through AWS menus, we use code to instantly deploy encrypted storage (KMS keys), tamper-proof audit vaults (S3 Object Lock), and continuous monitoring (CloudTrail).
2. **Automated Security Gates (Policy as Code via Open Policy Agent/Rego)**
   * *What it is:* A suite of automated rules that inspect any proposed changes to the system.
   * *The Business Value:* Think of this as a digital security guard. If an engineer accidentally tries to deploy an unencrypted database, these automated rules will catch the flaw and block the deployment *before* the vulnerability ever reaches the live environment.
3. **The Evidence Pipeline (GitHub Actions)**
   * *What it is:* An automated assembly line for code.
   * *The Business Value:* Every time a change is proposed, this pipeline automatically tests the code, checks it against our security policies, mathematically signs the approval (using Cosign), and securely stores the "proof" in our audit vault. When auditors ask for evidence, it is already waiting for them.
4. **Machine-Readable Documentation (OSCAL)**
   * *What it is:* A standardized, digital definition of our security controls.
   * *The Business Value:* We replace static, quickly-outdated Word documents with dynamic data files that explicitly map our cloud infrastructure directly to legal and regulatory framework requirements.

---

## 🛠️ Prerequisites

To deploy this environment, you will need a few standard tools installed on your machine.

* **An AWS Account:** A sandbox or development account to host the cloud resources.
* **AWS CLI:** The tool used to authenticate your computer with your AWS account.
* **Terraform:** The tool that reads our configuration files and builds the cloud infrastructure.
* **Make:** A standard utility to run our automated setup and teardown scripts.

---

## 🚀 How to Run the Project

The environment is designed to be easily deployed and destroyed.

### 1. Authenticate

First, ensure your terminal is securely authenticated to your AWS environment.

```bash
# If using standard IAM credentials
aws configure

# If using AWS SSO (Single Sign-On)
export $(aws configure export-credentials)
```

### 2. Deploy the Infrastructure

Deploy the secure pipeline and the Acme Health application using the provided Makefile. This command tells Terraform to go to AWS and build the necessary networks, databases, and security controls.

```bash
make deploy AWS_PROFILE=<your-sandbox-profile>
```

### 3. Test the Application

Once deployed, you can verify that the Acme Health API is successfully receiving patient data securely.

```bash
make test AWS_PROFILE=<your-sandbox-profile>
```

Expected output:

```bash
{"submission_id": "f1e3...", "status": "received"}
```

#### 🏗️ The Four GRC Layers

This project transforms the basic Acme Health application into a compliant, audit-ready system through four distinct layers of governance. Here is how they break down and where to find them in the repository:

* **Layer 1: GRC Baseline (Terraform)**

  * Location: `terraform/`

  * What it does: Provisions the secure foundation. We deploy custom KMS keys, an S3 evidence vault with Object Lock for immutability, and a CloudTrail trail. All of the starter application's data stores are brought under our Customer Managed Key (CMK) for strict encryption control.

* **Layer 2: OPA Policy Suite (Rego)**

  * Location: `policies/`

  * What it does: Automated security gates. This suite contains five or more policies specifically designed to catch known vulnerabilities (documented in our GAPS.md file). Every policy maps directly to at least one control from our chosen compliance framework.

* **Layer 3: GitHub Actions Pipeline**

  * Location: `.github/workflows/`

  * What it does: The continuous integration and evidence-gathering engine. The pipeline executes in strict sequence: Plan → Conftest gate (evaluating Layer 2 policies) → Apply → Cosign sign (cryptographically signing the results) → Upload to vault (storing the immutable evidence).

* **Layer 4: OSCAL Component**

  * Location: `OSCAL/`

  * What it does: Machine-readable compliance documentation. A component-definition.json file that explicitly describes exactly how this governed system implements its required security controls.

### 4. Teardown

Cloud resources cost money. Once you are finished reviewing the environment, you can securely destroy all provisioned resources with a single command to prevent ongoing charges.

```bash
make destroy AWS_PROFILE=<your-sandbox-profile>
```

(Note: Because this architecture utilizes highly efficient, serverless technologies, the cost of deploying and destroying this workload within an hour is roughly $0.00).

📂 Repository Layout Highlights

* `terraform/` - The blueprint code for our AWS cloud infrastructure.

* `policies/` - The Rego rules acting as our automated security gates.

* `.github/workflows/` - The CI/CD assembly line that automates our deployments and gathers audit evidence.

* `OSCAL/` - The compliance documentation mapping our tech to HIPAA/SOC 2/CMMC controls.
