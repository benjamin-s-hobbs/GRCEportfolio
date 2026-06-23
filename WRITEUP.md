<!-- Adding Writeup Document for Capstone Project to explain decision choices and provide insight to first 
principles thinking applied to this project. -->

# WRITEUP.md for ACME Health Project 2026-1-14-01

## NOW (Current Sprint)

### Design Decisions

#### Voice

We have chosen to speak in the first person plural throughout this project writeup to emphasize that "We" are a team. Understanding that the task of solving our concerns for shipping an audit-defensible product was assigned to, and worked on solely by myself, Benjamin Hobbs- GRC Engineer, I know that I could not have completed this task without the men and women of the ACME Health Team and my professional contemporaries in the field of GRC Engineering. "We" bring you this solution for your consideration.

#### Choosing a Primary Framework

- We chose to use HIPAA as our primary framework because it most directly mapped to ACME Health proposed Patient Intake API. The industry that ACME is in (Healthcare) is primarily governed by HIPAA (Health Insurance Portability and Accountability Act).

- As HIPAA is a law enacted by Congress, it is most prudent for ACME to comply with this first. This sprint we will address the [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html), a regulation mandating technical, physical, and administrative safeguards to protect electronic data. [The HIPAA Privacy Rule](https://www.hhs.gov/hipaa/for-professionals/privacy/laws-regulations/index.html) regulation will be addressed at a later sprint as indicated in the "LATER" section of this project write up.

- Considering the business goals of ACME Health to deliver this solution to both enterprises and federal government interests as well we will remain observant of SOC 2 Type II and CMMC Level 2 controls that map to our chosen HIPAA controls to make sure that we "build once, and map everywhere."

### Control Coverage

#### HIPAA 164.308(a)(7)

#### HIPAA 164.312(a)(1)

#### HIPAA 164.312(a)(2)(iv)

GAP-01 & GAP-03

#### HIPAA 164.312(b) Switching to a REST API is the cleaner, more secure, and defensible architectural choice, especially when security and compliance are paramount

We are choosing to present this change as a trade-off between architectural simplicity and security compliance.

#### HIPAA 164.312(e)(1)

GAP-03 & GAP-05

### Trade-Offs

As there is not currently an official OSCAL (Open Security Controls Assessment Language) catlog for HIPAA, we will be citing the NIST SP 800-66 Rev. 2 titled (Implementing the HIPAA Security Rule) as the catalog.

## NEXT (Next couple of sprints)

## LATER

- Complete HIPAA Privacy Rule adoption using IAM (AWS Identity Center) Resources to layer on privacy protection using NIST SP 800-188 as the catalog.

- Patient data lifecycle (deletion, export). Worth mentioning in your write-up as a known gap.
Lab4-4 ()
WRITEUP.md section mapping each chain property (authenticity, integrity, timeliness, preservation) to the artifact that proves it.
=== 1. Integrity (SHA-256) ===
  OK (dd8a473f8c1dcd969e220296f180f8069d12564fa92ae9c488c40e2387e6adee)
=== 2. Authenticity + timestamp (Cosign + Sigstore Rekor) ===
Verified OK
  OK (Cosign verified, Rekor entry exists)
=== 3. Preservation (Object Lock retention) ===
  OK (retain until 2026-04-27T18:30:33.696000+00:00)

CHAIN INTACT for run 24963918994
(real sample)
EVIDENCE_VAULT=cgep-lab-grc-evidence-vault-0748579d bash scripts/verify-evidence.sh 27634193583 --p
rofile cgep
download: s3://cgep-lab-grc-evidence-vault-0748579d/runs/27634193583/evidence-27634193583-49b71ef308f5eece30b86e1ebdc354cad27611d5.tar.gz.sha256 to ./evidence-27634193583-49b71ef308f5eece30b86e1ebdc354cad27611d5.tar.gz.sha256
download: s3://cgep-lab-grc-evidence-vault-0748579d/runs/27634193583/receipt.json to ./receipt.json
download: s3://cgep-lab-grc-evidence-vault-0748579d/runs/27634193583/evidence-27634193583-49b71ef308f5eece30b86e1ebdc354cad27611d5.tar.gz.sig.bundle to ./evidence-27634193583-49b71ef308f5eece30b86e1ebdc354cad27611d5.tar.gz.sig.bundle
download: s3://cgep-lab-grc-evidence-vault-0748579d/runs/27634193583/evidence-27634193583-49b71ef308f5eece30b86e1ebdc354cad27611d5.tar.gz to ./evidence-27634193583-49b71ef308f5eece30b86e1ebdc354cad27611d5.tar.gz
Verified OK
CHAIN INTACT for run 27634193583

# tfsec:ignore:aws-ec2-no-public-egress-sgr - Acceptable risk: Lambda 
# requires internet egress via NAT to reach AWS service APIs. 
resource "aws_security_group" "lambda_sg" {
  name        = "intake-lambda-sg"
  description = "Security group for Patient Intake API Lambda function"
  
  vpc_id      = aws_vpc.main.id 
  1. Public Egress on the Lambda Security Group
The Finding: aws-ec2-no-public-egress-sgr
The Cause: Your lambda_sg has an egress rule pointing to 0.0.0.0/0 (the entire public internet). tfsec hates this because it represents a data exfiltration risk if the Lambda is compromised.
The GRC Solution: Because your architecture relies on a NAT Gateway for the Lambda to reach AWS APIs (like DynamoDB, KMS, and S3) rather than using dedicated VPC Endpoints, this open egress is technically required for the application to function. In the GRC world, we handle this as an Accepted Risk.

You can silence this error by placing a tfsec:ignore comment directly above the security group resource in your main.tf. This documents the exception right in the code:

2. Auto-Assigning Public IPs in Subnets (x2)
The Finding: aws-ec2-no-public-ip-subnet (Flags twice, once for each public subnet)
The Cause: The aws_subnet.public resource block has map_public_ip_on_launch = true. This means any EC2 instance accidentally dropped into this subnet will automatically get a public IP address, which is a major compliance violation for secure workloads.
The GRC Solution: Hardening! The only thing in your public subnet is the NAT Gateway, and the NAT Gateway uses an explicitly assigned Elastic IP (aws_eip.nat). It does not rely on the auto-assign feature.

We can completely eliminate this vulnerability by flipping the boolean to false in your main.tf:

Terraform
resource "aws_subnet" "public" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(aws_vpc.main.cidr_block, 8, count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]
  
  # Change this from true to false
  map_public_ip_on_launch = false 

  tags = {
    Name = "${local.name_prefix}-public-${count.index}"
  }
}
Once you apply that ignore comment to the security group and flip the boolean on the subnets, tfsec will return 0 high/critical failures, and your pipeline will proceed directly to the Bundle + sign + upload steps.

These are excellent details to mention in your WRITEUP.md as well. Documenting that you purposefully disabled map_public_ip_on_launch shows a strong understanding of VPC hardening.

Are there any other structural changes or formatting updates you'd like to make to the write-up before we watch the final pipeline run?