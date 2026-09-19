#!/usr/bin/env bash
# .cursor/install.sh
#
# Idempotent bootstrap for the grc-gate GRC compliance-as-code pipeline.
# Installs the exact tool versions pinned by .github/workflows/grc-gate.yml so
# that a Cloud Agent can run the policy gate, Terraform validation, and scans
# locally. Safe to re-run: every tool is version-checked before download.
set -euo pipefail

# Versions pinned to match .github/workflows/grc-gate.yml
TERRAFORM_VERSION="1.6.6"
CONFTEST_VERSION="0.50.0"
TFSEC_VERSION="1.28.14"
COSIGN_VERSION="3.0.2"
OPA_VERSION="0.70.0"

BIN_DIR="/usr/local/bin"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

SUDO=""
if [[ "$(id -u)" -ne 0 ]]; then SUDO="sudo"; fi

have() { command -v "$1" >/dev/null 2>&1; }
ver_has() { "$1" --version 2>&1 | grep -q "$2"; }

echo "==> Installing base packages (jq, unzip, curl, python3)"
if have apt-get; then
  $SUDO apt-get update -y -qq
  $SUDO apt-get install -y -qq jq unzip curl ca-certificates python3 >/dev/null
fi

echo "==> Terraform ${TERRAFORM_VERSION}"
if ! have terraform || ! ver_has terraform "$TERRAFORM_VERSION"; then
  curl -fsSL "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip" -o "$TMP/tf.zip"
  unzip -o -q "$TMP/tf.zip" -d "$TMP"
  $SUDO install -m 0755 "$TMP/terraform" "$BIN_DIR/terraform"
fi

echo "==> Conftest ${CONFTEST_VERSION}"
if ! have conftest || ! ver_has conftest "$CONFTEST_VERSION"; then
  curl -fsSL "https://github.com/open-policy-agent/conftest/releases/download/v${CONFTEST_VERSION}/conftest_${CONFTEST_VERSION}_Linux_x86_64.tar.gz" \
    | tar -xz -C "$TMP" conftest
  $SUDO install -m 0755 "$TMP/conftest" "$BIN_DIR/conftest"
fi

echo "==> OPA ${OPA_VERSION}"
if ! have opa || ! ver_has opa "$OPA_VERSION"; then
  curl -fsSL "https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_amd64_static" -o "$TMP/opa"
  $SUDO install -m 0755 "$TMP/opa" "$BIN_DIR/opa"
fi

echo "==> tfsec ${TFSEC_VERSION}"
if ! have tfsec || ! ver_has tfsec "$TFSEC_VERSION"; then
  curl -fsSL "https://github.com/aquasecurity/tfsec/releases/download/v${TFSEC_VERSION}/tfsec-linux-amd64" -o "$TMP/tfsec"
  $SUDO install -m 0755 "$TMP/tfsec" "$BIN_DIR/tfsec"
fi

echo "==> Cosign ${COSIGN_VERSION}"
if ! have cosign || ! ver_has cosign "$COSIGN_VERSION"; then
  curl -fsSL "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64" -o "$TMP/cosign"
  $SUDO install -m 0755 "$TMP/cosign" "$BIN_DIR/cosign"
fi

echo "==> AWS CLI v2"
if ! have aws; then
  curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "$TMP/awscliv2.zip"
  unzip -o -q "$TMP/awscliv2.zip" -d "$TMP"
  $SUDO "$TMP/aws/install" --update >/dev/null
fi

echo "==> Pre-fetch Terraform providers (terraform init)"
if [[ -d terraform ]]; then
  ( cd terraform && terraform init -input=false -backend=false >/dev/null 2>&1 ) || \
    echo "   (terraform init skipped/failed; will run at task time)"
fi

echo "==> Tool versions:"
terraform version | head -1
conftest --version | head -1
opa version | head -1
tfsec --version
cosign version 2>/dev/null | grep -i "GitVersion\|^v" | head -1 || true
aws --version
echo "==> grc-gate environment ready."
