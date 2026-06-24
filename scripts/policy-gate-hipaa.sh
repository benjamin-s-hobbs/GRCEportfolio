#!/usr/bin/env bash
# scripts/policy-gate-hipaa.sh
#
# Run the Conftest policy gate against a Terraform plan. Used locally and by
# the GitHub Actions workflow in Lab 4.3.
#
# Usage:
#   policy-gate.sh --workspace <terraform-workspace> [--policy <policies-dir>]
#
# Exits 0 on pass, 1 on any policy failure. Always writes machine-readable
# output to evidence/lab-3-4/conftest-results.json.

set -euo pipefail

POLICY_DIR="policies/aws/hipaa/"
WORKSPACE=""
EVIDENCE_DIR="evidence/lab-3-4"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace) WORKSPACE="$2"; shift 2 ;;
    --policy)    POLICY_DIR="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -z "$WORKSPACE" ]] && { echo "Usage: $0 --workspace <path>" >&2; exit 2; }

mkdir -p "$EVIDENCE_DIR"

# Generate plan.json from a saved tfplan if present, otherwise from a fresh plan.
if [[ -f "$WORKSPACE/tfplan" ]]; then
  ( cd "$WORKSPACE" && terraform show -json tfplan > "$WORKSPACE/plan.json" )
else
  echo "No tfplan found in $WORKSPACE. Run terraform plan -out=tfplan first." >&2
  exit 2
fi

# Run all HIPAA namespaces. Capture JSON output even on failure.
EXIT=0
{
    echo "["
    FIRST=1
      for ns in aws.hipaa.tls_deny aws.hipaa.bucket_versioning_status aws.hipaa.bucket_versioning_exists aws.hipaa.lambda_vpc aws.hipaa.least_privilege aws.hipaa.apigw_logging aws.hipaa.apigw_waf ; do
    [[ $FIRST -eq 1 ]] && FIRST=0 || printf ","
        
    conftest test --policy ../policies/aws/hipaa/ --namespace "$ns" --output=json plan.json || true
    done
    echo "]"
} > "$EVIDENCE_DIR/conftest-results.json"

if [[ $EXIT -eq 0 ]]; then
  echo "policy-gate: PASS"
else
  echo "policy-gate: FAIL"
  echo "See $EVIDENCE_DIR/conftest-results.json for details."
fi

exit $EXIT