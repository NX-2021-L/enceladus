#!/usr/bin/env bash
# Pre-deploy health gate for direct CLI CloudFormation deploys.
#
# MUST be run before any `aws cloudformation deploy` against production stacks.
# Direct CFN deploys bypass all CI guards — the Sev1 incident on 2026-04-11
# (DOC-2CACF0D1E7E6) was caused by a direct CLI deploy, not GitHub Actions.
#
# Usage:
#   bash tools/pre-deploy-health-gate.sh \
#     --stack enceladus-compute \
#     --template infrastructure/cloudformation/02-compute.yaml
#
# Checks performed:
#   1. Captures current Lambda CodeSize/Architecture/Runtime snapshot
#   2. Validates CFN template contains IsGamma conditionals (via verify_lambda_arch_parity.py)
#   3. Validates EnvironmentSuffix parameter presence in template
#   4. Warns operator about direct deploy risks
#
# Part of ENC-PLN-020 (Production Deploy Hardening) / ENC-FTR-068.

set -euo pipefail

REGION="${AWS_DEFAULT_REGION:-us-west-2}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MANIFEST="${REPO_ROOT}/infrastructure/lambda_workflow_manifest.json"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"

# --- Parse arguments ---
STACK_NAME=""
TEMPLATE_FILE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --stack) STACK_NAME="$2"; shift 2 ;;
        --template) TEMPLATE_FILE="$2"; shift 2 ;;
        --region) REGION="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 --stack <stack-name> --template <template-path> [--region <region>]"
            exit 0
            ;;
        *) echo "[ERROR] Unknown argument: $1"; exit 1 ;;
    esac
done

if [[ -z "${STACK_NAME}" || -z "${TEMPLATE_FILE}" ]]; then
    echo "[ERROR] --stack and --template are required"
    echo "Usage: $0 --stack enceladus-compute --template infrastructure/cloudformation/02-compute.yaml"
    exit 1
fi

# Resolve template path relative to repo root if not absolute
if [[ ! "${TEMPLATE_FILE}" = /* ]]; then
    TEMPLATE_FILE="${REPO_ROOT}/${TEMPLATE_FILE}"
fi

if [[ ! -f "${TEMPLATE_FILE}" ]]; then
    echo "[ERROR] Template file not found: ${TEMPLATE_FILE}"
    exit 1
fi

echo "============================================================"
echo "  PRE-DEPLOY HEALTH GATE — DIRECT CFN DEPLOY SAFETY CHECK"
echo "============================================================"
echo ""
echo "  WARNING: Direct 'aws cloudformation deploy' bypasses ALL"
echo "  CI guards (CI, Secrets Scan, PR Commit Gate, Governance"
echo "  Dictionary Guard). The Sev1 incident on 2026-04-11 was"
echo "  caused by a direct CLI deploy, NOT by GitHub Actions."
echo ""
echo "  Stack:    ${STACK_NAME}"
echo "  Template: ${TEMPLATE_FILE}"
echo "  Region:   ${REGION}"
echo ""
echo "============================================================"
echo ""

ERRORS=0
SNAPSHOT_FILE="/tmp/pre-deploy-snapshot-${TIMESTAMP}.json"

# --- Check 1: Capture Lambda snapshot ---
echo "[CHECK 1/4] Capturing current Lambda state snapshot..."

if [[ ! -f "${MANIFEST}" ]]; then
    echo "[ERROR] Lambda workflow manifest not found: ${MANIFEST}"
    ERRORS=$((ERRORS + 1))
else
    FUNCTIONS=$(python3 -c "
import json, sys
m = json.load(open('${MANIFEST}'))
for f in m.get('functions', []):
    print(f['function_name'])
")

    echo "[" > "${SNAPSHOT_FILE}"
    FIRST=true
    COUNT=0
    for fn in ${FUNCTIONS}; do
        CONFIG=$(aws lambda get-function-configuration \
            --function-name "${fn}" \
            --region "${REGION}" \
            --query '{FunctionName:FunctionName,CodeSize:CodeSize,Runtime:Runtime,Architectures:Architectures,LastModified:LastModified}' \
            --output json 2>/dev/null || echo '{"FunctionName":"'"${fn}"'","error":"not_found"}')

        if [[ "${FIRST}" == "true" ]]; then
            FIRST=false
        else
            echo "," >> "${SNAPSHOT_FILE}"
        fi
        echo "  ${CONFIG}" >> "${SNAPSHOT_FILE}"
        COUNT=$((COUNT + 1))

        # Check CodeSize while we're at it
        CODE_SIZE=$(echo "${CONFIG}" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('CodeSize',0))" 2>/dev/null || echo "0")
        if [[ "${CODE_SIZE}" -lt 1024 && "${CODE_SIZE}" -gt 0 ]]; then
            echo "  [ALERT] ${fn}: CodeSize=${CODE_SIZE} bytes (< 1024) — possible CFN stub!"
            ERRORS=$((ERRORS + 1))
        fi
    done
    echo "]" >> "${SNAPSHOT_FILE}"

    echo "[INFO] Snapshot saved: ${SNAPSHOT_FILE} (${COUNT} Lambdas)"
fi

# --- Check 2: Validate IsGamma conditionals ---
echo ""
echo "[CHECK 2/4] Validating CFN template architecture parity..."

if python3 "${REPO_ROOT}/tools/verify_lambda_arch_parity.py"; then
    echo "[PASS] CFN template uses IsGamma conditionals correctly"
else
    echo "[FAIL] CFN template has architecture parity violations"
    ERRORS=$((ERRORS + 1))
fi

# --- Check 3: Validate EnvironmentSuffix parameter ---
echo ""
echo "[CHECK 3/4] Validating EnvironmentSuffix parameter in template..."

if grep -q "EnvironmentSuffix" "${TEMPLATE_FILE}"; then
    echo "[PASS] Template contains EnvironmentSuffix parameter"
else
    echo "[FAIL] Template missing EnvironmentSuffix parameter — deploy will apply universally!"
    ERRORS=$((ERRORS + 1))
fi

# --- Check 4: Validate deploy scripts ---
echo ""
echo "[CHECK 4/4] Validating deploy scripts via manifest..."

# This is already done by verify_lambda_arch_parity.py, but we add a specific
# check for hardcoded RUNTIME/ARCHITECTURE defaults without conditionals
HARDCODED_SCRIPTS=$(grep -rn 'RUNTIME="\${RUNTIME:-python3\.12}"' "${REPO_ROOT}"/backend/lambda/*/deploy.sh 2>/dev/null || true)
if [[ -n "${HARDCODED_SCRIPTS}" ]]; then
    echo "[FAIL] Deploy scripts with hardcoded python3.12 defaults:"
    echo "${HARDCODED_SCRIPTS}"
    ERRORS=$((ERRORS + 1))
else
    echo "[PASS] No deploy scripts with hardcoded python3.12 defaults"
fi

# --- Summary ---
echo ""
echo "============================================================"
if [[ ${ERRORS} -gt 0 ]]; then
    echo "  HEALTH GATE: FAILED (${ERRORS} errors)"
    echo "  DO NOT proceed with 'aws cloudformation deploy'."
    echo "============================================================"
    exit 1
else
    echo "  HEALTH GATE: PASSED"
    echo "  Snapshot: ${SNAPSHOT_FILE}"
    echo ""
    echo "  You may proceed with the direct deploy. After completion,"
    echo "  run the UAT suite to validate:"
    echo "    python3 tools/gamma_uat_suite.py --environment production --full-stack"
    echo "============================================================"
    exit 0
fi
