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
#   4. Validates deploy scripts have no hardcoded runtime defaults
#   5. Validates enceladus-shared layer is pinned to canonical (verify_shared_layer_version.py)
#   6. Validates env-var parity — no out-of-band vars the deploy would strip (env_parity_gate.py)
#   7. Validates no live CFN drift (fail-on-drift; audit_cfn_drift.py) before touching the stack
#   ...and warns operator about direct deploy risks
#
# Part of ENC-PLN-020 (Production Deploy Hardening) / ENC-FTR-068.
# ENC-TSK-H24: Check 5 added — the enceladus-shared :7-vs-:10 layer-version parity gate.
# ENC-PLN-048 / ENC-FTR-102: Check 6 added — env-var parity gate (H17 resolver + H18 fail-closed).
# ENC-TSK-J12 / ENC-ISS-455: Check 7 added — CFN drift regression guard. Adding or
# adopting an out-of-band-existing resource via a plain deploy fails
# AWS::EarlyValidation::ResourceExistenceCheck and wedges the stack (R1/R2 in
# DOC-AA5C7A37A103); this check fails the gate closed while unresolved live
# drift exists, until the change-set IMPORT reconciliation (ENC-TSK-J14) lands.

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
echo "[CHECK 1/7] Capturing current Lambda state snapshot..."

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
echo "[CHECK 2/7] Validating CFN template architecture parity..."

if python3 "${REPO_ROOT}/tools/verify_lambda_arch_parity.py"; then
    echo "[PASS] CFN template uses IsGamma conditionals correctly"
else
    echo "[FAIL] CFN template has architecture parity violations"
    ERRORS=$((ERRORS + 1))
fi

# --- Check 3: Validate EnvironmentSuffix parameter ---
echo ""
echo "[CHECK 3/7] Validating EnvironmentSuffix parameter in template..."

if grep -q "EnvironmentSuffix" "${TEMPLATE_FILE}"; then
    echo "[PASS] Template contains EnvironmentSuffix parameter"
else
    echo "[FAIL] Template missing EnvironmentSuffix parameter — deploy will apply universally!"
    ERRORS=$((ERRORS + 1))
fi

# --- Check 4: Validate deploy scripts ---
echo ""
echo "[CHECK 4/7] Validating deploy scripts via manifest..."

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

# --- Check 5: Validate enceladus-shared layer-version parity (ENC-TSK-H24) ---
echo ""
echo "[CHECK 5/7] Validating enceladus-shared layer-version pin (:7-vs-:10 gate)..."

# Static checks (template Default + workflow --parameter-overrides override) are
# fail-closed (no AWS creds needed). ENC-TSK-H28 added the workflow-override check that
# closes the ENC-ISS-385 blind spot: `aws cloudformation deploy` reuses the stale stored
# SharedLayerArn (:7) unless the workflow passes the canonical override, so a green template
# Default alone never moved live. --live --regress-only opportunistically diffs the deployed
# stack param + live get-function-configuration and fails ONLY on a regression (a function/
# stack ABOVE canonical), TOLERATING a stale :7 here because THIS deploy is what heals it
# (skips silently without creds). Post-deploy, reconcile with bare --live (fails on ANY
# != canonical) to PROVE the :7->:10 heal landed -- see the tool docstring.
if python3 "${REPO_ROOT}/tools/verify_shared_layer_version.py" "${TEMPLATE_FILE}" \
        --live --regress-only --stack-name "${STACK_NAME}"; then
    echo "[PASS] enceladus-shared template+workflow pinned to canonical; no live regression"
else
    echo "[FAIL] enceladus-shared layer-version parity violation (missing workflow override or live regression; would (re)introduce the :7-class incident, ENC-ISS-385 / ENC-LSN-053)"
    ERRORS=$((ERRORS + 1))
fi

# --- Check 6: Validate environment-variable parity (ENC-PLN-048 / ENC-FTR-102) ---
# Resolves the template's per-function Environment.Variables (evaluating
# !Ref/--parameter-overrides, !Sub, !If/AWS::NoValue) and fails closed if any
# deploy-critical required var would be unset — the exact H05/H09 "deploy would
# strip <var>" class. ENC-TSK-H16: the required vars AND their deploy-critical/
# advisory classification are the single source in env_drift_registry.json;
# tools/env_parity_waivers.json carries only risk-accepted failure suppressions.
echo ""
echo "[CHECK 6/7] Validating env-var parity (no out-of-band vars the deploy would strip)..."

# Infer EnvironmentSuffix from the stack name so gamma stacks resolve their -gamma env.
PARITY_PARAMS=()
case "${STACK_NAME}" in
    *gamma*) PARITY_PARAMS+=(--parameter "EnvironmentSuffix=-gamma") ;;
esac

if python3 "${REPO_ROOT}/tools/env_parity_gate.py" \
        --template "${TEMPLATE_FILE}" \
        ${PARITY_PARAMS[@]+"${PARITY_PARAMS[@]}"}; then
    echo "[PASS] All deploy-critical env vars are present in the template-resolved env"
else
    echo "[FAIL] Env parity gate found deploy-critical vars the deploy would strip (see above)"
    ERRORS=$((ERRORS + 1))
fi

# --- Check 7: Validate no live CFN drift (ENC-TSK-J12 / ENC-ISS-455) ---
# A plain deploy that ADDs or adopts a resource already existing out-of-band
# fails AWS::EarlyValidation::ResourceExistenceCheck and wedges the stack
# (R1/R2, DOC-AA5C7A37A103). Fail the gate closed while unresolved live drift
# exists on the stack's environment; this is expected to (correctly) fail
# on the API stack until the change-set IMPORT reconciliation (ENC-TSK-J14)
# lands. Infer environment from the stack name, same as Check 6.
echo ""
DRIFT_ENV="prod"
case "${STACK_NAME}" in
    *gamma*) DRIFT_ENV="gamma" ;;
esac
DRIFT_REPORT="/tmp/pre-deploy-drift-${TIMESTAMP}.json"
echo "[CHECK 7/7] Validating no live CFN drift (environment=${DRIFT_ENV}, fail-on-drift)..."

if python3 "${REPO_ROOT}/tools/audit_cfn_drift.py" \
        --environment "${DRIFT_ENV}" \
        --output-json "${DRIFT_REPORT}" \
        --fail-on-drift; then
    echo "[PASS] No CFN drift detected for ${DRIFT_ENV}"
else
    echo "[FAIL] CFN drift detected for ${DRIFT_ENV} — resolve before deploying (see ${DRIFT_REPORT}; ENC-ISS-455 / ENC-TSK-J12)"
    ERRORS=$((ERRORS + 1))
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
