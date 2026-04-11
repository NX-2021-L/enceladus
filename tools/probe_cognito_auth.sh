#!/usr/bin/env bash
# probe_cognito_auth.sh — bootstrap a Cognito IdToken via the terminal-agent path
# and probe Cognito-protected Lambda routes with `Authorization: Bearer <token>`.
#
# ENC-ISS-198 / ENC-TSK-D22 (H9): the COE Phase R3 empirical validation in
# DOC-2CACF0D1E7E6 used a synthetic `aws lambda invoke` probe with no
# Authorization header. That probe lands in the no-token path of
# `auth.py:_authenticate()` and returns HTTP 401 *before* `_verify_token()` is
# ever called — which is structurally indistinguishable from the 401 a real
# Cognito-authenticated request produces when the JWT init has silently failed.
# The COE recovery declared the platform healthy while every Cognito-protected
# write was actually broken for ~3 hours.
#
# This script closes that gap. It actually exercises `_verify_token()` with a
# real IdToken and confirms the response is NOT the misleading
# "JWT library not available in Lambda package" 401.
#
# Usage:
#   ./tools/probe_cognito_auth.sh                       # probe the default route set
#   ./tools/probe_cognito_auth.sh --route /api/v1/...    # probe a specific route
#   ./tools/probe_cognito_auth.sh --json                 # JSON output for CI
#
# Required:
#   AWS_PROFILE pointing at io-dev-admin (or env credentials with secretsmanager:GetSecretValue
#   on devops/coordination/cognito/terminal-agent and cognito-idp:InitiateAuth on the user pool).
#
# Output: PASS/FAIL summary per probed route. Exit 0 if all routes return non-401 OR a
# non-JWT-related 401 (e.g. expired token retry). Exit 1 if any route returns the
# canonical "JWT library not available in Lambda package" error.

set -euo pipefail

REGION="${REGION:-us-west-2}"
COGNITO_REGION="${COGNITO_REGION:-us-east-1}"
SECRET_ID="${TERMINAL_COGNITO_SECRET_ID:-devops/coordination/cognito/terminal-agent}"
API_BASE="${API_BASE:-https://8nkzqkmxqc.execute-api.us-west-2.amazonaws.com}"

# Default route set: one representative read path per Cognito-protected Lambda
# in `backend/lambda/shared_layer/deploy.sh:ALL_FUNCTIONS`. Each route is chosen
# to require auth but NOT require write permissions, so the probe is read-only.
DEFAULT_ROUTES=(
    "GET /api/v1/coordination/components"                          # devops-coordination-api
    "GET /api/v1/tracker/enceladus"                                # devops-tracker-mutation-api (list path)
    "GET /api/v1/documents?project_id=enceladus&limit=1"           # devops-document-api
    "GET /api/v1/projects"                                         # devops-project-service
    "GET /api/v1/feed?project_id=enceladus"                        # devops-feed-query-api
    "GET /api/v1/coordination/sessions"                            # devops-coordination-monitor-api
    "GET /api/v1/deploy/pending/enceladus"                         # devops-deploy-intake / orchestrator
    "GET /api/v1/changelog/version/enceladus"                      # devops-changelog-api
    "GET /api/v1/governance/dictionary"                            # devops-coordination-api governance
    "GET /api/v1/coordination/auth/tokens"                         # devops-coordination-api auth
)

ROUTE_OVERRIDE=""
JSON_OUT=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --route) ROUTE_OVERRIDE="$2"; shift 2 ;;
        --json) JSON_OUT=1; shift ;;
        -h|--help)
            sed -n '2,30p' "$0"; exit 0 ;;
        *) echo "Unknown arg: $1" >&2; exit 2 ;;
    esac
done

log() { [[ "$JSON_OUT" -eq 0 ]] && echo "[$(date -u +%H:%M:%SZ)] $*" >&2; }

# ---------------------------------------------------------------------------
# Step 1: bootstrap a Cognito IdToken via the terminal-agent path
# ---------------------------------------------------------------------------
log "[START] Bootstrapping terminal-agent Cognito IdToken"

if ! command -v aws >/dev/null 2>&1; then
    echo "ERROR: aws CLI not found in PATH" >&2; exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
    # Use python as a jq fallback so this works on stock macOS
    JQ() { python3 -c "import sys, json; d=json.load(sys.stdin); print(${1})"; }
else
    JQ() { jq -r "$1"; }
fi

SECRET_JSON="$(aws secretsmanager get-secret-value \
    --region "${REGION}" \
    --secret-id "${SECRET_ID}" \
    --query SecretString \
    --output text 2>&1)" || {
    echo "ERROR: failed to fetch ${SECRET_ID} from Secrets Manager: ${SECRET_JSON}" >&2
    exit 2
}

USERNAME="$(echo "${SECRET_JSON}" | python3 -c "import sys,json; print(json.load(sys.stdin)['username'])")"
PASSWORD="$(echo "${SECRET_JSON}" | python3 -c "import sys,json; print(json.load(sys.stdin)['password'])")"
CLIENT_ID="$(echo "${SECRET_JSON}" | python3 -c "import sys,json; print(json.load(sys.stdin)['client_id'])")"
AUTH_FLOW="$(echo "${SECRET_JSON}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('auth_flow','USER_PASSWORD_AUTH'))")"

ID_TOKEN="$(aws cognito-idp initiate-auth \
    --region "${COGNITO_REGION}" \
    --auth-flow "${AUTH_FLOW}" \
    --client-id "${CLIENT_ID}" \
    --auth-parameters "USERNAME=${USERNAME},PASSWORD=${PASSWORD}" \
    --query 'AuthenticationResult.IdToken' \
    --output text)"

if [[ -z "${ID_TOKEN}" || "${ID_TOKEN}" == "None" ]]; then
    echo "ERROR: Cognito initiate-auth returned empty IdToken" >&2
    exit 2
fi

log "[INFO] IdToken acquired (length=${#ID_TOKEN})"

# ---------------------------------------------------------------------------
# Step 2: probe each route
# ---------------------------------------------------------------------------
if [[ -n "${ROUTE_OVERRIDE}" ]]; then
    ROUTES=("GET ${ROUTE_OVERRIDE}")
else
    ROUTES=("${DEFAULT_ROUTES[@]}")
fi

PASS=0
FAIL=0
RESULTS_JSON="["

for entry in "${ROUTES[@]}"; do
    METHOD="${entry%% *}"
    PATH_PART="${entry#* }"
    URL="${API_BASE}${PATH_PART}"

    log "[PROBE] ${METHOD} ${PATH_PART}"

    HTTP_CODE_AND_BODY="$(curl -sS -o /tmp/probe_body.txt -w "%{http_code}" \
        -X "${METHOD}" \
        -H "Authorization: Bearer ${ID_TOKEN}" \
        "${URL}" 2>&1 || echo "000")"
    HTTP_CODE="${HTTP_CODE_AND_BODY: -3}"
    BODY_PREVIEW="$(head -c 400 /tmp/probe_body.txt 2>/dev/null || echo '')"

    # FAIL if the body contains the canonical ENC-ISS-198 error string
    if grep -q "JWT library not available in Lambda package" /tmp/probe_body.txt 2>/dev/null; then
        FAIL=$((FAIL + 1))
        STATUS="FAIL"
        REASON="ENC-ISS-198 error string present in response body"
    elif [[ "${HTTP_CODE}" =~ ^[2-3][0-9][0-9]$ ]]; then
        PASS=$((PASS + 1))
        STATUS="PASS"
        REASON="HTTP ${HTTP_CODE} (success)"
    elif [[ "${HTTP_CODE}" =~ ^4[0-9][0-9]$ ]] && [[ "${HTTP_CODE}" != "401" ]]; then
        # 4xx other than 401 (e.g. 404 not found, 400 bad request, 405 method
        # not allowed) is fine — we just confirmed auth was processed.
        PASS=$((PASS + 1))
        STATUS="PASS"
        REASON="HTTP ${HTTP_CODE} (auth processed, non-auth error)"
    elif [[ "${HTTP_CODE}" == "401" ]]; then
        FAIL=$((FAIL + 1))
        STATUS="FAIL"
        REASON="HTTP 401 — token rejected (check token validity OR check for ENC-ISS-198 regression)"
    else
        FAIL=$((FAIL + 1))
        STATUS="FAIL"
        REASON="HTTP ${HTTP_CODE} (unexpected)"
    fi

    if [[ "${JSON_OUT}" -eq 1 ]]; then
        RESULTS_JSON="${RESULTS_JSON}{\"method\":\"${METHOD}\",\"path\":\"${PATH_PART}\",\"http_code\":\"${HTTP_CODE}\",\"status\":\"${STATUS}\",\"reason\":\"${REASON}\"},"
    else
        printf "  [%s] %-3s %-50s HTTP %-4s — %s\n" "${STATUS}" "${METHOD}" "${PATH_PART}" "${HTTP_CODE}" "${REASON}"
    fi
done

if [[ "${JSON_OUT}" -eq 1 ]]; then
    RESULTS_JSON="${RESULTS_JSON%,}]"
    printf '{"pass":%d,"fail":%d,"results":%s}\n' "${PASS}" "${FAIL}" "${RESULTS_JSON}"
else
    echo
    echo "[SUMMARY] PASS=${PASS}  FAIL=${FAIL}  TOTAL=${#ROUTES[@]}"
fi

if [[ "${FAIL}" -gt 0 ]]; then
    exit 1
fi
exit 0
