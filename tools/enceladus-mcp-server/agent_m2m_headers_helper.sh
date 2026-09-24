#!/usr/bin/env bash
# agent_m2m_headers_helper.sh — ENC-FTR-074 Ph2 (ENC-TSK-I80) headers helper.
#
# Acquires a FRESH Cognito access_token for the headless agent (enceladus-agent-m2m App
# Client) via the OAuth2 client_credentials grant against the agent-auth User Pool stood up
# in Ph1 (08-agent-auth.yaml / ENC-TSK-I79), and injects it as an Authorization: Bearer
# header for the gamma Enceladus MCP gateway. This is the ".mcp.json headersHelper" referenced
# by tools/enceladus-mcp-server/mcp.gamma-m2m.json.
#
# The minted token carries the enc:agent_tier + enc:session_id custom claims (pre-token Lambda)
# and the requested resource-server scope, so the Ph2 REQUEST authorizer can tier-gate it.
#
# Output modes (pick one):
#   --headers-json   Print {"Authorization":"Bearer <token>"}            (default)
#   --token          Print the raw access_token only
#   --export         Print: export ENCELADUS_M2M_BEARER='Bearer <token>'
#                            export ENCELADUS_M2M_ACCESS_TOKEN='<token>'
#
# Credential resolution (first match wins):
#   1. ENCELADUS_M2M_CLIENT_ID + ENCELADUS_M2M_CLIENT_SECRET (env)
#   2. Secrets Manager secret ENCELADUS_M2M_SECRET_ID (default enceladus/agent-m2m/client-secret),
#      whose SecretString is {"client_id":"...","client_secret":"..."} (hydrated by the Ph1
#      rotation Lambda). Requires AWS credentials with secretsmanager:GetSecretValue.
#
# Endpoint / scope (env, with gamma defaults):
#   ENCELADUS_M2M_TOKEN_ENDPOINT   OAuth2 token endpoint (no default — must be set OR derivable)
#   ENCELADUS_M2M_DOMAIN_PREFIX    Hosted-UI domain prefix (used to derive the endpoint)
#   ENCELADUS_M2M_REGION           default us-west-2
#   ENCELADUS_M2M_SCOPE            default enceladus-api/agent.standard
#
# Never prints the client_secret. Token is short-lived (60 min; see Ph1 AccessTokenValidity).

set -euo pipefail

OUTPUT_MODE="--headers-json"
case "${1:-}" in
  --headers-json|--token|--export) OUTPUT_MODE="$1" ;;
  "") : ;;
  *) echo "usage: $0 [--headers-json|--token|--export]" >&2; exit 2 ;;
esac

REGION="${ENCELADUS_M2M_REGION:-us-west-2}"
SCOPE="${ENCELADUS_M2M_SCOPE:-enceladus-api/agent.standard}"
SECRET_ID="${ENCELADUS_M2M_SECRET_ID:-enceladus/agent-m2m/client-secret}"

PYTHON_BIN="${ENCELADUS_MCP_PYTHON_BIN:-$(command -v python3 || true)}"
if [ -z "${PYTHON_BIN}" ]; then
  echo "[ERROR] python3 is required (JSON parsing)." >&2
  exit 1
fi

CLIENT_ID="${ENCELADUS_M2M_CLIENT_ID:-}"
CLIENT_SECRET="${ENCELADUS_M2M_CLIENT_SECRET:-}"

# Resolve credentials from Secrets Manager when not provided directly.
if [ -z "${CLIENT_ID}" ] || [ -z "${CLIENT_SECRET}" ]; then
  if ! command -v aws >/dev/null 2>&1; then
    echo "[ERROR] No ENCELADUS_M2M_CLIENT_ID/SECRET in env and AWS CLI not available to read ${SECRET_ID}." >&2
    exit 1
  fi
  SECRET_JSON="$(aws secretsmanager get-secret-value \
      --region "${REGION}" \
      --secret-id "${SECRET_ID}" \
      --query SecretString --output text 2>/dev/null || true)"
  if [ -z "${SECRET_JSON}" ]; then
    echo "[ERROR] Could not read Secrets Manager secret ${SECRET_ID} in ${REGION}." >&2
    exit 1
  fi
  CLIENT_ID="$(printf '%s' "${SECRET_JSON}" | "${PYTHON_BIN}" -c 'import json,sys;print(json.load(sys.stdin).get("client_id",""))')"
  CLIENT_SECRET="$(printf '%s' "${SECRET_JSON}" | "${PYTHON_BIN}" -c 'import json,sys;print(json.load(sys.stdin).get("client_secret",""))')"
fi

if [ -z "${CLIENT_ID}" ] || [ -z "${CLIENT_SECRET}" ]; then
  echo "[ERROR] M2M client_id/client_secret unresolved (set ENCELADUS_M2M_CLIENT_ID/SECRET or populate ${SECRET_ID})." >&2
  exit 1
fi

# Resolve the OAuth2 token endpoint.
TOKEN_ENDPOINT="${ENCELADUS_M2M_TOKEN_ENDPOINT:-}"
if [ -z "${TOKEN_ENDPOINT}" ]; then
  if [ -n "${ENCELADUS_M2M_DOMAIN_PREFIX:-}" ]; then
    TOKEN_ENDPOINT="https://${ENCELADUS_M2M_DOMAIN_PREFIX}.auth.${REGION}.amazoncognito.com/oauth2/token"
  else
    echo "[ERROR] Set ENCELADUS_M2M_TOKEN_ENDPOINT (or ENCELADUS_M2M_DOMAIN_PREFIX) — the agent-auth" >&2
    echo "[ERROR] OAuth2 token endpoint is account-specific (see 08-agent-auth.yaml TokenEndpoint output)." >&2
    exit 1
  fi
fi

# client_credentials grant with client_secret_basic auth.
RESPONSE="$(curl -sS -X POST "${TOKEN_ENDPOINT}" \
  -u "${CLIENT_ID}:${CLIENT_SECRET}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "scope=${SCOPE}" 2>/dev/null || true)"

ACCESS_TOKEN="$(printf '%s' "${RESPONSE}" | "${PYTHON_BIN}" -c '
import json, sys
try:
    obj = json.load(sys.stdin)
except Exception:
    sys.exit(0)
print(obj.get("access_token", ""))
')"

if [ -z "${ACCESS_TOKEN}" ]; then
  ERR="$(printf '%s' "${RESPONSE}" | "${PYTHON_BIN}" -c '
import json, sys
try:
    obj = json.load(sys.stdin)
    print(obj.get("error_description") or obj.get("error") or "")
except Exception:
    print("")
')"
  echo "[ERROR] client_credentials grant failed at ${TOKEN_ENDPOINT} (scope=${SCOPE}). ${ERR}" >&2
  exit 1
fi

case "${OUTPUT_MODE}" in
  --token)
    printf '%s\n' "${ACCESS_TOKEN}"
    ;;
  --export)
    printf "export ENCELADUS_M2M_BEARER='Bearer %s'\n" "${ACCESS_TOKEN}"
    printf "export ENCELADUS_M2M_ACCESS_TOKEN='%s'\n" "${ACCESS_TOKEN}"
    ;;
  --headers-json|*)
    ACCESS_TOKEN="${ACCESS_TOKEN}" "${PYTHON_BIN}" -c '
import json, os
print(json.dumps({"Authorization": "Bearer " + os.environ["ACCESS_TOKEN"]}))
'
    ;;
esac
