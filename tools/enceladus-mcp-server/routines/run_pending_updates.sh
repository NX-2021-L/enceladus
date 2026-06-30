#!/usr/bin/env bash
# run_pending_updates.sh — ENC-FTR-074 Ph2 (ENC-TSK-I80) hourly Pending-Updates routine runner.
#
# Executes the governed "Pending Updates" read against the gamma Enceladus MCP gateway,
# authenticated by a FRESH Cognito M2M access_token with the agent.standard scope (minted by
# agent_m2m_headers_helper.sh via the client_credentials grant). Designed to be invoked on an
# hourly schedule (cron / systemd timer / EventBridge-Scheduler→runner / Claude Code routine).
# Each run authenticates through the Ph2 REQUEST authorizer (Tier 1 admits agent.standard) and
# the call is recorded in the gamma MCP / coordination-api CloudWatch logs (AC4 evidence).
#
# Env (with gamma defaults):
#   ENCELADUS_GAMMA_MCP_URL   default https://enceladus-gamma.jreese.net/api/v1/coordination/mcp
#   ENCELADUS_M2M_SCOPE       forced to enceladus-api/agent.standard for this routine
#   ENCELADUS_PROJECT_ID      default enceladus
# Plus the credential/endpoint env consumed by agent_m2m_headers_helper.sh.
#
# Exit 0 on a successful governed response; non-zero otherwise (so the scheduler can alarm).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELPER="${SCRIPT_DIR}/../agent_m2m_headers_helper.sh"

MCP_URL="${ENCELADUS_GAMMA_MCP_URL:-https://enceladus-gamma.jreese.net/api/v1/coordination/mcp}"
PROJECT_ID="${ENCELADUS_PROJECT_ID:-enceladus}"
export ENCELADUS_M2M_SCOPE="enceladus-api/agent.standard"

PYTHON_BIN="${ENCELADUS_MCP_PYTHON_BIN:-$(command -v python3 || true)}"
if [ -z "${PYTHON_BIN}" ]; then
  echo "[ERROR] python3 required." >&2
  exit 1
fi

TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "[INFO] ${TS} pending-updates routine starting (scope=agent.standard, url=${MCP_URL})"

# Mint a fresh M2M bearer token (agent.standard).
ACCESS_TOKEN="$(bash "${HELPER}" --token)"
if [ -z "${ACCESS_TOKEN}" ]; then
  echo "[ERROR] Failed to mint M2M access_token." >&2
  exit 1
fi

# Governed read: code-mode 'search' tool, action tracker.pending_updates.
REQ_BODY="$("${PYTHON_BIN}" -c '
import json, os
print(json.dumps({
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
        "name": "search",
        "arguments": {
            "action": "tracker.pending_updates",
            "arguments": {"project_id": os.environ["PROJECT_ID"]},
        },
    },
}))
' PROJECT_ID="${PROJECT_ID}")"

RESPONSE="$(curl -sS -w '\n%{http_code}' -X POST "${MCP_URL}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -d "${REQ_BODY}" 2>/dev/null || true)"

HTTP_CODE="$(printf '%s' "${RESPONSE}" | tail -1)"
BODY="$(printf '%s' "${RESPONSE}" | sed '$d')"

if [ "${HTTP_CODE}" = "200" ]; then
  COUNT="$(printf '%s' "${BODY}" | "${PYTHON_BIN}" -c '
import json, sys
try:
    obj = json.load(sys.stdin)
except Exception:
    print("unknown"); sys.exit(0)
res = (obj.get("result") or {})
# MCP content envelope or direct result.
print("ok")
' 2>/dev/null || echo "unknown")"
  echo "[SUCCESS] $(date -u +%Y-%m-%dT%H:%M:%SZ) pending-updates routine completed (HTTP 200, ${COUNT})"
  exit 0
fi

if [ "${HTTP_CODE}" = "401" ] || [ "${HTTP_CODE}" = "403" ]; then
  echo "[ERROR] pending-updates routine denied (HTTP ${HTTP_CODE}). Token tier/scope or authorizer config." >&2
  echo "${BODY}" >&2
  exit 1
fi

echo "[ERROR] pending-updates routine failed (HTTP ${HTTP_CODE})." >&2
echo "${BODY}" >&2
exit 1
