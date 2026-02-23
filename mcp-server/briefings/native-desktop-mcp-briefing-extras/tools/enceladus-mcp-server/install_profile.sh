#!/usr/bin/env bash
# install_profile.sh — Install the Enceladus MCP server profile for provider sessions.
#
# Registers the Enceladus MCP server with Claude Code (or compatible MCP clients)
# so provider sessions can access governed Enceladus system resources.
#
# Usage:
#   ./install_profile.sh                    # Auto-detect workspace root
#   ENCELADUS_WORKSPACE_ROOT=/path ./install_profile.sh   # Override root
#
# Related: DVP-TSK-245, DVP-FTR-023

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_PY="${SCRIPT_DIR}/server.py"

# Workspace root auto-detection
WORKSPACE_ROOT="${ENCELADUS_WORKSPACE_ROOT:-$(cd "${SCRIPT_DIR}/../../.." && pwd)}"

echo "[INFO] Enceladus MCP profile installer"
echo "[INFO] Server: ${SERVER_PY}"
echo "[INFO] Workspace root: ${WORKSPACE_ROOT}"

# Verify server.py exists
if [ ! -f "${SERVER_PY}" ]; then
    echo "[ERROR] server.py not found at ${SERVER_PY}"
    exit 1
fi

# Verify Python + dependencies
if ! python3 -c "import mcp, boto3" >/dev/null 2>&1; then
    echo "[INFO] Installing required Python packages..."
    python3 -m pip install --user --quiet mcp boto3 PyYAML 2>/dev/null || {
        echo "[ERROR] Failed to install required packages (mcp, boto3, PyYAML)"
        exit 1
    }
fi

# Verify AWS credentials
if ! aws sts get-caller-identity >/dev/null 2>&1; then
    echo "[WARNING] AWS credentials not available. MCP server will have limited functionality."
fi

# Resolve a stable AWS profile for MCP runtime when possible.
# If credential separation is enabled below, writer profile takes precedence.
RESOLVED_AWS_PROFILE=""
if [ -n "${AWS_PROFILE:-}" ]; then
    if aws sts get-caller-identity --profile "${AWS_PROFILE}" >/dev/null 2>&1; then
        RESOLVED_AWS_PROFILE="${AWS_PROFILE}"
        echo "[INFO] Using AWS_PROFILE from shell: ${RESOLVED_AWS_PROFILE}"
    else
        echo "[WARNING] Shell AWS_PROFILE='${AWS_PROFILE}' is not usable for sts; ignoring."
    fi
fi

if [ -z "${RESOLVED_AWS_PROFILE}" ]; then
    for candidate in personal default ec2-role; do
        if aws sts get-caller-identity --profile "${candidate}" >/dev/null 2>&1; then
            RESOLVED_AWS_PROFILE="${candidate}"
            echo "[INFO] Auto-detected AWS profile for MCP runtime: ${RESOLVED_AWS_PROFILE}"
            break
        fi
    done
fi

# Configure MCP writer AWS profile for credential separation (ENC-ISS-009 Phase 2A).
# The MCP server subprocess uses this profile to assume the writer role, while the
# agent process itself runs under the scoped read-only dispatch session role.
MCP_WRITER_ROLE_ARN="${ENCELADUS_MCP_WRITER_ROLE_ARN:-arn:aws:iam::356364570033:role/enceladus-mcp-writer-role}"
MCP_WRITER_PROFILE="enceladus-mcp-writer"
MCP_WRITER_ENV=""
MCP_BASE_AWS_PROFILE_ENV=""

if [ -n "${ENCELADUS_MCP_WRITER_ROLE_ARN:-}" ] || [ "${ENCELADUS_ENABLE_CREDENTIAL_SEPARATION:-false}" = "true" ]; then
    echo "[INFO] Configuring MCP writer profile: ${MCP_WRITER_PROFILE}"
    aws configure set profile.${MCP_WRITER_PROFILE}.role_arn "${MCP_WRITER_ROLE_ARN}" 2>/dev/null || true
    aws configure set profile.${MCP_WRITER_PROFILE}.credential_source Ec2InstanceMetadata 2>/dev/null || true
    aws configure set profile.${MCP_WRITER_PROFILE}.region us-west-2 2>/dev/null || true

    # Verify the writer profile can assume the role
    if aws sts get-caller-identity --profile "${MCP_WRITER_PROFILE}" >/dev/null 2>&1; then
        echo "[SUCCESS] MCP writer profile configured and verified"
        MCP_WRITER_ENV="\"AWS_PROFILE\": \"${MCP_WRITER_PROFILE}\","
    else
        echo "[WARNING] MCP writer profile configured but role assumption failed — falling back to ambient credentials"
    fi
fi

if [ -z "${MCP_WRITER_ENV}" ] && [ -n "${RESOLVED_AWS_PROFILE}" ]; then
    MCP_BASE_AWS_PROFILE_ENV="\"AWS_PROFILE\": \"${RESOLVED_AWS_PROFILE}\","
fi

# Build the MCP server configuration JSON
MCP_CONFIG=$(cat <<EOCONFIG
{
  "mcpServers": {
    "enceladus": {
      "command": "python3",
      "args": ["${SERVER_PY}"],
      "env": {
        ${MCP_WRITER_ENV}
        ${MCP_BASE_AWS_PROFILE_ENV}
        "ENCELADUS_WORKSPACE_ROOT": "${WORKSPACE_ROOT}",
        "ENCELADUS_REGION": "us-west-2",
        "ENCELADUS_TRACKER_TABLE": "devops-project-tracker",
        "ENCELADUS_PROJECTS_TABLE": "projects",
        "ENCELADUS_DOCUMENTS_TABLE": "documents",
        "ENCELADUS_S3_BUCKET": "jreese-net",
        "ENCELADUS_S3_GOVERNANCE_PREFIX": "governance/live",
        "ENCELADUS_S3_GOVERNANCE_HISTORY_PREFIX": "governance/history"
      }
    }
  }
}
EOCONFIG
)

# Try to install into Claude Code settings
CLAUDE_SETTINGS_DIR="${HOME}/.claude"
CLAUDE_MCP_FILE="${CLAUDE_SETTINGS_DIR}/mcp.json"

if [ -d "${CLAUDE_SETTINGS_DIR}" ] || command -v claude >/dev/null 2>&1; then
    mkdir -p "${CLAUDE_SETTINGS_DIR}"

    if [ -f "${CLAUDE_MCP_FILE}" ]; then
        # Merge with existing config
        echo "[INFO] Merging into existing ${CLAUDE_MCP_FILE}"
        python3 -c "
import json, sys
existing = {}
try:
    with open('${CLAUDE_MCP_FILE}', 'r') as f:
        existing = json.load(f)
except (json.JSONDecodeError, FileNotFoundError):
    pass

new_config = json.loads('''${MCP_CONFIG}''')
existing.setdefault('mcpServers', {}).update(new_config.get('mcpServers', {}))

with open('${CLAUDE_MCP_FILE}', 'w') as f:
    json.dump(existing, f, indent=2)
print('[SUCCESS] Enceladus MCP profile merged into ${CLAUDE_MCP_FILE}')
"
    else
        echo "${MCP_CONFIG}" > "${CLAUDE_MCP_FILE}"
        echo "[SUCCESS] Enceladus MCP profile written to ${CLAUDE_MCP_FILE}"
    fi
else
    echo "[INFO] Claude Code settings directory not found. Outputting config for manual installation:"
    echo ""
    echo "${MCP_CONFIG}"
    echo ""
    echo "[INFO] Add the above to your MCP client's configuration file."
fi

echo "[DONE] Enceladus MCP profile installation complete"
