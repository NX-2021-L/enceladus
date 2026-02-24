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

# Build the MCP server configuration JSON
MCP_CONFIG=$(cat <<EOCONFIG
{
  "mcpServers": {
    "enceladus": {
      "command": "python3",
      "args": ["${SERVER_PY}"],
      "env": {
        "ENCELADUS_WORKSPACE_ROOT": "${WORKSPACE_ROOT}",
        "ENCELADUS_REGION": "us-west-2",
        "ENCELADUS_TRACKER_TABLE": "devops-project-tracker",
        "ENCELADUS_PROJECTS_TABLE": "projects",
        "ENCELADUS_DOCUMENTS_TABLE": "documents",
        "ENCELADUS_S3_BUCKET": "jreese-net"
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
