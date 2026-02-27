#!/usr/bin/env bash
# install_profile.sh — Install the Enceladus MCP server profile for provider sessions.
#
# Registers the Enceladus MCP server with Claude Code/Codex (or compatible MCP clients)
# so provider sessions can access governed Enceladus system resources.
#
# Usage:
#   ./install_profile.sh
#   ENCELADUS_WORKSPACE_ROOT=/path ./install_profile.sh
#
# Related: DVP-TSK-245, DVP-FTR-023, ENC-TSK-511

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_PY="${SCRIPT_DIR}/server.py"

# Workspace root auto-detection
WORKSPACE_ROOT="${ENCELADUS_WORKSPACE_ROOT:-$(cd "${SCRIPT_DIR}/../../.." && pwd)}"
MCP_PRIMARY_ALIAS="${ENCELADUS_MCP_PRIMARY_ALIAS:-enceladus}"
MCP_SECONDARY_ALIAS="${ENCELADUS_MCP_SECONDARY_ALIAS:-enceladus-local}"
MCP_INCLUDE_SECONDARY_ALIAS="${ENCELADUS_MCP_INCLUDE_SECONDARY_ALIAS:-true}"
CLAUDE_SETTINGS_DIR="${ENCELADUS_MCP_CLAUDE_SETTINGS_DIR:-${HOME}/.claude}"
CODEX_SETTINGS_DIR="${ENCELADUS_MCP_CODEX_SETTINGS_DIR:-${HOME}/.codex}"

# Resolve a stable Python interpreter for MCP runtime.
PYTHON_BIN="${ENCELADUS_MCP_PYTHON_BIN:-$(command -v python3 || true)}"
if [ -z "${PYTHON_BIN}" ]; then
    echo "[ERROR] python3 not found in PATH"
    exit 1
fi

PYTHON_USER_SITE="$("${PYTHON_BIN}" - <<'PY'
import site
print(site.getusersitepackages())
PY
)"
MCP_PYTHONPATH="${PYTHON_USER_SITE}"
if [ -n "${PYTHONPATH:-}" ]; then
    MCP_PYTHONPATH="${MCP_PYTHONPATH}:${PYTHONPATH}"
fi

echo "[INFO] Enceladus MCP profile installer"
echo "[INFO] Server: ${SERVER_PY}"
echo "[INFO] Workspace root: ${WORKSPACE_ROOT}"
echo "[INFO] Python: ${PYTHON_BIN}"
echo "[INFO] Primary alias: ${MCP_PRIMARY_ALIAS}"
echo "[INFO] Secondary alias: ${MCP_SECONDARY_ALIAS} (enabled=${MCP_INCLUDE_SECONDARY_ALIAS})"

# Verify server.py exists
if [ ! -f "${SERVER_PY}" ]; then
    echo "[ERROR] server.py not found at ${SERVER_PY}"
    exit 1
fi

# Verify Python + dependencies
if ! "${PYTHON_BIN}" -c "import mcp, boto3" >/dev/null 2>&1; then
    echo "[INFO] Installing required Python packages..."
    "${PYTHON_BIN}" -m pip install --user --quiet mcp boto3 PyYAML 2>/dev/null || {
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
    for candidate in enceladus-agent personal default ec2-role; do
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
MCP_WRITER_ACTIVE="false"

if [ -n "${ENCELADUS_MCP_WRITER_ROLE_ARN:-}" ] || [ "${ENCELADUS_ENABLE_CREDENTIAL_SEPARATION:-false}" = "true" ]; then
    echo "[INFO] Configuring MCP writer profile: ${MCP_WRITER_PROFILE}"
    aws configure set profile.${MCP_WRITER_PROFILE}.role_arn "${MCP_WRITER_ROLE_ARN}" 2>/dev/null || true
    aws configure set profile.${MCP_WRITER_PROFILE}.credential_source Ec2InstanceMetadata 2>/dev/null || true
    aws configure set profile.${MCP_WRITER_PROFILE}.region us-west-2 2>/dev/null || true

    # Verify the writer profile can assume the role
    if aws sts get-caller-identity --profile "${MCP_WRITER_PROFILE}" >/dev/null 2>&1; then
        echo "[SUCCESS] MCP writer profile configured and verified"
        MCP_WRITER_ACTIVE="true"
    else
        echo "[WARNING] MCP writer profile configured but role assumption failed — falling back to ambient credentials"
    fi
fi

MCP_RUNTIME_AWS_PROFILE=""
if [ "${MCP_WRITER_ACTIVE}" = "true" ]; then
    MCP_RUNTIME_AWS_PROFILE="${MCP_WRITER_PROFILE}"
elif [ -n "${RESOLVED_AWS_PROFILE}" ]; then
    MCP_RUNTIME_AWS_PROFILE="${RESOLVED_AWS_PROFILE}"
fi

# Unified service-auth env resolution (ENC-FTR-028):
# Allow one coordination key to fan out across all API-specific key env vars.
BASE_INTERNAL_KEY="${ENCELADUS_COORDINATION_INTERNAL_API_KEY:-${ENCELADUS_COORDINATION_API_INTERNAL_API_KEY:-${COORDINATION_INTERNAL_API_KEY:-}}}"
if [ -n "${BASE_INTERNAL_KEY}" ]; then
    export ENCELADUS_COORDINATION_INTERNAL_API_KEY="${ENCELADUS_COORDINATION_INTERNAL_API_KEY:-${BASE_INTERNAL_KEY}}"
    export ENCELADUS_COORDINATION_API_INTERNAL_API_KEY="${ENCELADUS_COORDINATION_API_INTERNAL_API_KEY:-${BASE_INTERNAL_KEY}}"
    export ENCELADUS_DOCUMENT_API_INTERNAL_API_KEY="${ENCELADUS_DOCUMENT_API_INTERNAL_API_KEY:-${BASE_INTERNAL_KEY}}"
    export ENCELADUS_DEPLOY_API_INTERNAL_API_KEY="${ENCELADUS_DEPLOY_API_INTERNAL_API_KEY:-${BASE_INTERNAL_KEY}}"
    export ENCELADUS_TRACKER_API_INTERNAL_API_KEY="${ENCELADUS_TRACKER_API_INTERNAL_API_KEY:-${BASE_INTERNAL_KEY}}"
    export ENCELADUS_GOVERNANCE_API_INTERNAL_API_KEY="${ENCELADUS_GOVERNANCE_API_INTERNAL_API_KEY:-${BASE_INTERNAL_KEY}}"
    export ENCELADUS_PROJECTS_API_INTERNAL_API_KEY="${ENCELADUS_PROJECTS_API_INTERNAL_API_KEY:-${BASE_INTERNAL_KEY}}"
    export COORDINATION_INTERNAL_API_KEY="${COORDINATION_INTERNAL_API_KEY:-${BASE_INTERNAL_KEY}}"
fi

if [ "${ENCELADUS_ALLOW_KEYLESS_PROFILE:-false}" != "true" ]; then
    if [ -z "${ENCELADUS_COORDINATION_INTERNAL_API_KEY:-}" ] \
        && [ -z "${ENCELADUS_COORDINATION_API_INTERNAL_API_KEY:-}" ] \
        && [ -z "${COORDINATION_INTERNAL_API_KEY:-}" ]; then
        echo "[ERROR] No internal service auth key found in environment."
        echo "[ERROR] Set ENCELADUS_COORDINATION_INTERNAL_API_KEY (or COORDINATION_INTERNAL_API_KEY) before install."
        echo "[ERROR] To bypass for diagnostic-only installs, set ENCELADUS_ALLOW_KEYLESS_PROFILE=true."
        exit 1
    fi
fi

# Build the MCP server configuration JSON
MCP_CONFIG=$(PYTHON_BIN="${PYTHON_BIN}" \
    SERVER_PY="${SERVER_PY}" \
    MCP_PYTHONPATH="${MCP_PYTHONPATH}" \
    WORKSPACE_ROOT="${WORKSPACE_ROOT}" \
    MCP_RUNTIME_AWS_PROFILE="${MCP_RUNTIME_AWS_PROFILE}" \
    MCP_PRIMARY_ALIAS="${MCP_PRIMARY_ALIAS}" \
    MCP_SECONDARY_ALIAS="${MCP_SECONDARY_ALIAS}" \
    MCP_INCLUDE_SECONDARY_ALIAS="${MCP_INCLUDE_SECONDARY_ALIAS}" \
    "${PYTHON_BIN}" - <<'PY'
import json
import os


def to_bool(value: str) -> bool:
    return value.strip().lower() not in {"", "0", "false", "no", "off"}


env_block = {
    "PYTHONUNBUFFERED": "1",
    "PYTHONPATH": os.environ["MCP_PYTHONPATH"],
    "ENCELADUS_WORKSPACE_ROOT": os.environ["WORKSPACE_ROOT"],
    "ENCELADUS_REGION": "us-west-2",
    "ENCELADUS_TRACKER_TABLE": "devops-project-tracker",
    "ENCELADUS_PROJECTS_TABLE": "projects",
    "ENCELADUS_DOCUMENTS_TABLE": "documents",
    "ENCELADUS_S3_BUCKET": "jreese-net",
    "ENCELADUS_S3_GOVERNANCE_PREFIX": "governance/live",
    "ENCELADUS_S3_GOVERNANCE_HISTORY_PREFIX": "governance/history",
    # HTTP API base URLs (Phase 2d migration — MCP routes through HTTP APIs)
    "ENCELADUS_TRACKER_API_BASE": "https://jreese.net/api/v1/tracker",
    "ENCELADUS_GOVERNANCE_API_BASE": "https://jreese.net/api/v1/governance",
    "ENCELADUS_PROJECTS_API_BASE": "https://jreese.net/api/v1/coordination/projects",
    "ENCELADUS_HEALTH_API_URL": "https://jreese.net/api/v1/health",
}
for key in (
    "COORDINATION_INTERNAL_API_KEY",
    "COORDINATION_INTERNAL_API_KEY_PREVIOUS",
    "COORDINATION_INTERNAL_API_KEYS",
    "ENCELADUS_COORDINATION_INTERNAL_API_KEY",
    "ENCELADUS_COORDINATION_API_INTERNAL_API_KEY",
    "ENCELADUS_COORDINATION_API_INTERNAL_API_KEYS",
    "ENCELADUS_DOCUMENT_API_INTERNAL_API_KEY",
    "ENCELADUS_DEPLOY_API_INTERNAL_API_KEY",
    "ENCELADUS_TRACKER_API_INTERNAL_API_KEY",
    "ENCELADUS_GOVERNANCE_API_INTERNAL_API_KEY",
    "ENCELADUS_PROJECTS_API_INTERNAL_API_KEY",
):
    value = os.environ.get(key, "").strip()
    if value:
        env_block[key] = value

import sys as _sys
api_key_configured = any("API_KEY" in k for k in env_block)
if not api_key_configured:
    print("[WARNING] No ENCELADUS_*_INTERNAL_API_KEY env vars set. MCP profile will have NO auth keys.", file=_sys.stderr)
    print("[WARNING] Tracker/document/deploy writes will return PERMISSION_DENIED until keys are configured.", file=_sys.stderr)
    print("[WARNING] Set ENCELADUS_COORDINATION_INTERNAL_API_KEY before running install_profile.sh.", file=_sys.stderr)

aws_profile = os.environ.get("MCP_RUNTIME_AWS_PROFILE", "").strip()
if aws_profile:
    env_block["AWS_PROFILE"] = aws_profile

command = os.environ["PYTHON_BIN"]
server_py = os.environ["SERVER_PY"]
servers = {
    os.environ["MCP_PRIMARY_ALIAS"]: {
        "command": command,
        "args": [server_py],
        "env": env_block,
    }
}

secondary_alias = os.environ.get("MCP_SECONDARY_ALIAS", "").strip()
include_secondary = to_bool(os.environ.get("MCP_INCLUDE_SECONDARY_ALIAS", "true"))
if include_secondary and secondary_alias and secondary_alias not in servers:
    servers[secondary_alias] = {
        "command": command,
        "args": [server_py],
        "env": env_block,
    }

print(json.dumps({"mcpServers": servers}, indent=2))
PY
)

# Try to install into Claude Code settings
CLAUDE_MCP_FILE="${CLAUDE_SETTINGS_DIR}/mcp.json"

if [ -d "${CLAUDE_SETTINGS_DIR}" ] || command -v claude >/dev/null 2>&1; then
    mkdir -p "${CLAUDE_SETTINGS_DIR}"

    if [ -f "${CLAUDE_MCP_FILE}" ]; then
        # Merge with existing config
        echo "[INFO] Merging into existing ${CLAUDE_MCP_FILE}"
        "${PYTHON_BIN}" -c "
import json
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

# ---------------------------------------------------------------------------
# Register with Claude Code CLI (terminal) via `claude mcp add --scope user`.
# The CLI uses ~/.claude.json (mcpServers key), NOT ~/.claude/mcp.json.
# This step is separate from the desktop/project mcp.json written above.
# ---------------------------------------------------------------------------
if command -v claude >/dev/null 2>&1; then
    echo "[INFO] Registering with Claude Code CLI (user scope -> ~/.claude.json)..."

    # Build -e KEY=VALUE args by parsing the already-computed MCP_CONFIG via stdin.
    # mapfile ensures values containing '=' or spaces are handled correctly.
    mapfile -t _MCP_ENV_ARGS < <(
        echo "${MCP_CONFIG}" | "${PYTHON_BIN}" -c "
import json, sys
config = json.load(sys.stdin)
servers = config.get('mcpServers', {})
if servers:
    env = next(iter(servers.values())).get('env', {})
    for k, v in env.items():
        print('-e')
        print(f'{k}={v}')
"
    )

    # Remove any existing entry first (idempotent), then re-add.
    claude mcp remove "${MCP_PRIMARY_ALIAS}" --scope user 2>/dev/null || true

    # shellcheck disable=SC2068
    if claude mcp add \
        --scope user \
        "${_MCP_ENV_ARGS[@]}" \
        "${MCP_PRIMARY_ALIAS}" \
        "${PYTHON_BIN}" \
        "${SERVER_PY}" 2>&1; then
        echo "[SUCCESS] Registered '${MCP_PRIMARY_ALIAS}' with Claude Code CLI (user scope)"
    else
        echo "[WARNING] claude mcp add failed — manual CLI registration may be needed."
        echo "[WARNING] Run: claude mcp add --scope user -e KEY=VAL ... ${MCP_PRIMARY_ALIAS} ${PYTHON_BIN} ${SERVER_PY}"
    fi
else
    echo "[WARNING] 'claude' CLI not found — skipping Claude Code CLI registration."
    echo "[WARNING] After installing Claude Code CLI, run: install_profile.sh to register."
fi

# Best-effort: upsert Codex MCP profile section for desktop sessions.
CODEX_CONFIG_FILE="${CODEX_SETTINGS_DIR}/config.toml"
mkdir -p "${CODEX_SETTINGS_DIR}"

if CODEX_CONFIG_FILE="${CODEX_CONFIG_FILE}" \
    PYTHON_BIN="${PYTHON_BIN}" \
    SERVER_PY="${SERVER_PY}" \
    MCP_PYTHONPATH="${MCP_PYTHONPATH}" \
    WORKSPACE_ROOT="${WORKSPACE_ROOT}" \
    MCP_RUNTIME_AWS_PROFILE="${MCP_RUNTIME_AWS_PROFILE}" \
    MCP_PRIMARY_ALIAS="${MCP_PRIMARY_ALIAS}" \
    MCP_SECONDARY_ALIAS="${MCP_SECONDARY_ALIAS}" \
    MCP_INCLUDE_SECONDARY_ALIAS="${MCP_INCLUDE_SECONDARY_ALIAS}" \
    "${PYTHON_BIN}" - <<'PY'
import os
import pathlib
import re

cfg = pathlib.Path(os.environ["CODEX_CONFIG_FILE"])
text = cfg.read_text() if cfg.exists() else ""

# Remove prior managed block and direct server sections to avoid duplicate TOML keys.
text = re.sub(r"(?ms)^# BEGIN ENCELADUS MCP PROFILE \(managed\)\n.*?# END ENCELADUS MCP PROFILE \(managed\)\n?", "", text)
aliases = [os.environ["MCP_PRIMARY_ALIAS"]]
secondary = os.environ.get("MCP_SECONDARY_ALIAS", "").strip()
if secondary and os.environ.get("MCP_INCLUDE_SECONDARY_ALIAS", "true").strip().lower() not in {"", "0", "false", "no", "off"}:
    aliases.append(secondary)
for section in aliases:
    text = re.sub(
        rf"(?ms)^\[mcp_servers\.{re.escape(section)}\]\n.*?(?=^\[|\Z)",
        "",
        text,
    )
    text = re.sub(
        rf"(?ms)^\[mcp_servers\.{re.escape(section)}\.env\]\n.*?(?=^\[|\Z)",
        "",
        text,
    )

text = text.rstrip()
if text:
    text += "\n\n"

py_bin = os.environ["PYTHON_BIN"]
server_py = os.environ["SERVER_PY"]
env_items = {
    "PYTHONUNBUFFERED": "1",
    "PYTHONPATH": os.environ["MCP_PYTHONPATH"],
    "ENCELADUS_WORKSPACE_ROOT": os.environ["WORKSPACE_ROOT"],
    "ENCELADUS_REGION": "us-west-2",
    "ENCELADUS_TRACKER_TABLE": "devops-project-tracker",
    "ENCELADUS_PROJECTS_TABLE": "projects",
    "ENCELADUS_DOCUMENTS_TABLE": "documents",
    "ENCELADUS_S3_BUCKET": "jreese-net",
    # HTTP API base URLs (Phase 2d migration)
    "ENCELADUS_TRACKER_API_BASE": "https://jreese.net/api/v1/tracker",
    "ENCELADUS_GOVERNANCE_API_BASE": "https://jreese.net/api/v1/governance",
    "ENCELADUS_PROJECTS_API_BASE": "https://jreese.net/api/v1/coordination/projects",
    "ENCELADUS_HEALTH_API_URL": "https://jreese.net/api/v1/health",
}
for key in (
    "COORDINATION_INTERNAL_API_KEY",
    "COORDINATION_INTERNAL_API_KEY_PREVIOUS",
    "COORDINATION_INTERNAL_API_KEYS",
    "ENCELADUS_COORDINATION_INTERNAL_API_KEY",
    "ENCELADUS_COORDINATION_API_INTERNAL_API_KEY",
    "ENCELADUS_COORDINATION_API_INTERNAL_API_KEYS",
    "ENCELADUS_DOCUMENT_API_INTERNAL_API_KEY",
    "ENCELADUS_DEPLOY_API_INTERNAL_API_KEY",
    "ENCELADUS_TRACKER_API_INTERNAL_API_KEY",
    "ENCELADUS_GOVERNANCE_API_INTERNAL_API_KEY",
    "ENCELADUS_PROJECTS_API_INTERNAL_API_KEY",
):
    value = os.environ.get(key, "").strip()
    if value:
        env_items[key] = value
aws_profile = os.environ.get("MCP_RUNTIME_AWS_PROFILE", "").strip()
if aws_profile:
    env_items["AWS_PROFILE"] = aws_profile


def _toml_str(value: str) -> str:
    escaped = value.replace('\\', '\\\\').replace('"', '\\"')
    return f'"{escaped}"'


def _server_block(name: str) -> str:
    lines = [
        f"[mcp_servers.{name}]",
        f"command = {_toml_str(py_bin)}",
        f"args = [{_toml_str(server_py)}]",
        "",
        f"[mcp_servers.{name}.env]",
    ]
    for k, v in sorted(env_items.items()):
        lines.append(f"{k} = {_toml_str(v)}")
    return "\n".join(lines)

server_blocks = [_server_block(aliases[0])]
for alias in aliases[1:]:
    if alias != aliases[0]:
        server_blocks.append(_server_block(alias))

managed = "# BEGIN ENCELADUS MCP PROFILE (managed)\n" + "\n\n".join(server_blocks) + "\n# END ENCELADUS MCP PROFILE (managed)\n"
cfg.write_text(text + managed)
print(f"[SUCCESS] Enceladus MCP profile upserted in {cfg}")
PY
then
    :
else
    echo "[WARNING] Failed to update ${CODEX_CONFIG_FILE}; continuing"
fi

# Optional stdio smoke test so install failures surface immediately.
if [ "${ENCELADUS_SKIP_MCP_SMOKE_TEST:-false}" != "true" ]; then
    echo "[INFO] Running MCP stdio smoke test"
    if ! PYTHON_BIN="${PYTHON_BIN}" \
        SERVER_PY="${SERVER_PY}" \
        WORKSPACE_ROOT="${WORKSPACE_ROOT}" \
        MCP_RUNTIME_AWS_PROFILE="${MCP_RUNTIME_AWS_PROFILE}" \
        "${PYTHON_BIN}" - <<'PY'
import os
import anyio
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


async def main() -> None:
    server_env = {
        "ENCELADUS_WORKSPACE_ROOT": os.environ["WORKSPACE_ROOT"],
        "ENCELADUS_REGION": "us-west-2",
        "ENCELADUS_TRACKER_TABLE": "devops-project-tracker",
        "ENCELADUS_PROJECTS_TABLE": "projects",
        "ENCELADUS_DOCUMENTS_TABLE": "documents",
        "ENCELADUS_S3_BUCKET": "jreese-net",
        "ENCELADUS_S3_GOVERNANCE_PREFIX": "governance/live",
        "ENCELADUS_S3_GOVERNANCE_HISTORY_PREFIX": "governance/history",
        # HTTP API base URLs (Phase 2d migration)
        "ENCELADUS_TRACKER_API_BASE": "https://jreese.net/api/v1/tracker",
        "ENCELADUS_GOVERNANCE_API_BASE": "https://jreese.net/api/v1/governance",
        "ENCELADUS_PROJECTS_API_BASE": "https://jreese.net/api/v1/coordination/projects",
        "ENCELADUS_HEALTH_API_URL": "https://jreese.net/api/v1/health",
    }
    for key in (
        "COORDINATION_INTERNAL_API_KEY",
        "COORDINATION_INTERNAL_API_KEY_PREVIOUS",
        "COORDINATION_INTERNAL_API_KEYS",
        "ENCELADUS_COORDINATION_INTERNAL_API_KEY",
        "ENCELADUS_COORDINATION_API_INTERNAL_API_KEY",
        "ENCELADUS_COORDINATION_API_INTERNAL_API_KEYS",
        "ENCELADUS_DOCUMENT_API_INTERNAL_API_KEY",
        "ENCELADUS_DEPLOY_API_INTERNAL_API_KEY",
        "ENCELADUS_TRACKER_API_INTERNAL_API_KEY",
        "ENCELADUS_GOVERNANCE_API_INTERNAL_API_KEY",
        "ENCELADUS_PROJECTS_API_INTERNAL_API_KEY",
    ):
        value = os.environ.get(key, "").strip()
        if value:
            server_env[key] = value
    aws_profile = os.environ.get("MCP_RUNTIME_AWS_PROFILE", "").strip()
    if aws_profile:
        server_env["AWS_PROFILE"] = aws_profile

    params = StdioServerParameters(
        command=os.environ["PYTHON_BIN"],
        args=[os.environ["SERVER_PY"]],
        env=server_env,
    )

    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            await session.call_tool("connection_health", {})
            await session.call_tool("governance_hash", {})

            # Authenticated API probe — validates that API keys are present and accepted.
            # connection_health + governance_hash both use direct DynamoDB/S3 and pass even
            # with no keys configured. tracker_list requires the HTTP API auth key.
            result = await session.call_tool("tracker_list", {"project_id": "enceladus", "record_type": "task", "status": "open"})
            result_text = result.content[0].text if result.content else ""
            import json as _json
            try:
                result_obj = _json.loads(result_text)
                if isinstance(result_obj, dict) and result_obj.get("error") in ("PERMISSION_DENIED", "Authentication required"):
                    import sys
                    print(f"[ERROR] Authenticated API probe failed — PERMISSION_DENIED. API key may be missing or incorrect in MCP profile.", file=sys.stderr)
                    print(f"[ERROR] Set ENCELADUS_COORDINATION_INTERNAL_API_KEY and re-run install_profile.sh.", file=sys.stderr)
                    sys.exit(1)
            except Exception:
                pass  # Non-JSON or unexpected format — don't block on parse failures
            print("[SUCCESS] Authenticated API probe passed (tracker_list)")


anyio.run(main)
print("[SUCCESS] MCP stdio smoke test passed")
PY
    then
        echo "[ERROR] MCP stdio smoke test failed"
        exit 1
    fi
fi

echo "[DONE] Enceladus MCP profile installation complete"
