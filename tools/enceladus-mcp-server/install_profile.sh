#!/usr/bin/env bash
# install_profile.sh — Install the Enceladus remote HTTP MCP profile for provider sessions.
#
# Registers the Enceladus remote MCP gateway with Claude Code/Codex (or compatible
# MCP clients) so provider sessions can access governed Enceladus system resources
# through the Streamable HTTP endpoint — no local server.py subprocess needed.
#
# Usage:
#   ENCELADUS_COORDINATION_INTERNAL_API_KEY=<key> ./install_profile.sh
#   ENCELADUS_WORKSPACE_ROOT=/path ./install_profile.sh
#
# Related: DVP-TSK-245, DVP-FTR-023, ENC-TSK-511, ENC-TSK-862, ENC-TSK-864

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Workspace root auto-detection
WORKSPACE_ROOT="${ENCELADUS_WORKSPACE_ROOT:-$(cd "${SCRIPT_DIR}/../../.." && pwd)}"
MCP_PRIMARY_ALIAS="${ENCELADUS_MCP_PRIMARY_ALIAS:-enceladus}"
CLAUDE_SETTINGS_DIR="${ENCELADUS_MCP_CLAUDE_SETTINGS_DIR:-${HOME}/.claude}"
CODEX_SETTINGS_DIR="${ENCELADUS_MCP_CODEX_SETTINGS_DIR:-${HOME}/.codex}"

# Remote MCP gateway URL (ENC-TSK-862, ENC-TSK-864)
MCP_GATEWAY_URL="${ENCELADUS_MCP_GATEWAY_URL:-https://jreese.net/api/v1/coordination/mcp}"

# Python is needed for JSON/TOML config file manipulation only (not for MCP runtime).
PYTHON_BIN="${ENCELADUS_MCP_PYTHON_BIN:-$(command -v python3 || true)}"
if [ -z "${PYTHON_BIN}" ]; then
    echo "[ERROR] python3 not found in PATH (needed for config file manipulation)"
    exit 1
fi

echo "[INFO] Enceladus MCP profile installer (remote HTTP mode)"
echo "[INFO] Gateway: ${MCP_GATEWAY_URL}"
echo "[INFO] Workspace root: ${WORKSPACE_ROOT}"
echo "[INFO] Alias: ${MCP_PRIMARY_ALIAS}"

# ---------------------------------------------------------------------------
# Unified service-auth env resolution (ENC-FTR-028):
# Allow one coordination key to fan out across all API-specific key env vars.
# ---------------------------------------------------------------------------
BASE_INTERNAL_KEY="${ENCELADUS_COORDINATION_INTERNAL_API_KEY:-${ENCELADUS_COORDINATION_API_INTERNAL_API_KEY:-${COORDINATION_INTERNAL_API_KEY:-}}}"
if [ -n "${BASE_INTERNAL_KEY}" ]; then
    export ENCELADUS_COORDINATION_INTERNAL_API_KEY="${ENCELADUS_COORDINATION_INTERNAL_API_KEY:-${BASE_INTERNAL_KEY}}"
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

# Resolve the auth key for the remote gateway header.
RESOLVED_AUTH_KEY="${ENCELADUS_COORDINATION_INTERNAL_API_KEY:-${ENCELADUS_COORDINATION_API_INTERNAL_API_KEY:-${COORDINATION_INTERNAL_API_KEY:-}}}"

# ---------------------------------------------------------------------------
# Build remote HTTP MCP config JSON (ENC-TSK-862, ENC-TSK-864)
# ---------------------------------------------------------------------------
MCP_CONFIG=$(MCP_PRIMARY_ALIAS="${MCP_PRIMARY_ALIAS}" \
  MCP_GATEWAY_URL="${MCP_GATEWAY_URL}" \
  RESOLVED_AUTH_KEY="${RESOLVED_AUTH_KEY}" \
  "${PYTHON_BIN}" -c "
import json, os
alias = os.environ['MCP_PRIMARY_ALIAS']
url = os.environ['MCP_GATEWAY_URL']
auth_key = os.environ.get('RESOLVED_AUTH_KEY', '')
server = {'type': 'http', 'url': url}
if auth_key:
    server['headers'] = {'X-Coordination-Internal-Key': auth_key}
print(json.dumps({'mcpServers': {alias: server}}, indent=2))
")

# ---------------------------------------------------------------------------
# Install into Claude Code desktop settings (~/.claude/mcp.json)
# ---------------------------------------------------------------------------
CLAUDE_MCP_FILE="${CLAUDE_SETTINGS_DIR}/mcp.json"

if [ -d "${CLAUDE_SETTINGS_DIR}" ] || command -v claude >/dev/null 2>&1; then
    mkdir -p "${CLAUDE_SETTINGS_DIR}"

    if [ -f "${CLAUDE_MCP_FILE}" ]; then
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
# Register with Claude Code CLI (terminal) via direct ~/.claude.json update.
# The CLI uses ~/.claude.json (mcpServers key), NOT ~/.claude/mcp.json.
# ---------------------------------------------------------------------------
CLAUDE_CLI_CONFIG="${HOME}/.claude.json"
if [ -f "${CLAUDE_CLI_CONFIG}" ] || command -v claude >/dev/null 2>&1; then
    echo "[INFO] Updating Claude Code CLI config (${CLAUDE_CLI_CONFIG})..."
    "${PYTHON_BIN}" -c "
import json, os, sys

cli_path = os.path.expanduser('~/.claude.json')
existing = {}
try:
    with open(cli_path, 'r') as f:
        existing = json.load(f)
except (json.JSONDecodeError, FileNotFoundError):
    pass

new_config = json.loads('''${MCP_CONFIG}''')
existing.setdefault('mcpServers', {}).update(new_config.get('mcpServers', {}))

with open(cli_path, 'w') as f:
    json.dump(existing, f, indent=2)
    f.write('\n')
print(f'[SUCCESS] Enceladus MCP profile merged into {cli_path}')
"
else
    echo "[WARNING] Claude CLI config not found — skipping CLI registration."
fi

# ---------------------------------------------------------------------------
# Best-effort: upsert Codex MCP profile section for Codex sessions.
# ---------------------------------------------------------------------------
CODEX_CONFIG_FILE="${CODEX_SETTINGS_DIR}/config.toml"
mkdir -p "${CODEX_SETTINGS_DIR}"

if CODEX_CONFIG_FILE="${CODEX_CONFIG_FILE}" \
    MCP_PRIMARY_ALIAS="${MCP_PRIMARY_ALIAS}" \
    MCP_GATEWAY_URL="${MCP_GATEWAY_URL}" \
    RESOLVED_AUTH_KEY="${RESOLVED_AUTH_KEY}" \
    "${PYTHON_BIN}" - <<'PY'
import os
import pathlib
import re

import sys
cfg = pathlib.Path(os.environ["CODEX_CONFIG_FILE"])
text = cfg.read_text() if cfg.exists() else ""

if "mcp.jreese.net" in text:
    print("[WARNING] Existing codex config contains legacy URL (mcp.jreese.net) — overwriting with canonical URL.", file=sys.stderr)

# Remove prior managed blocks to avoid duplicate TOML keys.
text = re.sub(r"(?ms)^# BEGIN ENCELADUS CODEX STARTUP \(managed\)\n.*?# END ENCELADUS CODEX STARTUP \(managed\)\n?", "", text)
text = re.sub(r"(?ms)^# BEGIN ENCELADUS MCP PROFILE \(managed\)\n.*?# END ENCELADUS MCP PROFILE \(managed\)\n?", "", text)
alias = os.environ["MCP_PRIMARY_ALIAS"]
# Remove any prior stdio or HTTP server sections for this alias.
for section_suffix in ("", ".env", ".headers", ".http_headers"):
    text = re.sub(
        rf"(?ms)^\[mcp_servers\.{re.escape(alias)}{re.escape(section_suffix)}\]\n.*?(?=^\[|\Z)",
        "",
        text,
    )
# Also remove legacy enceladus-local sections.
for section_suffix in ("", ".env", ".headers"):
    text = re.sub(
        rf"(?ms)^\[mcp_servers\.enceladus-local{re.escape(section_suffix)}\]\n.*?(?=^\[|\Z)",
        "",
        text,
    )

def _ensure_setting(existing: str, key: str, value_literal: str) -> str:
    if re.search(rf"(?m)^{re.escape(key)}\s*=", existing):
        return existing
    existing = existing.rstrip()
    if existing:
        existing += "\n"
    return existing + f"{key} = {value_literal}\n"

text = _ensure_setting(text, "project_doc_max_bytes", "131072")
text = _ensure_setting(
    text,
    "project_doc_fallback_filenames",
    '["AGENTS.md", "agents.md", "AGENT.md", "README.agents.md"]',
)
text = _ensure_setting(
    text,
    "project_root_markers",
    '[".git", "AGENTS.md", "agents.md", "projects.yaml"]',
)

text = text.rstrip()
if text:
    text += "\n\n"

text += (
    "# BEGIN ENCELADUS CODEX STARTUP (managed)\n"
    "# Codex startup contract for Enceladus (remote HTTP MCP):\n"
    "# - Workspace AGENTS.md is loaded at session start via project_doc_fallback_filenames.\n"
    "# - During init, load governance://agents/bootstrap-template.md and governance://agents/lifecycle-primer.md.\n"
    "# - Use MCP checkout_task / advance_task_status for the CAI -> CCI lifecycle; put CCI-... in the PR body.\n"
    "# - Prefer non-interactive git flows and operate from the task worktree CWD, not the shared main checkout.\n"
    "# - For stdio-mode sessions (server.py direct): set ENCELADUS_MCP_INTERFACE_MODE=code to surface the governed 4-tool interface.\n"
    "# END ENCELADUS CODEX STARTUP (managed)\n\n"
)

def _toml_str(value: str) -> str:
    escaped = value.replace('\\', '\\\\').replace('"', '\\"')
    return f'"{escaped}"'

gateway_url = os.environ["MCP_GATEWAY_URL"]
auth_key = os.environ.get("RESOLVED_AUTH_KEY", "").strip()

lines = [
    f"[mcp_servers.{alias}]",
    f"type = {_toml_str('http')}",
    f"url = {_toml_str(gateway_url)}",
]
if auth_key:
    lines.append("")
    lines.append(f"[mcp_servers.{alias}.http_headers]")
    lines.append(f"X-Coordination-Internal-Key = {_toml_str(auth_key)}")

for tool in ("search", "coordination", "get_compact_context", "execute"):
    lines.append("")
    lines.append(f"[mcp_servers.{alias}.tools.{tool}]")
    lines.append(f"approval_mode = {_toml_str('approve')}")

server_block = "\n".join(lines)
managed = "# BEGIN ENCELADUS MCP PROFILE (managed)\n" + server_block + "\n# END ENCELADUS MCP PROFILE (managed)\n"
cfg.write_text(text + managed)
print(f"[SUCCESS] Enceladus MCP profile (HTTP) upserted in {cfg}")
PY
then
    :
else
    echo "[WARNING] Failed to update ${CODEX_CONFIG_FILE}; continuing"
fi

# ---------------------------------------------------------------------------
# Write global ~/.codex/AGENTS.md (Codex bootstrap) if missing or outdated.
# ---------------------------------------------------------------------------
CODEX_GLOBAL_AGENTS_MD="${CODEX_SETTINGS_DIR}/AGENTS.md"
if [ ! -f "${CODEX_GLOBAL_AGENTS_MD}" ] \
    || ! grep -q "bootstrap-template" "${CODEX_GLOBAL_AGENTS_MD}" 2>/dev/null \
    || ! grep -q "lifecycle-primer" "${CODEX_GLOBAL_AGENTS_MD}" 2>/dev/null \
    || ! grep -q "remote HTTP" "${CODEX_GLOBAL_AGENTS_MD}" 2>/dev/null \
    || grep -q "enceladus-local" "${CODEX_GLOBAL_AGENTS_MD}" 2>/dev/null; then
    cat > "${CODEX_GLOBAL_AGENTS_MD}" << 'GLOBAL_AGENTS_EOF'
# Codex Bootstrap

Managed MCP profile: remote HTTP
Remote URL: `https://jreese.net/api/v1/coordination/mcp`

MCP server `enceladus` is configured in `~/.codex/config.toml`.

Initialize by running (in order):
1. `mcp: connection_health` — verify connectivity, get governance hash
2. `mcp: governance_get("agents.md")` — load full governance rules
3. `mcp: governance_dictionary` — load compact enum/constraint index
4. `mcp: governance_get("agents/bootstrap-template.md")` — load session init protocol
5. `mcp: governance_get("agents/lifecycle-primer.md")` — load the git lifecycle primer

Follow all instructions in `agents.md` and `agents/lifecycle-primer.md` before proceeding with any work.

## Git Lifecycle Quick Reference

- Set `task.components` and `task.transition_type` before `checkout_task`.
- `checkout_task` is required before any code changes; work only inside the task worktree.
- `advance_task_status("coding-complete")` returns `CAI-...`; `advance_task_status("committed", {"commit_sha": ...})` returns `CCI-...`.
- The PR body must include the `CCI-...` token before `PR Commit Gate` will pass.
- Run `git` / `gh` from the task worktree CWD, not the shared main checkout.
- Branch protection is strict: merge or rebase `origin/main` into the task branch before attempting to merge.
- GitHub Actions re-runs can observe stale PR-body payloads; if the CCI or body changed, push or update the PR before assuming the gate saw it.
- See `governance://agents/lifecycle-primer.md` for the full gate matrix, component strictness rules, and evidence requirements.
GLOBAL_AGENTS_EOF
    echo "[SUCCESS] Global Codex AGENTS.md written to ${CODEX_GLOBAL_AGENTS_MD}"
else
    echo "[INFO] Global Codex AGENTS.md already present at ${CODEX_GLOBAL_AGENTS_MD}"
fi

# ---------------------------------------------------------------------------
# Write workspace AGENTS.md (Codex bootstrap) if missing or outdated.
# ---------------------------------------------------------------------------
WORKSPACE_AGENTS_MD="${WORKSPACE_ROOT}/AGENTS.md"
if [ ! -f "${WORKSPACE_AGENTS_MD}" ] \
    || ! grep -q "bootstrap-template" "${WORKSPACE_AGENTS_MD}" 2>/dev/null \
    || ! grep -q "lifecycle-primer" "${WORKSPACE_AGENTS_MD}" 2>/dev/null \
    || ! grep -q "remote HTTP" "${WORKSPACE_AGENTS_MD}" 2>/dev/null \
    || grep -q "enceladus-local" "${WORKSPACE_AGENTS_MD}" 2>/dev/null; then
    cat > "${WORKSPACE_AGENTS_MD}" << 'AGENTS_EOF'
# Enceladus Workspace — Agent Bootstrap

Managed MCP profile: remote HTTP
Remote URL: `https://jreese.net/api/v1/coordination/mcp`

MCP server `enceladus` is configured via remote HTTP gateway.
Source: `tools/enceladus-mcp-server/server.py` (deployed as Lambda)

## Initialization (REQUIRED — run in order every session)

1. `mcp: connection_health` — verify DynamoDB/S3/API connectivity, get governance hash
2. `mcp: governance_get("agents.md")` — **load full governance rules and execute all steps**
3. `mcp: governance_dictionary` — load compact enum/constraint index
4. `mcp: governance_get("agents/bootstrap-template.md")` — load session init protocol
5. `mcp: governance_get("agents/lifecycle-primer.md")` — load lifecycle gates before any PR work
6. `mcp: tracker_list(project_id="enceladus", record_type="task", status="open")` — open tasks
7. `mcp: tracker_pending_updates(project_id="enceladus")` — pending updates

All operating rules, tool reference, and task policies are in `governance://agents.md`.
Do not proceed with any work until steps 1-5 are complete.

## Git Lifecycle Quick Reference

- Set `task.components` and `task.transition_type` before `checkout_task`.
- `checkout_task` is required before code changes; never edit from the shared main checkout.
- `coding-complete` returns `CAI-...`; `committed` requires `commit_sha` and returns `CCI-...`.
- Put the `CCI-...` token in the PR body before opening or updating the PR.
- Run `git` / `gh` from the task worktree CWD so branch, PR, and status commands target the right repo state.
- If GitHub says the branch is behind, merge or rebase `origin/main` in the worktree before merging.
- Re-running PR workflows after only editing the PR body can use stale payloads; push or update the PR body before assuming the CCI gate saw the change.
- Read `governance://agents/lifecycle-primer.md` for the full lifecycle arc, strictness rank table, and evidence schema.

## Pre-Code Protocol (every task pickup)

Before modifying any files for a task:
1. Sync main: `git -C <repo> fetch origin && git -C <repo> merge --ff-only origin/main`
2. Create task-scoped worktree: `bash tools/agent-worktree-init.sh <TRACKER-ID>-<slug>`
   - Creates branch `agent/<TRACKER-ID>-<slug>` automatically
3. Query component registry: `mcp: get_code_map(project_id, domain?)` for file paths
4. Check out task: `mcp: checkout_task(record_id, active_agent_session_id, governance_hash)`
5. Work only inside the printed worktree path — never modify files in the main checkout.

Always assume other agent sessions are running concurrently on this machine.
See `governance://agents.md` section 3.10 for full multi-agent safety rules.
AGENTS_EOF
    echo "[SUCCESS] Workspace AGENTS.md written to ${WORKSPACE_AGENTS_MD}"
else
    echo "[INFO] Workspace AGENTS.md already present at ${WORKSPACE_AGENTS_MD}"
fi

# ---------------------------------------------------------------------------
# Write global ~/.claude/CLAUDE.md quick reference for Claude Code sessions.
# ---------------------------------------------------------------------------
mkdir -p "${CLAUDE_SETTINGS_DIR}"
CLAUDE_GLOBAL_MD="${CLAUDE_SETTINGS_DIR}/CLAUDE.md"
if [ ! -f "${CLAUDE_GLOBAL_MD}" ] \
    || ! grep -q "ENCELADUS_GIT_LIFECYCLE_QUICK_REFERENCE" "${CLAUDE_GLOBAL_MD}" 2>/dev/null \
    || ! grep -q "lifecycle-primer" "${CLAUDE_GLOBAL_MD}" 2>/dev/null \
    || ! grep -q "remote HTTP" "${CLAUDE_GLOBAL_MD}" 2>/dev/null; then
    cat > "${CLAUDE_GLOBAL_MD}" << 'CLAUDE_EOF'
# Enceladus Claude Bootstrap

Source: `governance://agents/bootstrap-template.md`
Managed MCP profile: remote HTTP
Remote URL: `https://jreese.net/api/v1/coordination/mcp`

## Session Init

1. `connection_health()`
2. `governance_get("agents.md")`
3. `governance_dictionary()`
4. `governance_get("agents/bootstrap-template.md")`
5. `governance_get("agents/lifecycle-primer.md")`

## Git Lifecycle Quick Reference

<!-- ENCELADUS_GIT_LIFECYCLE_QUICK_REFERENCE -->

| Rule | Why |
| --- | --- |
| Set `components` + `transition_type` before `checkout_task` | Checkout enforcement and strictness matching happen before code work starts |
| `coding-complete` returns `CAI`; `committed` with `commit_sha` returns `CCI` | The checkout service gates commit and PR progression |
| Put `CCI-...` in the PR body | `PR Commit Gate` rejects PRs without it |
| Run `git` / `gh` from the task worktree CWD | Avoid wrong-repo commands and shared-checkout mutations |
| Merge or rebase `origin/main` before merge | Strict branch protection blocks stale branches |
| Re-run with care after PR body edits | GitHub workflow payloads can lag body-only updates |

See `governance://agents/lifecycle-primer.md` for the full lifecycle arc, evidence schema, and component strictness ranking.
CLAUDE_EOF
    echo "[SUCCESS] Global Claude bootstrap written to ${CLAUDE_GLOBAL_MD}"
else
    echo "[INFO] Global Claude bootstrap already present at ${CLAUDE_GLOBAL_MD}"
fi

# ---------------------------------------------------------------------------
# Remote HTTP smoke test (replaces old stdio smoke test).
# Probes the gateway with a simple tracker_list MCP call via curl.
# ---------------------------------------------------------------------------
if [ "${ENCELADUS_SKIP_MCP_SMOKE_TEST:-false}" != "true" ]; then
    echo "[INFO] Running remote MCP smoke test against ${MCP_GATEWAY_URL}"
    _SMOKE_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
        -H "Content-Type: application/json" \
        -H "Accept: application/json, text/event-stream" \
        -H "X-Coordination-Internal-Key: ${RESOLVED_AUTH_KEY}" \
        -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
        "${MCP_GATEWAY_URL}" 2>/dev/null) || true
    _SMOKE_HTTP_CODE=$(echo "${_SMOKE_RESPONSE}" | tail -1)
    _SMOKE_BODY=$(echo "${_SMOKE_RESPONSE}" | sed '$d')

    if [ "${_SMOKE_HTTP_CODE}" = "200" ]; then
        # Count tools in response to verify surface
        _TOOL_COUNT=$("${PYTHON_BIN}" -c "
import json, sys
try:
    body = '''${_SMOKE_BODY}'''
    obj = json.loads(body)
    tools = obj.get('result', {}).get('tools', [])
    names = [t.get('name','') for t in tools]
    code_mode = [n for n in names if n in ('search','coordination','get_compact_context','execute')]
    print(f'{len(tools)} tools ({len(code_mode)} code-mode)')
except Exception as e:
    print(f'parse-error: {e}')
" 2>/dev/null) || _TOOL_COUNT="unknown"
        echo "[SUCCESS] Remote MCP smoke test passed (HTTP 200, ${_TOOL_COUNT})"
    elif [ "${_SMOKE_HTTP_CODE}" = "401" ]; then
        echo "[ERROR] Remote MCP smoke test failed — HTTP 401 Unauthorized."
        echo "[ERROR] API key may be incorrect. Check ENCELADUS_COORDINATION_INTERNAL_API_KEY."
        exit 1
    else
        echo "[WARNING] Remote MCP smoke test returned HTTP ${_SMOKE_HTTP_CODE} — gateway may use SSE streaming."
        echo "[WARNING] Profile installed; verify connectivity with connection_health() in a session."
    fi
fi

echo "[DONE] Enceladus MCP profile installation complete (remote HTTP)"
