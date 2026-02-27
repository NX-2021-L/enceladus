# New Machine Setup (Native Desktop UI, MCP-Only)

## Goal

Prepare a machine so native desktop UI sessions can start with Enceladus MCP and initialize through `governance://agents.md`.

## Minimum Prerequisites

- Python 3.11+
- AWS credentials with access to Enceladus resources
- Full Enceladus repo checkout (briefing wrappers resolve canonical MCP source in-repo)

## Setup Steps

1. From the repository root, verify canonical MCP assets:

```bash
ls -la tools/enceladus-mcp-server/server.py \
       tools/enceladus-mcp-server/install_profile.sh \
       tools/enceladus-mcp-server/dispatch_plan_generator.py
```

2. Install required Python packages (if missing):

```bash
python3 -m pip install --user mcp boto3 PyYAML
```

3. Verify AWS credential context is available to MCP runtime:

```bash
aws sts get-caller-identity
```

If this fails, export a usable profile before installing MCP:

```bash
export AWS_PROFILE=personal
aws sts get-caller-identity
```

3b. Export Enceladus service auth key (required for tracker/document/deploy write access):

```bash
export ENCELADUS_COORDINATION_INTERNAL_API_KEY="<current-key-from-ops>"
# All services default to this key unless specifically overridden:
export ENCELADUS_TRACKER_API_INTERNAL_API_KEY="$ENCELADUS_COORDINATION_INTERNAL_API_KEY"
export ENCELADUS_DOCUMENT_API_INTERNAL_API_KEY="$ENCELADUS_COORDINATION_INTERNAL_API_KEY"
export ENCELADUS_DEPLOY_API_INTERNAL_API_KEY="$ENCELADUS_COORDINATION_INTERNAL_API_KEY"
export ENCELADUS_GOVERNANCE_API_INTERNAL_API_KEY="$ENCELADUS_COORDINATION_INTERNAL_API_KEY"
export ENCELADUS_PROJECTS_API_INTERNAL_API_KEY="$ENCELADUS_COORDINATION_INTERNAL_API_KEY"
```

Obtain the current key from AWS Secrets Manager or your team ops channel.
If keys are missing, `install_profile.sh` will emit a `[WARNING]` and the MCP profile will
silently fail auth on all tracker/document/deploy write operations (PERMISSION_DENIED).

4. Install the Enceladus MCP profile:

```bash
ENCELADUS_WORKSPACE_ROOT="$(pwd)" \
tools/enceladus-mcp-server/install_profile.sh
```

5. Restart the desktop client (or start a fresh session) so the MCP server process reloads updated profile/runtime paths.

6. Start a desktop UI session and paste `SESSION_BRIEFING_TEMPLATE-UI.md`.

## Expected Initialization

After the init prompt, the agent should:

1. Resolve active Enceladus server alias (`enceladus` or `enceladus-local`).
2. Read `governance://agents.md` via `governance_get("agents.md")`.
3. Validate MCP readiness (`connection_health`, `coordination_capabilities`, `governance_hash`).
4. Proceed with standard MCP-only session initialization.
