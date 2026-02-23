# New Machine Setup (Terminal / Host-v2, MCP-Only)

## Goal

Prepare local terminal and host-v2 terminal sessions so they can bootstrap MCP if missing, then initialize via `governance://agents.md`.

## Minimum Prerequisites

- Python 3.11+
- AWS credentials with access to Enceladus resources
- This briefing folder cloned/copied as a standalone package

## Setup Steps

1. From this folder, verify bundled MCP assets:

```bash
ls -la ./tools/enceladus-mcp-server/server.py \
       ./tools/enceladus-mcp-server/install_profile.sh \
       ./tools/enceladus-mcp-server/dispatch_plan_generator.py
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

4. Pre-install MCP profile (recommended for warm starts):

```bash
ENCELADUS_WORKSPACE_ROOT="$(pwd)" \
./tools/enceladus-mcp-server/install_profile.sh
```

5. Restart the terminal client session so MCP server runtime reloads updated profile/runtime paths.

6. Start the terminal session and paste `SESSION_BRIEFING_TEMPLATE-TERMINAL.md`.

## Expected Initialization

The agent should:

1. Detect whether MCP server `enceladus` is configured.
2. Install/repair profile if missing.
3. Validate `connection_health`, `coordination_capabilities`, and `governance_hash`.
4. Read `governance://agents.md` and continue MCP-only workflow.
