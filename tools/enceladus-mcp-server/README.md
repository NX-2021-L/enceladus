# Enceladus MCP Server Assets

This directory is the canonical source for Enceladus MCP runtime assets used by:

- local/desktop MCP sessions
- host-v2 bootstrap flows
- bundled native briefing packages under `briefings/*/tools/enceladus-mcp-server/`

## Core Files

- `server.py`
- `dispatch_plan_generator.py`
- `install_profile.sh`
- `host_v2_first_bootstrap.sh`
- `host_v2_user_data_template.sh`

## Sync Rule

Briefing bundle copies of the MCP assets must remain in lockstep with these canonical files to avoid profile/runtime drift that can surface as MCP `Transport closed` failures in Codex/desktop sessions.

## Deployment Policy

- Keep MCP source versioned in Git.
- Deploy coordination/runtime lambdas through their normal deploy scripts.
- Run MCP stdio smoke validation after installer or path changes.
