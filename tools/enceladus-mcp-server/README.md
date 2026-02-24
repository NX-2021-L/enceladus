# Enceladus MCP Server Assets

This directory is the canonical source for Enceladus MCP runtime assets used by:

- local/desktop MCP sessions
- host-v2 bootstrap flows
- briefing templates under `briefings/` (via canonical installer wrapper)

## Core Files

- `server.py`
- `dispatch_plan_generator.py`
- `install_profile.sh`
- `host_v2_first_bootstrap.sh`
- `host_v2_user_data_template.sh`
- `create_host_v2_launch_template.sh`

## Sync Rule

Briefing templates and wrappers must call this canonical installer/runtime path.
Do not copy `server.py` or `dispatch_plan_generator.py` into briefing subfolders;
that drift caused historical MCP transport mismatches.

## Deployment Policy

- Keep MCP source versioned in Git.
- Deploy coordination/runtime lambdas through their normal deploy scripts.
- Run MCP stdio smoke validation after installer or path changes.
