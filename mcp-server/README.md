# MCP Server

Enceladus MCP server source mirror.

## Scope

This folder mirrors the canonical MCP source from:

- `/Users/jreese/Dropbox/claude-code-dev/projects/devops/tools/enceladus-mcp-server`

Included artifacts:

- `server.py`
- `dispatch_plan_generator.py`
- `install_profile.sh`
- integration/unit tests
- `briefings/` canonical native MCP session briefing templates

## Deployment Policy

- MCP source is kept in GitHub for full-codebase visibility and collaboration.
- No GitHub Actions auto-deploy is configured for MCP components in this repo.

## Tracker ID Allocation

`tracker_create` now uses an atomic DynamoDB counter per `(project_id, record_type)` instead of scan-and-increment ID allocation.

- Counter records are stored in the tracker table with `record_id` keys prefixed by `counter#`.
- New IDs are allocated via atomic `UpdateItem` increments to prevent concurrent collisions.
- Creation still uses conditional puts; if an ID collision is detected, the server retries with a fresh counter increment.

## Briefing Templates

Native MCP briefing templates are now managed in Git at:

- `mcp-server/briefings/native-desktop-mcp-briefing`
- `mcp-server/briefings/native-terminal-mcp-briefing`
- `mcp-server/briefings/native-desktop-mcp-briefing-extras`
