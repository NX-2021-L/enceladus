# Native Desktop MCP Briefing (Minimal)

This folder contains the minimum files needed to initialize MCP-only native desktop UI sessions.

## Required Files

- `SESSION_BRIEFING_TEMPLATE-UI.md`
- `NEW_MACHINE_SETUP.md`
- `README.md`
- `tools/enceladus-mcp-server/install_profile.sh`

## Session Start

1. Complete one-time setup in `NEW_MACHINE_SETUP.md`.
2. Start a native desktop UI session.
3. Paste `SESSION_BRIEFING_TEMPLATE-UI.md` as the first prompt.

## Path Rule

Installer path is local to this folder, but runtime MCP assets are resolved from the canonical repository path `tools/enceladus-mcp-server/`.
