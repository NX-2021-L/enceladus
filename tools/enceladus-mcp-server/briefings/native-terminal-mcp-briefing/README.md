# Native Terminal MCP Briefing (Minimal)

This folder contains terminal-optimized init files for MCP-only Enceladus sessions.

## Required Files

- `SESSION_BRIEFING_TEMPLATE-TERMINAL.md`
- `NEW_MACHINE_SETUP.md`
- `README.md`
- `tools/enceladus-mcp-server/install_profile.sh`

## Session Start

1. Complete one-time setup in `NEW_MACHINE_SETUP.md`.
2. Start a local terminal session or host-v2 terminal session.
3. Paste `SESSION_BRIEFING_TEMPLATE-TERMINAL.md` as the first prompt.

The terminal template enforces setup-if-missing MCP bootstrap before governance initialization.

## Path Rule

Installer path is local to this folder, but runtime MCP assets are resolved from the canonical repository path `tools/enceladus-mcp-server/`.
