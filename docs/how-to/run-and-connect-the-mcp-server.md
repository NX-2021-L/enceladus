# How to run and connect to the Enceladus MCP server

This guide covers two bounded tasks:

1. **Connect an MCP client** (Claude Code, Claude desktop, or Codex) to the hosted Enceladus gateway.
2. **Run the server locally** over stdio for development.

For what the server exposes, see the [MCP tool surface reference](../reference/mcp-tool-surface.md). For why every tool routes through a service API instead of touching DynamoDB directly, see [About the MCP API boundary](../explanation/about-the-mcp-api-boundary.md). For the session bootstrap and lifecycle contract an agent must follow once connected, see the [repo-root `AGENTS.md`](../../AGENTS.md).

## Before you start

You need:

- An MCP-capable client (Claude Code desktop, Claude Code CLI, or Codex).
- For the fastest path, the canonical installer: `tools/enceladus-mcp-server/install_profile.sh`. It writes the correct entry into every client config it finds and runs a smoke test — prefer it over hand-editing JSON/TOML.
- For local development: Python 3 and the `mcp` package importable (`server.py` imports `mcp.server`).

## 1. Connect a client to the hosted gateway

The hosted gateway speaks Streamable HTTP and enforces the governed **code-mode** tool surface (`search`, `coordination`, `get_compact_context`, `execute`). Point your client at the gateway URL with `type: http` — no local `server.py` subprocess is involved.

Canonical gateway URL (written by the installer, `install_profile.sh` line 25):

```
https://jreese.net/api/v1/coordination/mcp
```

`https://mcp.jreese.net` is a CNAME alias for the same API Gateway stage, so either host reaches the same backend. See the [five-surface parity matrix](../../tools/enceladus-mcp-server/briefings/native-desktop-mcp-briefing-extras/FIVE_SURFACE_MCP_PARITY_MATRIX.md) for the authoritative per-surface URL/auth breakdown.

### Recommended: run the installer

```bash
ENCELADUS_COORDINATION_INTERNAL_API_KEY=<your-key> \
  tools/enceladus-mcp-server/install_profile.sh
```

This merges the `enceladus` server entry into `~/.claude/mcp.json`, `~/.claude.json` (`mcpServers` key), and `~/.codex/config.toml`, then runs a `tools/list` smoke test against the gateway. Do not commit the key or paste it into this guide — supply it only via the environment variable above. If the key rotates, re-run the installer to refresh the stored value.

### Manual config (if you are not using the installer)

Each client stores the entry in a different file:

| Client | Config file | Key |
| --- | --- | --- |
| Claude desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` | `mcpServers` |
| Claude Code CLI | `~/.claude.json` | `mcpServers` |
| Claude Code (desktop settings) | `~/.claude/mcp.json` | `mcpServers` |
| Codex | `~/.codex/config.toml` | `[mcp_servers.enceladus]` |

Minimal Claude / JSON entry (shape emitted by `install_profile.sh`):

```json
{
  "mcpServers": {
    "enceladus": {
      "type": "http",
      "url": "https://jreese.net/api/v1/coordination/mcp"
    }
  }
}
```

Minimal Codex entry:

```toml
[mcp_servers.enceladus]
type = "http"
url = "https://jreese.net/api/v1/coordination/mcp"
```

**Authentication depends on the surface — confirm yours in the parity matrix rather than assuming:**

- The **claude.ai web connector** uses Cognito OAuth (OAuth 2.1 PKCE); the client runs the flow and you add **no** auth header to any config.
- The **terminal/desktop surfaces written by the installer** authenticate with an `X-Coordination-Internal-Key` header carrying your internal key. When present, the JSON entry gains a `"headers"` object and the Codex entry gains an `[mcp_servers.enceladus.http_headers]` section (see `install_profile.sh` lines 73–76 and 235–238). Let the installer write this — do not hand-place secret values.

### Verify the connection

In a client session, call `connection_health()`. A healthy response confirms DynamoDB/S3/API connectivity and returns the `governance_hash`. The four code-mode tools (`search`, `coordination`, `get_compact_context`, `execute`) should be the visible surface; the gateway enforces code mode regardless of any `ENCELADUS_MCP_INTERFACE_MODE` setting.

## 2. Run the server locally over stdio

Local runs use the **stdio** transport, which is `server.py`'s default. Running the module directly starts the stdio server:

```bash
ENCELADUS_MCP_INTERFACE_MODE=code \
  python3 tools/enceladus-mcp-server/server.py
```

Two facts make `ENCELADUS_MCP_INTERFACE_MODE=code` important locally:

- `ENCELADUS_MCP_TRANSPORT` defaults to `stdio` (`server.py` line 399), so you do not need to set the transport for a local run. The `streamable_http` value is for the Lambda/HTTP path (`lambda_handler`), not stdio.
- Interface mode defaults to **raw**, which exposes 50+ individual tools. Set `ENCELADUS_MCP_INTERFACE_MODE=code` to surface the same governed 4-tool interface the hosted gateway enforces (`server.py` lines 423–440; see drift finding DRIFT-4 in the [parity matrix](../../tools/enceladus-mcp-server/briefings/native-desktop-mcp-briefing-extras/FIVE_SURFACE_MCP_PARITY_MATRIX.md)).

To point a client at this local stdio process instead of the hosted gateway, register a stdio MCP server in your client config whose command launches `server.py` with the same environment. Mirror the launch command and env above; consult your client's docs for the exact stdio-server config shape.

> The canonical installer (`install_profile.sh`) configures the **remote HTTP** profile, not a local stdio one — use the local run above only for development and testing against your own checkout of `server.py`.
