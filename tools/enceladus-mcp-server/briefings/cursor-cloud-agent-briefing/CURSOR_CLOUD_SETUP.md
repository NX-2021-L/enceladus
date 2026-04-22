# Cursor Cloud Agent — Enceladus MCP Setup

## Architecture

Cursor Cloud Agents connect to the Enceladus MCP server via the **remote HTTP gateway** (not stdio). The gateway URL is `https://jreese.net/api/v1/coordination/mcp`. Auth is passed as the `X-Coordination-Internal-Key` request header.

### Why HTTP (not stdio)

Cursor's HTTP MCP transport proxies tool calls through the backend. The agent's VM never sees the auth header value, making it more secure than stdio. SSE and `mcp-remote` are not supported by Cursor Cloud Agents.

## One-Time Setup (per user or per team)

Only **Step 1** is required. The repo already ships `.cursor/mcp.json`, so no dashboard MCP entry is needed.

### Step 1 — Add the API key as a Cursor Secret (required)

1. Go to [cursor.com/dashboard/cloud-agents](https://cursor.com/dashboard/cloud-agents).
2. Open the **Secrets** tab.
3. Add a secret named exactly:

```
ENCELADUS_COORDINATION_INTERNAL_API_KEY
```

   Value: the current internal API key (obtain from AWS Secrets Manager or your ops channel).

4. Mark it as **Redacted** so it is not exposed in agent transcripts or commits.

> **Team scope**: Secrets can be scoped to a team so all team members' cloud agents inherit the same key without individual setup.

### Step 2 — Dashboard MCP entry (optional — skip if using repo config)

The repo ships `.cursor/mcp.json` which registers the `enceladus` MCP server automatically for all agents running in this workspace. **No manual dashboard entry is needed.**

If you want an explicit dashboard-level entry (e.g. for use outside this repo), you can add it:

1. Go to [cursor.com/agents](https://cursor.com/agents) → MCP dropdown.
2. Add a new server:
   - **Name**: `enceladus`
   - **Type**: `HTTP`
   - **URL**: `https://jreese.net/api/v1/coordination/mcp`
   - **Headers**: `X-Coordination-Internal-Key: <key>`

Headers entered in the dashboard are encrypted at rest and never readable back.

### Step 3 — Verify (optional)

After adding the secret, start a new cloud agent session. It should pick up the `enceladus` MCP tools. The agent will run the standard initialization sequence defined in `AGENTS.md`.

## How `.cursor/mcp.json` Works

The file at `.cursor/mcp.json` in the repo root uses `${env:ENCELADUS_COORDINATION_INTERNAL_API_KEY}` in the header value. Cursor substitutes secrets injected from the dashboard before the header is sent. The literal `${env:...}` placeholder is never transmitted.

```json
{
  "mcpServers": {
    "enceladus": {
      "type": "http",
      "url": "https://jreese.net/api/v1/coordination/mcp",
      "headers": {
        "X-Coordination-Internal-Key": "${env:ENCELADUS_COORDINATION_INTERNAL_API_KEY}"
      }
    }
  }
}
```

## Environment Setup (`.cursor/environment.json`)

The repo also ships `.cursor/environment.json`. Its `install` command runs on every new agent VM to:

1. Install `mcp`, `boto3`, and `PyYAML` Python packages (needed if the agent runs the stdio `server.py` for local testing).
2. Run `install_profile.sh` in keyless mode to write `~/.codex/config.toml` and related bootstrap files.

The `ENCELADUS_COORDINATION_INTERNAL_API_KEY` secret is available as an environment variable during `install`, so the profile installer will also write a functioning `~/.codex/config.toml` entry for Codex-style sessions.

## Initialization Sequence (every session)

Agents in this repo are instructed by `AGENTS.md` to run these MCP calls in order:

1. `connection_health` — verify DynamoDB/S3/API connectivity, get governance hash
2. `governance_get("agents.md")` — load full governance rules
3. `governance_dictionary` — load compact enum/constraint index
4. `governance_get("agents/bootstrap-template.md")` — session init protocol
5. `governance_get("agents/lifecycle-primer.md")` — lifecycle gates

This sequence is mandatory before any task work begins.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| MCP tools missing from agent session | Secret not set or wrong name | Add `ENCELADUS_COORDINATION_INTERNAL_API_KEY` to Cursor Secrets |
| `PERMISSION_DENIED` on write tools | Key present but wrong value | Rotate key from AWS Secrets Manager |
| `connection_health` returns unhealthy | Gateway or backend down | Check `https://jreese.net/api/v1/health` |
| `${env:...}` appears literally in logs | Old Cursor version or misconfigured secret | Update Cursor and verify secret name matches exactly |
