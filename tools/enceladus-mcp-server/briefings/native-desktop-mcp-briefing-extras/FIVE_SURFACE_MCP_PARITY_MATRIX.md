# ENC-TSK-G46: Five-Surface MCP Client Parity Matrix

**Task:** ENC-TSK-G46 (G14-L2: Audit — 5-surface MCP client parity matrix)
**Feature:** ENC-FTR-099 (Request-Scale Configuration Stack — Token Economics Defense)
**Wave:** DOC-1487FA9B03A5
**Authored:** 2026-04-27
**governance_hash:** `5b5277ebe1e612e4ebe274f98518ae30afe25d055ebda431614efcbcd6805944`

---

## Scope

IO rescoped ENC-TSK-G14 from a single Anthropic-inline-connector header migration
to a five-surface parity charter after the original premise was invalidated: the
codebase does not use the Anthropic-inline MCP connector. All five surfaces hit the
same governed gateway at `https://jreese.net/api/v1/coordination/mcp` (or stdio).

This document enumerates the five surfaces, their transport/auth/config-source and
tool-list parity status, identifies the shared code path, describes per-surface
adapter boundaries, and recommends the G47 boundary shape.

**Related doc:** `TERMINAL_MCP_VALIDATION_MATRIX.md` (prior validation matrix
covering install-bootstrap contract tests for surfaces 1–2 and host-v2 fleet).

---

## Five-Surface Inventory

| # | Surface | Transport | Auth method | Config source | Gateway URL | Tool-list parity |
|---|---------|-----------|-------------|---------------|-------------|-----------------|
| 1 | Claude Code HTTP | Streamable HTTP | `X-Coordination-Internal-Key` header | `~/.claude/mcp.json` (written by `install_profile.sh`) | `https://jreese.net/api/v1/coordination/mcp` | ✅ 4/4 |
| 2 | Claude/Codex terminal CLI | HTTP | `Authorization: Bearer <Cognito JWT>` | `~/.codex/config.toml` (written by `install_profile.sh`) | `https://mcp.jreese.net` ⚠️ | ⚠️ 3/4 approval policies |
| 3 | claude.ai web connector | Streamable HTTP (OAuth 2.1 PKCE) | Cognito JWT Bearer (DCR + `authorization_code` flow) | claude.ai connector record (MCP settings UI) | `https://jreese.net/api/v1/coordination/mcp` | ✅ 4/4 (reach: manual capture from io) |
| 4 | Cursor desktop | HTTP | `X-Coordination-Internal-Key` header (env substitution) | `.cursor/mcp.json` (repo-committed) | `https://jreese.net/api/v1/coordination/mcp` | ✅ 4/4 |
| 5 | Cursor cloud agent | HTTP (Cursor backend proxy) | `X-Coordination-Internal-Key` (Cursor Secret) | `.cursor/mcp.json` + Cursor dashboard Secrets | `https://jreese.net/api/v1/coordination/mcp` | ✅ 4/4 |

### Code-mode tool set (canonical, all surfaces)

All HTTP surfaces hit the coordination_api gateway which enforces `code` interface
mode regardless of the `ENCELADUS_MCP_INTERFACE_MODE` env var in `server.py`.
The four exposed tools are:

| Tool | Description |
|------|-------------|
| `search` | Compact read-only discovery (action + arguments pattern) |
| `coordination` | Orchestration / dispatch-plan generation |
| `get_compact_context` | Budgeted composite context assembly with hybrid retrieval (ENC-TSK-B92) |
| `execute` | Governed workflow runner for ordered mutation / lifecycle steps |

### governance_hash propagation

`governance_hash` is embedded in every `search` and `execute` response body by the
coordination_api. All five surfaces receive it identically on first tool call.
No surface exposes a different hash — they share a single backend. Terminal sessions
are expected to capture the hash from `system.connection_health` and forward it on
all mutation calls.

---

## Shared Code Path

Two code paths serve all five surfaces; every request ultimately passes through
one or both.

### Path A — stdio (surfaces running local `server.py`)

```
tools/enceladus-mcp-server/server.py
  line  41   : from mcp.server import Server
  line  42   : from mcp.server.stdio import stdio_server
  lines 423–439  : interface_mode resolution (ENCELADUS_MCP_INTERFACE_MODE env var)
  lines 3216–3402: code-mode tool catalog definition
  lines 3406–3409: list_tools() — filters by INTERFACE_MODE
  line  5183  : call_tool() (@app.call_tool decorator)
  lines 5187–5199: code-mode gate + _TOOL_HANDLERS dispatch
```

**Note:** `server.py` defaults to **raw mode** (50+ tools) when
`ENCELADUS_MCP_INTERFACE_MODE` is unset. Stdio installs must set this env var
explicitly to surface the governed 4-tool interface. HTTP surfaces (paths A→B
or pure B) are not affected — the gateway enforces code mode independently.

### Path B — Streamable HTTP gateway (all five surfaces)

```
backend/lambda/coordination_api/lambda_function.py
  line  121  : COMPONENTS_TABLE = os.environ.get("COMPONENTS_TABLE", "component-registry")
  line  13634: claims, auth_err = _authenticate(event)   ← auth branching point
  lines 13787–13788: GET/POST /api/v1/coordination/mcp → _handle_mcp_http(claims, event)

backend/lambda/coordination_api/handlers.py
  lines 321–388 : _handle_mcp_http()
    line  266  : _dispatch_mcp_jsonrpc_method()
    lines 266–273: INTERFACE_MODE == "code" → filter to _ENCELADUS_CODE_MODE_TOOLS
    line  283  : call_args.setdefault("caller_identity", MCP_AUDIT_CALLER_IDENTITY)

tools/enceladus-mcp-server/server.py
  lines 9975–9989: Lambda HTTP event handler
    StreamableHTTPSessionManager(stateless=True, json_response=True)
    line  10810–10850: HTTP auth validation (Cognito JWT or Bearer token)
```

`_authenticate()` in `lambda_function.py` is the single branching point for
auth strategy: Cognito JWT vs internal API key. Both branches converge at
`_handle_mcp_http()` and produce the same code-mode tool surface.

---

## Per-Surface Adapter Boundaries

### Surface 1 — Claude Code HTTP

- **Adapter boundary:** `~/.claude/mcp.json` `type: http` entry written by
  `install_profile.sh`. Auth key resolved from `ENCELADUS_COORDINATION_INTERNAL_API_KEY`
  env var at install time; written as a static value into the JSON config.
- **No runtime auth refresh:** if the key rotates, `install_profile.sh` must be
  re-run to update the stored value.
- **Interface mode:** enforced at gateway (code mode); `server.py` env var not relevant.

### Surface 2 — Claude/Codex terminal CLI

- **Adapter boundary:** `~/.codex/config.toml` `[mcp_servers.enceladus]` block.
  Auth is a Cognito JWT Bearer token (time-bound; expires ~60 minutes post-issuance).
  The live config at `~/.codex/config.toml` uses URL `https://mcp.jreese.net`,
  which differs from the canonical gateway URL used by all other surfaces.
- **Token refresh:** codex sessions using an expired token will fail auth. The
  `install_profile.sh` does not implement automatic Cognito token refresh for
  the codex config.
- **Approval policy:** three of four code-mode tools are covered by explicit
  `approval_mode = "approve"` entries (`search`, `get_compact_context`, `execute`);
  `coordination` is absent. Behavior on `coordination` tool calls depends on
  codex runtime defaults (likely auto-approve, but unspecified).

### Surface 3 — claude.ai web connector

- **Adapter boundary:** claude.ai MCP connector record. Managed by the OAuth 2.1
  DCR (`mcp_server.cognito_oauth` dict entity) — the authorization endpoint and
  token endpoint point to Cognito Hosted UI. Bearer tokens are validated as Cognito
  JWTs by the coordination_api.
- **Reach from terminal:** not reachable. Validation requires manual capture from io
  (tool-list snapshot via claude.ai session).
- **Interface mode:** enforced at gateway.

### Surface 4 — Cursor desktop

- **Adapter boundary:** `.cursor/mcp.json` (repo-committed at repo root). Auth key
  is resolved via `${env:ENCELADUS_COORDINATION_INTERNAL_API_KEY}` env substitution
  at request time — Cursor substitutes the secret before the header is sent, so the
  literal placeholder is never transmitted.
- **No static key storage:** unlike surface 1, the key is not baked into the config
  file; it is resolved from the shell/IDE environment at runtime. Key rotation
  requires only an env var update.
- **Interface mode:** enforced at gateway.

### Surface 5 — Cursor cloud agent

- **Adapter boundary:** same `.cursor/mcp.json` config as surface 4, but the
  `ENCELADUS_COORDINATION_INTERNAL_API_KEY` secret is resolved from the Cursor
  dashboard Secrets store (not the local shell environment). The Cursor backend
  proxies the HTTP call; the agent VM never sees the key value.
- **Setup requirement:** the secret must be registered in Cursor dashboard before
  cloud agent sessions can authenticate. See `cursor-cloud-agent-briefing/
  CURSOR_CLOUD_SETUP.md` for the one-time setup steps.
- **Interface mode:** enforced at gateway.

---

## Drift Findings

### DRIFT-1 — URL divergence on surface 2 (codex)

**Severity:** Medium  
**Where:** `~/.codex/config.toml` `[mcp_servers.enceladus] url`  
**Observed:** `https://mcp.jreese.net`  
**Expected:** `https://jreese.net/api/v1/coordination/mcp` (canonical gateway)

The live codex config uses a different hostname than all other surfaces. If
`https://mcp.jreese.net` is a CNAME alias for the same API Gateway stage, the
divergence is cosmetic. If it routes to a different Lambda function URL or stage,
surface 2 may observe different behavior (e.g., different feature-flag state,
different AppConfig TTL, different log group). **Needs io confirmation** that
`mcp.jreese.net` is an alias for `jreese.net/api/v1/coordination/mcp`.

**G47 action:** Confirm URL identity; standardize `install_profile.sh` to write
the canonical URL for codex. Update existing `~/.codex/config.toml` entries.

### DRIFT-2 — Auth strategy divergence on surface 2 (codex)

**Severity:** Medium  
**Where:** `~/.codex/config.toml` `Authorization` header  
**Observed:** `Authorization: Bearer <Cognito JWT>` (time-bound ~60 min)  
**Expected pattern for agent surfaces:** persistent internal key

The codex surface authenticates via a Cognito JWT that expires. Any codex session
started after token expiry will fail all MCP calls with auth errors. `install_profile.sh`
does not currently implement token refresh for the codex config. Internal-key-based
surfaces (1, 4, 5) have no expiry concern.

**G47 action:** Decide whether codex should use the internal key (matching surfaces
1/4/5) or implement a Cognito token-refresh mechanism in `install_profile.sh`.

### DRIFT-3 — `coordination` tool absent from surface 2 approval policy

**Severity:** Low  
**Where:** `~/.codex/config.toml` `[mcp_servers.enceladus.tools.*]` blocks  
**Observed:** approval_mode set for `search`, `get_compact_context`, `execute`; `coordination` not listed  
**Expected:** all four code-mode tools have an explicit approval_mode entry

The `coordination` tool is the dispatch-plan generation and orchestration surface.
Without an explicit approval_mode entry for it, codex runtime will apply its
default policy (behavior unspecified; likely auto-approve). If the default is
`require` or interactive, `coordination` tool calls will stall silently.

**G47 action:** Add `[mcp_servers.enceladus.tools.coordination] approval_mode = "approve"`
to `install_profile.sh`'s codex config writer.

### DRIFT-4 — Interface-mode env gap for stdio installs

**Severity:** Low (HTTP surfaces unaffected)  
**Where:** `tools/enceladus-mcp-server/server.py` lines 423–439  
**Observed:** `server.py` defaults to raw mode (50+ tools) when
`ENCELADUS_MCP_INTERFACE_MODE` is unset  
**Expected:** code-mode (4-tool) surface

Any session that runs `server.py` locally via stdio (e.g., local development,
test harness) without the env var will see 50+ raw tools instead of the governed
4-tool code-mode surface. HTTP-mode sessions (all five production surfaces) are
unaffected — the gateway enforces code mode at `handlers.py` lines 266–273
independent of the env var.

**G47 action:** Document the required env var in `install_profile.sh` session
bootstrap and `TERMINAL_MCP_BOOTSTRAP_CONTRACT.md`. Consider defaulting `server.py`
to code mode when `COORDINATION_INTERFACE_MODE` env var is absent in Lambda context.

---

## Recommendations for ENC-TSK-G47

### G47 adapter-boundary shape

The `_authenticate()` call in `backend/lambda/coordination_api/lambda_function.py`
(line 13634) is already the single, correct branching point for auth strategy:
Cognito JWT (surfaces 2, 3) vs internal API key (surfaces 1, 4, 5). Both branches
converge at `_handle_mcp_http()` and produce an identical code-mode tool surface.
**G47 should not introduce a new adapter class or split the MCP handler** — the
boundary already exists.

### Recommended G47 work items (ordered by impact)

1. **Confirm and standardize gateway URL for surface 2** (DRIFT-1): verify that
   `https://mcp.jreese.net` aliases `https://jreese.net/api/v1/coordination/mcp`;
   update `install_profile.sh` to write the canonical URL to `~/.codex/config.toml`.

2. **Resolve surface 2 auth strategy** (DRIFT-2): decide between (a) switching codex
   to the persistent internal key path (minimal change, consistent with surfaces 1/4/5)
   or (b) adding a Cognito token-refresh step to `install_profile.sh` codex bootstrap
   (preserves Cognito flow, adds complexity). Option (a) is recommended given that
   surfaces 4/5 (Cursor) already prove the internal-key path is viable for non-Claude
   runtimes.

3. **Add `coordination` approval entry to codex config writer** (DRIFT-3): one-line
   addition to `install_profile.sh`.

4. **Document stdio env-var requirement** (DRIFT-4): add `ENCELADUS_MCP_INTERFACE_MODE=code`
   to `TERMINAL_MCP_BOOTSTRAP_CONTRACT.md` required env section and to the stdio-mode
   startup docs.

5. **Surface 3 (claude.ai web) tool-list capture**: the web connector tool-list was
   not directly verifiable from a terminal session. As a follow-on to G47, io should
   capture the tool-list snapshot from a live claude.ai session and confirm parity.

### Files G47 will likely touch

| File | Change type |
|------|-------------|
| `tools/enceladus-mcp-server/install_profile.sh` | Fix codex config URL + add coordination approval policy |
| `tools/enceladus-mcp-server/briefings/native-desktop-mcp-briefing-extras/TERMINAL_MCP_BOOTSTRAP_CONTRACT.md` | Add ENCELADUS_MCP_INTERFACE_MODE env var to required env section |
| `backend/lambda/coordination_api/lambda_function.py` | No changes required (auth boundary is correct) |
| `backend/lambda/coordination_api/handlers.py` | No changes required (code-mode gate is correct) |
| `tools/enceladus-mcp-server/server.py` | Optional: default to code mode in Lambda context |
