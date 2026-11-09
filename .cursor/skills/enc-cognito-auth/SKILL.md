---
name: enc-cognito-auth
description: "Acquire a live Cognito session for the Enceladus PWA via the MCP coordination API. Invoke from any Claude Code terminal session. Calls coordination.auth.cognito_session, displays auth metadata and truncated id_token, emits a ready-to-use curl snippet with the Cookie header set, and dumps the full playwright_cookies array for browser automation. Trigger on /enc-cognito-auth, 'get cognito session', 'authenticate to PWA', 'get enceladus token', or whenever a terminal agent needs authenticated access to jreese.net endpoints. NOT for MCP mutations (tracker, documents, checkout) — those use the internal API key path, not Cognito cookie auth. Upgrade path: ENC-FTR-074 will replace this with M2M client_credentials grant and identity-stamped tokens."
---

# enc-cognito-auth — Enceladus PWA Cognito Auth Session

Acquire a live Cognito session for the Enceladus PWA via the MCP coordination API. No interactive OAuth required.

## Trigger

Use when a terminal agent needs to curl or Playwright-drive the Enceladus PWA at `jreese.net` as an authenticated session — for diagnostics, validation, or automated read operations against PWA endpoints.

Do NOT use for MCP mutations (tracker, documents, checkout). Those route through the internal API key path, not Cognito cookie auth.

## Steps

1. Call `mcp__enceladus__coordination` with `action: auth.cognito_session` and no arguments.

2. Extract and display:
   - `session.auth_flow`
   - `session.expires_in`
   - `session.target_origin`
   - `id_token` cookie value (truncated: first 40 chars + `...` for readability)

3. Emit a ready-to-use curl snippet:

```bash
curl -s \
  -H "Cookie: enceladus_id_token=<id_token>" \
  https://jreese.net/enceladus/<ENDPOINT>
```

4. Emit the full `session.playwright_cookies` JSON array for browser automation.

5. State computed expiry: `issued_at` epoch ms + `expires_in` seconds, formatted as UTC ISO 8601.

## Notes

**Auth mechanism**: USER_PASSWORD_AUTH via `terminal-agent` service account — credentials held server-side in the MCP coordination API.

**Tokens returned**: id_token (1hr TTL), refresh_token (30-day TTL), session_at timestamp cookie.

**Install**: Save as `.claude/commands/enc-cognito-auth.md` (project) or `~/.claude/commands/enc-cognito-auth.md` (user). Invoke with `/enc-cognito-auth`.

**Upgrade path**: ENC-FTR-074 replaces this with M2M client_credentials grant, identity-stamped tokens, and governance tier enforcement.

## Governance Awareness (detail DOC-28C7B321D060)

- SCI required on every governed mutation + server-minted ENC-SES-NNN, else 403 (ENC-FTR-122).
- FSM-forbidden mutations (arc change, state override, post-closure) route escalation.request -> ENC-ESC-NNN -> io approval in PWA; never re-create records or hand-edit DDB (ENC-FTR-121).
- Autonomous builds are stall-watched from the isolated enceladus-support repo; silent stalls notify io (ENC-FTR-119).
- Deploy/CFN: DOC-BAEB4AC14720 + DOC-B716E8FB10B6 + DOC-CAE64D63F326.
