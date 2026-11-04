# Stateless MCP evaluation (ENC-TSK-S28-0B, AC3)

Status: evaluation only. Nothing here is implemented. Source BRD: DOC-E32D0ED08473, W1.2.

## What the spec revision says

MCP revision 2026-07-28, as summarized in the task brief (I did not re-read the spec text in this session), lets a streamable-HTTP server run sessionless: it accepts a request without a prior `initialize` / `notifications/initialized` exchange, and `Mcp-Session-Id` is optional. A sessionless server does not mint session ids, and a client that has none sends none. Protocol-version negotiation moves to the `MCP-Protocol-Version` request header, with the server rejecting unsupported versions per request. Treat this as the target contract and confirm the exact wording before building on it.

## What Enceladus does today

The `enceladus-mcp-code` Lambda already builds its transport as `StreamableHTTPSessionManager(json_response=True, stateless=True)` and rebuilds the ASGI task group on every invocation. Measured against the current server: a bare `tools/list` POST with no `initialize` returns HTTP 200, a plain JSON body and no `Mcp-Session-Id`. So the server is de facto stateless; the handshake ELR performs is a client habit, not a server requirement. Auth is a Cognito bearer verified on every request in `_handle_lambda_event`, independent of any session.

ELR long-lived mode (this task) therefore saves only client-side cost: one TLS setup per host and one `initialize` plus `notifications/initialized` pair per process, instead of per call.

## What going stateless would save

Two sequential round trips per process (initialize, initialized) on top of the connection reuse already delivered. That is the cost of two small POSTs per `elr` invocation (not yet measured on the ledger), so it is worth most for short-lived processes (single-verb CLI calls), where the handshake is currently a large fraction of wall time. Long-running multi-call processes already amortize it.

## Risks

- Auth: none new; the bearer is checked per request. Dropping the handshake removes no auth gate (ELR already refuses to infer identity from `initialize`).
- Idempotency cache locality: the idempotency cache is per warm container, not per session. Statelessness neither helps nor hurts, but it removes the session id as a possible routing hint, so a retried write can land on a cold container and miss the cache. Writes must keep carrying an explicit `Idempotency-Key` and rely on server-side record versioning, not container memory.
- Protocol-version negotiation: without `initialize` the client cannot learn server capabilities or the negotiated version. ELR must send `MCP-Protocol-Version` on every request and handle a 400 by falling back to the handshake. Third-party clients that still require `initialize` must keep working, so the server must support both paths.
- Fallback: a gateway or proxy in front of the Lambda that enforces sessions would break handshake-free calls; the client needs a probe-and-fallback.

## Recommendation

Do not change the server; add an opt-in handshake-free mode to ELR (`ELR_MCP_HANDSHAKE=0`) that sends `MCP-Protocol-Version` and the bearer on a first `tools/call`, falls back to initialize on a 400/404, and records `client_session_init_ms=0` in the ledger.

## Suggested follow-up task

"ELR: handshake-free MCP calls with protocol-version header and automatic fallback" under BRD DOC-E32D0ED08473 W1.2. Acceptance: A/B ledger comparison of single-verb `elr` invocations shows the saved two round trips on the gamma gateway; the fallback is exercised by a unit test; production stays on the handshake path until the gamma result is reviewed. Cost class C1.
