# Governed Headless Agent Auth — Cognito M2M (ENC-FTR-074 Ph2 / ENC-TSK-I80)

This directory ships the **gamma** headless-agent authentication path for the Enceladus MCP
gateway: a Cognito **client_credentials** (M2M) token flow plus a REQUEST-type API Gateway
Lambda authorizer that tier-gates governed routes.

> **Deploy target: gamma only.** v3-prod is FROZEN (DOC-499FA089EC30). The authorizer, the
> agent-auth Cognito pool, and these profiles target the gamma stack. Nothing here touches
> `main` / the production API.

## Pieces

| File | Role |
| --- | --- |
| `infrastructure/cloudformation/08-agent-auth.yaml` | Ph1 dual-client Cognito pool **+ Ph2** REQUEST authorizer Lambda, `AWS::ApiGatewayV2::Authorizer`, and Tier 0 / Tier 1 self-test routes. |
| `agent_m2m_headers_helper.sh` | The **`.mcp.json` headersHelper**. Performs the client_credentials grant and emits a fresh `Authorization: Bearer <access_token>` header. |
| `mcp.gamma-m2m.json` | `.mcp.json` profile for headless gamma sessions, wiring the headersHelper. |
| `routines/run_pending_updates.sh` | Hourly Pending-Updates routine runner (authenticates with `agent.standard`). |
| `routines/pending-updates-hourly.json` | Declarative routine spec (schedule + auth + target). |

## Principal types discriminated by the authorizer (AC1)

The REQUEST authorizer (`enceladus-agent-authorizer`) inspects each request and resolves one of
three principal types, then enforces the route's required tier:

1. **internal-key** — `X-Coordination-Internal-Key` header validated against the Secrets Manager
   value in `InternalKeySecretId`. Granted `admin` (highest tier). Deny-closed when no secret id
   is configured.
2. **human** — a Cognito JWT issued by `HumanUserPoolId` (PWA), presented as `Authorization:
   Bearer` or the `enceladus_id_token` cookie. Not scope-limited; granted `admin`.
3. **m2m** — a headless-agent client_credentials access token issued by the agent-auth pool
   (`AgentUserPool`), carrying `enceladus-api/agent.*` scopes and the `enc:agent_tier` claim. The
   tier comes from `enc:agent_tier` (fallback: derived from the scopes).

The token signature is verified with a **pure standard-library RS256** implementation against the
pool JWKS — deliberately avoiding PyJWT/cryptography so the authorizer never inherits the
shared-layer `.so` ABI failure class (ENC-ISS-198 / ENC-LSN-020).

## Tier model & the governance-authority boundary (AC3)

```
observe (0)  <  standard (1)  <  elevated (2)  <  admin (3)
```

A route declares the **minimum** tier it requires. `agent.standard` (rank 1) is therefore:

- **admitted** on a **Tier 1** route — e.g. `POST /api/v1/agent/selftest/standard`, tracker /
  document / checkout mutations;
- **rejected with 403** on a **Tier 0** route — the governance-authority boundary, e.g.
  `POST /api/v1/agent/selftest/admin`, `dedup-review` approve, `deploy/submit|trigger|decide`,
  component `deprecate|restore|revert`.

GET/HEAD/OPTIONS reads require only `observe`.

## Mint a token / inject headers (AC2)

```bash
# Fresh bearer header as JSON (default) — this is what the .mcp.json headersHelper calls:
bash tools/enceladus-mcp-server/agent_m2m_headers_helper.sh --headers-json
# {"Authorization":"Bearer eyJ..."}

# Raw token, or export into the environment for the static-headers fallback:
bash tools/enceladus-mcp-server/agent_m2m_headers_helper.sh --token
eval "$(bash tools/enceladus-mcp-server/agent_m2m_headers_helper.sh --export)"   # sets ENCELADUS_M2M_BEARER
```

Required environment (gamma defaults shown):

```bash
export ENCELADUS_M2M_TOKEN_ENDPOINT="https://<agent-auth-domain>.auth.us-west-2.amazoncognito.com/oauth2/token"  # see 08-agent-auth.yaml TokenEndpoint output
export ENCELADUS_M2M_SCOPE="enceladus-api/agent.standard"   # default
# Credentials: either env or Secrets Manager (enceladus/agent-m2m/client-secret, hydrated by the Ph1 rotation Lambda)
export ENCELADUS_M2M_CLIENT_ID=...        # optional if reading the secret
export ENCELADUS_M2M_CLIENT_SECRET=...    # optional if reading the secret
```

Then connect a headless session with `mcp.gamma-m2m.json` and run any governed MCP call to verify.

## Hourly Pending-Updates routine (AC4)

`routines/run_pending_updates.sh` mints an `agent.standard` token and calls
`search(action=tracker.pending_updates)` on the gamma MCP gateway every hour. Wire it with cron,
a systemd timer, EventBridge Scheduler (`cron(0 * * * ? *)`), or a Claude Code routine per
`routines/pending-updates-hourly.json`. A successful run logs `[SUCCESS] pending-updates routine
completed (HTTP 200)` and is visible in the gamma MCP / coordination-api CloudWatch logs.

## Live verification (post-deploy, human-owned)

This task is delivered to `committed`; deploy + live AC verification on gamma are owned by the
human reviewer:

```bash
# AC1 — authorizer exists on the gamma HTTP API:
aws apigatewayv2 get-authorizers --api-id <gamma-api-id> --region us-west-2

# AC3 — agent.standard rejected on Tier 0 (403) / admitted on Tier 1 (200):
TOK=$(ENCELADUS_M2M_SCOPE=enceladus-api/agent.standard bash tools/enceladus-mcp-server/agent_m2m_headers_helper.sh --token)
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://enceladus-gamma.jreese.net/api/v1/agent/selftest/admin    -H "Authorization: Bearer $TOK"   # expect 403
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://enceladus-gamma.jreese.net/api/v1/agent/selftest/standard -H "Authorization: Bearer $TOK"   # expect 200
```
