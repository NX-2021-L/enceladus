# Verify the gamma io-kit edge 0.3.0 activation (ENC-TSK-S57-e)

`_KIT030_BASES` in `tools/enceladus-mcp-server/server.py` now holds `https://mcp-gamma.jreese.net`. Once `enceladus-mcp-code-gamma` (alias `live`, `CUSTOM_DOMAIN=mcp-gamma.jreese.net`) runs this code, it runs io-kit-mcp-edge 0.3.0 (from `_kit030/`) instead of 0.1.3. Production (`https://mcp.jreese.net`, `enceladus-mcp-code`) and every other base are not in the list and take the unchanged 0.1.3 path.

What changes on gamma, and only there:

| | 0.1.3 (before) | 0.3.0 (after) |
| --- | --- | --- |
| PRM `/.well-known/oauth-protected-resource*` | served, no version header | served, header `x-io-kit-mcp: 0.3.0`, `authorization_servers` = the base |
| `/.well-known/oauth-authorization-server*`, `/register` | served by the host's kit (registration facade echoes the old client id) | not served: the sign-in service owns them (CloudFront routing, S57-d) |
| `/authorize`, `/callback` | host routes | not served by the host: sign-in service |
| `/oauth/token`, `/oauth/register` | host routes | unchanged, still host routes |
| Bearer gate accepts | the environment client only | the sign-in client `4r6e9pfkccv050akrcu2ihlen4` and the env client |

## Order, and what a client sees between the two steps

Two independent changes: the CloudFront routing (branch `agent/enc-tsk-s57-d-gamma-routing`, a stack update) and this activation (a Lambda deploy). Either can merge first. Between them gamma is half-switched:

* **Routing live, activation not deployed (recommended order).** The sign-in service answers the authorization-server metadata, `/register`, `/authorize`, `/callback` and `/token`, so discovery, registration and sign-in all work and Cognito issues tokens for the new sign-in client. The 0.1.3 gate on `/mcp` only accepts the old client id, so a token from a new sign-in is refused with 401 (`client_id mismatch`) on every call. Tokens already issued under the old client keep working, and refresh through `/oauth/token` (still a host route) keeps working. So: nothing already connected breaks; a brand-new sign-in finishes at the IdP and then does not get in. The fleet probe never exchanges a code for a token, so it sees C02, C13 (registration refused, 400) and C14 green and C16 `warn` (no version header yet).
* **Activation deployed, routing not live.** The 0.3.0 edge serves only PRM, OPTIONS and the bearer gate. `/.well-known/oauth-authorization-server`, `/register`, `/authorize` and `/callback` reach the bearer gate and answer 401, so a client that reads the PRM (`authorization_servers = [the base]`) cannot fetch the metadata and cannot start a connection; a sign-in already in flight loses `/authorize` and `/callback`. Existing tokens (old client, accepted by the 0.3.0 gate) and `/oauth/token` refresh keep working. The hourly fleet probe fails C02 and C14 (both blocking) and C13, which opens an `mcp-fleet` issue for `enceladus-gamma`.

Routing first has the smaller blast radius: nothing is broken for anyone already connected, the probe stays green, and the step that is slow to reverse (a CloudFront update, minutes) happens while nothing depends on it. The step that finishes the switch is a Lambda alias move, reversible in seconds. Activation first breaks discovery for every new connection and trips a blocking probe until the routing lands.

## After both are live: verify

1. Stack and distribution (routing):

```bash
aws cloudformation describe-stacks --region us-west-2 --stack-name enceladus-mcp-edge-gamma --query 'Stacks[0].StackStatus' --output text   # UPDATE_COMPLETE
aws cloudfront get-distribution --id E2KVDHFSQ5G5VE --query 'Distribution.Status' --output text                                              # Deployed
```

2. The deployed code (activation). Both must be true on gamma only:

```bash
curl -si https://mcp-gamma.jreese.net/.well-known/oauth-protected-resource | grep -i '^x-io-kit-mcp'   # x-io-kit-mcp: 0.3.0
curl -si https://mcp.jreese.net/.well-known/oauth-protected-resource      | grep -ci '^x-io-kit-mcp'   # 0   (production unchanged)
```

3. The io-kit fleet probe for `enceladus-gamma`, from a checkout of `NX-2021-L/io-kit` at `origin/main` (Node 20 or newer; the manifest `packages/mcp/fleet/fleet.json` sits beside the script, or pass `--fleet <file>` / `IO_KIT_FLEET_FILE`). `MCP_PROBE_NO_CODEARTIFACT=1` skips the package publish-time lookup that needs AWS; the C16 lag rule then has no publish time, which only matters when the version is behind:

```bash
cd <io-kit checkout>   # origin/main
MCP_PROBE_NO_CODEARTIFACT=1 node packages/mcp/fleet/mcp-fleet.mjs probe --connector enceladus-gamma --strict --out /tmp/fleet-gamma.json; echo "exit=$?"
```

`--strict` makes every check blocking (without it only C01, C02, C06, C09 and C14 are; `--strict-c13` adds just C13). Exit 0 means pass, 1 means a connector failed. The `fleet_version` in the manifest is `0.3.0`, which C16 compares against the header.

Expected for `enceladus-gamma`: C01, C02, C06, C09 pass; **C13 pass** (`register -> 400`: the sign-in service refuses the probe's non-allow-listed callback); **C14 pass** (`all clients reach the login page`: claude.ai, cursor and loopback each reach the Cognito hosted UI through `/authorize`); **C16 pass** (`x-io-kit-mcp=0.3.0`, no longer the `warn` for an absent header); C17 skip (not a thepup connector). Before this change the same command reports C13 `FAIL` (`register -> 201`) and C16 `warn`.

If C13 or C14 fails, the routing is not live or not propagated (the distribution `Status` is not `Deployed`); if C16 is `warn` with no header, the activation has not reached the `live` alias.

## Roll back

Activation (seconds, no CloudFront involved): move the `live` alias of the gamma function back to the version it pointed at before this deploy. The version is printed by the deploy's capture step; if it is lost, `aws lambda list-versions-by-function --region us-west-2 --function-name enceladus-mcp-code-gamma` and the alias history show it.

```bash
aws lambda update-alias --region us-west-2 --function-name enceladus-mcp-code-gamma --name live --function-version <previous>
```

Then gamma is back on 0.1.3: host serves `/authorize`, `/callback`, the registration facade and the old-client gate. If the routing is still live at that point, the half-switched state in the first bullet above applies, so also roll the routing back (`docs/how-to/import-the-gamma-mcp-distribution.md`, "Roll back") when abandoning the change. Production is not touched by either step.

## Not added: a post-deploy smoke assertion

`tools/post_deploy_smoke.py` would be the natural home for "gamma PRM must carry `x-io-kit-mcp: 0.3.0`", so that a silent fall back to the legacy gate triggers the existing alias rollback. It is not added here, deliberately:

* `PROBE_TABLE` is keyed by the production function name; gamma's `enceladus-mcp-code-gamma` is reported as the non-failing `no_probe_env_variant`, and `tools/test_post_deploy_smoke.py` asserts exactly that (two tests, plus one that checks a gamma name can never be told apart from production). Adding a gamma key changes that contract and those tests.
* `_deploy.yml` checks the smoke tool out from `main` (`.guard-tools`), not from the branch being deployed, so a change here would not take effect for a `v4/main` deploy until it reaches `main`.
* `ProbeSpec` has no response-header check, so it needs a small extension (`required_header`, checked in `probe_target`).

If wanted, it is a separate change: a `PROBE_TABLE["enceladus-mcp-code-gamma"]` entry (`base_url=https://mcp-gamma.jreese.net`, `QUALIFIER_ALIAS_QUALIFIED`, probes PRM 200 with `required_header=("x-io-kit-mcp", "0.3.0")` and `/` 401), `ProbeSpec.required_header`, and the two env-variant tests updated. Production's entry and probes would not change.
