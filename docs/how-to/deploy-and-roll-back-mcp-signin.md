# How to deploy, ship and roll back the MCP sign-in service (ENC-TSK-S57-a)

The sign-in service is the io-kit `createSignInService` (`@io-kit/mcp` 0.3.0) running as one Lambda, `enceladus-mcp-signin-gamma` (production later: `enceladus-mcp-signin`), in us-west-2. It is the OAuth authorization server the MCP hosts will advertise: it serves `/.well-known/oauth-authorization-server`, `/register` (allow-listed callbacks only: claude.ai, claude.com, Cursor, loopback), `/authorize`, `/callback` and `/token`, and relays them to the Cognito hosted UI of pool `us-east-1_b2D0V3E1k` (classic prefix domain `enceladus-status-356364570033`) using one fixed public client.

**S57-a carries no traffic.** Nothing routes to the Function URL; `mcp.jreese.net` and `mcp-gamma.jreese.net` behave exactly as before.

## Parts

| Part | Where |
| --- | --- |
| Service code, registry, build, tests, ship script | `backend/lambda/mcp_signin/` |
| Lambda, role, log group, alias `live`, Function URL | `infrastructure/cloudformation/12-mcp-signin.yaml` (us-west-2, stack `enceladus-mcp-signin-gamma`) |
| Cognito public client | `infrastructure/cloudformation/13-mcp-signin-client.yaml` (us-east-1, stack `enceladus-mcp-signin-client-gamma`) |

The client is a separate stack because a us-west-2 stack cannot create a client in a us-east-1 pool. The client id reaches the function as a stack parameter (`CognitoClientId`) fed from the client stack's `ClientId` output; it is never hard-coded. The client is public (no secret), code flow, scopes openid email profile, `ALLOW_REFRESH_TOKEN_AUTH` only, revocation on, callback exactly `https://mcp-gamma.jreese.net/callback`, 60 minute access/ID tokens, 30 day refresh.

The fleet registry (`fleet.enceladus.json`: the `enceladus` profile and the two connectors) is shipped inside the zip as `fleet.json`, because kit 0.3.0 ships none. Override at build time with `IO_KIT_FLEET_JSON` (inline) or `IO_KIT_FLEET_FILE`. The service signs in only the connectors on its own origin (`sign_in_service: self`).

## Profile guard (F-12)

`tools/check_mcp_signin_client.py` statically checks `13-mcp-signin-client.yaml` and runs in CI (`.github/workflows/mcp-signin-client-guard.yml`, with a self-test that proves it fails on each weakening) on every pull request that touches the template, the tool or the workflow. It enforces: `ExplicitAuthFlows` is exactly `ALLOW_REFRESH_TOKEN_AUTH` (and never `ALLOW_USER_AUTH`, `ALLOW_USER_PASSWORD_AUTH`, `ALLOW_ADMIN_USER_PASSWORD_AUTH` or `ALLOW_CUSTOM_AUTH`); no secret (`GenerateSecret: false`); authorization-code flow only with `AllowedOAuthFlowsUserPoolClient: true`; identity provider `COGNITO` only; scopes within openid, email, profile; every callback (both branches of the environment `!If`) exactly `https://mcp.jreese.net/callback` or `https://mcp-gamma.jreese.net/callback`; and token revocation on. The check reads the template from the working tree only: no AWS credentials, no network. Changing the profile on purpose means changing the guard in the same pull request, which review then sees.

## Before the function can start: the state key (out of band)

The function reads an HMAC key from SSM SecureString `/enceladus/mcp-signin/state-key` (us-west-2, default `alias/aws/ssm` key) once per cold start. The stack never creates, reads or prints it. Create it once, without echoing it:

```bash
AWS_PROFILE=product-lead aws ssm put-parameter --region us-west-2 --type SecureString \
  --name /enceladus/mcp-signin/state-key --value "$(openssl rand -base64 48)"
```

Until it exists every request fails closed (HTTP 500). Rotating it invalidates in-flight sign-ins (state lives 10 minutes) and nothing else. Production should use its own parameter (`StateKeyParameterName`).

## Deploy (human-run; no deploy workflow is wired)

1. us-east-1: deploy `13-mcp-signin-client.yaml` with `EnvironmentSuffix=-gamma`; read the `ClientId` output.
2. us-west-2: deploy `12-mcp-signin.yaml` with `EnvironmentSuffix=-gamma CognitoClientId=<ClientId>`. The CloudFormation deploy role needs `lambda:CreateFunctionUrlConfig` on `enceladus-mcp-signin-gamma` first (see below); `product-lead` can deploy it directly.
3. Create the state key (above).
4. `bash backend/lambda/mcp_signin/ship.sh` builds, updates the code, publishes a version, moves `live`, smokes the Function URL directly and moves `live` back if the smoke fails.

## Same-origin routing (a later step)

The hosts advertise themselves as their own authorization server (`sign_in_service: self`). A later step adds CloudFront behaviors on each MCP distribution that route `/.well-known/oauth-authorization-server*`, `/register`, `/authorize`, `/callback` and `/token` to this Function URL (origin request policy `AllViewerExceptHostHeader`, caching disabled). Until then the only caller is `ship.sh`.

## Roll back

- Code: `aws lambda update-alias --region us-west-2 --function-name enceladus-mcp-signin-gamma --name live --function-version <previous>` (`ship.sh` prints it).
- Everything: delete stack `enceladus-mcp-signin-gamma`, then `enceladus-mcp-signin-client-gamma`. With no routing in place nothing depends on either.
