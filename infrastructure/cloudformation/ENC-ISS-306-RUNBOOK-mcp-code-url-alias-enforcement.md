# ENC-ISS-306 Runbook — enforce the Sev1-safe alias-qualified Function URL for prod MCP (`enceladus-mcp-code`)

**Task:** ENC-TSK-I24 · **Issue:** ENC-ISS-306 (P0) · **Operator:** io-dev-admin (privileged) · **Region:** us-west-2 · **Account:** 356364570033

> **Agent guardrail:** the dispatched `enceladus-agent-cli` session authored this and must NOT execute any
> `update-function-code` / `$LATEST` push or any Lambda/CloudFront mutation. Every step below is privileged
> (`io-dev-admin`). Reads in this runbook were already performed read-only by the agent during LSN-056 verification.

## Verified live state (LSN-056, captured 2026-06-26)

| | value |
|---|---|
| Function | `enceladus-mcp-code` (py3.11, role `devops-coordination-api-lambda-role`; code is manually deployed to `$LATEST`) |
| **Unqualified** Function URL (→ `$LATEST`) | `https://bufpvmgszu74jbwargzklit7ui0yfvdl.lambda-url.us-west-2.on.aws/` (AuthType NONE) |
| **Qualified `live`** Function URL (→ alias `live`) | `https://udal3ytbj4ndsxre3yq26qnfoa0jxnaq.lambda-url.us-west-2.on.aws/` (AuthType NONE, same Cors) — **already exists** |
| Alias `live` | exists → version 5 (RoutingConfig `AdditionalVersionWeights {4: 1.0}`) — operationally managed |
| CloudFront | `E3IRO1VSMFENCC` (alias `mcp.jreese.net`), origin id `enceladus-mcp-code-furl`, **origin currently = the unqualified URL** ← the Sev1 vector |

**Root cause:** CloudFront serves `mcp.jreese.net` from the **unqualified** URL, so any `update-function-code`
to `$LATEST` is an instant prod traffic switch (the 2026-04-25 Sev1). The qualified `live` URL already isolates
traffic onto the alias — CloudFront just isn't pointed at it.

## Design notes (why this shape)

- **`Qualifier` is `createOnly`** on `AWS::Lambda::Url` — you cannot "set Qualifier=live" on the existing URL.
  Qualified and unqualified URLs are distinct resources/domains. The qualified one already exists; the fix is to
  **repoint CloudFront** to it and **delete the unqualified** one (removes the `$LATEST` public surface entirely).
- **The `live` alias is intentionally NOT codified in CFN.** `AWS::Lambda::Alias` requires `FunctionVersion`,
  which ops moves on every mcp-code promotion; a CFN-pinned version would revert prod to a stale version on the
  next compute deploy (the ENC-ISS-313 / PLN-047 CFN-stomp class). The imported `Url` references the alias by
  name (`live`); the alias stays operationally managed.
- **The functions are NOT imported** (Gen2/manual code lifecycle + plaintext secrets in env). Out of scope per
  the agreed smallest-correct-blast-radius decision.
- **Residual (out of scope, separate coord follow-up):** CloudFront origin *selection* stays out-of-band, so a
  deliberate multi-step manual repoint to a newly-created unqualified URL is still possible. That is a weak,
  intentional risk — NOT the Sev1 — tracked by the CloudFront-distribution codification follow-up.

---

## Phase A — Sev1 mitigation (pure ops; independent of the PR merge)

### A0. Pre-flight — confirm the qualified URL is healthy before repointing
Verify the qualified `live` URL serves equivalently to the current origin (MCP client handshake, or the OAuth
metadata path, or `connection_health` through it). Do not proceed if it does not serve.
```bash
aws lambda get-function-url-config --function-name enceladus-mcp-code --qualifier live --region us-west-2
# spot-check the endpoint responds (expect the same behavior as mcp.jreese.net today)
curl -sS -o /dev/null -w '%{http_code}\n' https://udal3ytbj4ndsxre3yq26qnfoa0jxnaq.lambda-url.us-west-2.on.aws/
```

### A1. Repoint the CloudFront origin → qualified `live` URL
```bash
aws cloudfront get-distribution-config --id E3IRO1VSMFENCC > /tmp/e3iro.json
ETAG=$(python3 -c "import json;print(json.load(open('/tmp/e3iro.json'))['ETag'])")
# In DistributionConfig.Origins.Items[ id == enceladus-mcp-code-furl ], set:
#   DomainName: udal3ytbj4ndsxre3yq26qnfoa0jxnaq.lambda-url.us-west-2.on.aws
# (change ONLY DomainName; leave OriginId, OAC, custom-origin settings, cache behaviors untouched)
python3 - <<'PY'
import json
d=json.load(open('/tmp/e3iro.json'))['DistributionConfig']
for o in d['Origins']['Items']:
    if o['Id']=='enceladus-mcp-code-furl':
        o['DomainName']='udal3ytbj4ndsxre3yq26qnfoa0jxnaq.lambda-url.us-west-2.on.aws'
json.dump(d, open('/tmp/e3iro-new.json','w'))
PY
aws cloudfront update-distribution --id E3IRO1VSMFENCC --distribution-config file:///tmp/e3iro-new.json --if-match "$ETAG"
aws cloudfront create-invalidation --id E3IRO1VSMFENCC --paths '/*'
# wait for Status=Deployed, then verify mcp.jreese.net serves via the live alias
aws cloudfront get-distribution --id E3IRO1VSMFENCC --query 'Distribution.Status'
```
**Verify:** `mcp.jreese.net` behaves identically (MCP handshake / `connection_health`). This already closes the
Sev1 — prod now follows the `live` alias, not `$LATEST`.

### A2. Delete the unqualified Function URL (remove the `$LATEST` public surface)
```bash
# removes ONLY the unqualified URL; the qualified `live` URL is untouched
aws lambda delete-function-url-config --function-name enceladus-mcp-code --region us-west-2
# confirm the unqualified URL is gone and the qualified one remains
aws lambda get-function-url-config --function-name enceladus-mcp-code --region us-west-2 2>&1 | grep -q ResourceNotFound && echo "unqualified URL deleted ✓"
aws lambda get-function-url-config --function-name enceladus-mcp-code --qualifier live --region us-west-2 --query FunctionUrl
```

---

## Phase B — Codification (requires ENC-TSK-I24 PR merged to `main`)

> **Import-first invariant.** After merge, `02-compute.yaml` on `main` declares `EnceladusMcpCodeLiveFunctionUrl`,
> but the physical URL exists out-of-band. The ENC-ISS-386 orphan guard only scans `AWS::Lambda::Function`, so it
> will NOT pre-catch this — a *normal* `enceladus-compute` deploy (including the merge-auto-triggered one) fails
> **closed** at `AWS::EarlyValidation::ResourceExistenceCheck` (change-set creation rejected; **non-destructive**,
> no stack mutation). Run the IMPORT (B1) before any normal compute deploy.

### B1. IMPORT the qualified URL into `enceladus-compute` (non-destructive, Retain)
```bash
# template = the merged 02-compute.yaml from main (upload to S3 or pass --template-body)
aws cloudformation create-change-set \
  --change-set-type IMPORT \
  --stack-name enceladus-compute \
  --change-set-name i24-import-iss306-mcp-code-url \
  --resources-to-import file://infrastructure/cloudformation/resource-import-mcp-code-url-iss306.json \
  --template-url <s3 url of merged 02-compute.yaml> \
  --parameters <all current stack params as UsePreviousValue=true> \
  --capabilities CAPABILITY_NAMED_IAM
# REVIEW: the change set must show EXACTLY ONE row — Action=Import, EnceladusMcpCodeLiveFunctionUrl — and nothing else
aws cloudformation describe-change-set --stack-name enceladus-compute --change-set-name i24-import-iss306-mcp-code-url \
  --query 'Changes[].{Action:ResourceChange.Action,Logical:ResourceChange.LogicalResourceId}'
aws cloudformation execute-change-set --stack-name enceladus-compute --change-set-name i24-import-iss306-mcp-code-url
# -> IMPORT_COMPLETE ; the qualified URL is now stack-managed with the SAME physical resource (no recreation)
```

### B2. Clean deploy proof (ISS-306 AC-4)
Run the sanctioned compute-stack deploy from `main`. Expect `UPDATE_COMPLETE`, **no** `ResourceAlreadyExists`,
**no** Add/Modify/Remove on `EnceladusMcpCodeLiveFunctionUrl` (it is now adopted). Confirm the live qualified URL
domain is unchanged (`udal3ytb...`) so CloudFront origin stays valid.

### B3. IaC-sourced validation (ISS-306 AC-2) — `$LATEST` cannot reach prod
With the IaC-managed state in place:
```bash
# push a deliberately-broken bundle to $LATEST ONLY (never to the alias)
aws lambda update-function-code --function-name enceladus-mcp-code --zip-file fileb://broken.zip --region us-west-2
# EXPECT: mcp.jreese.net STILL serves good responses (it follows the qualified live URL -> alias -> published version;
#         $LATEST has no public URL at all after Phase A2). Verify via MCP handshake / connection_health.
# ROLL BACK $LATEST to the last-good bundle:
aws lambda update-function-code --function-name enceladus-mcp-code --zip-file fileb://last-good.zip --region us-west-2
```

### B4. LSN-056 re-probe + AC-3 audit
- **LSN-056:** behavioral probe of `mcp.jreese.net` identical before vs after the whole sequence.
- **AC-3 (other prod Function-URL-backed Lambdas):** audit complete — the only `jreese.net` prod MCP Function URL is
  mcp-code (fixed here); `mcp-gamma.jreese.net` is a separate gamma env; `enceladus-mcp-streamable` is **dormant**
  (no log group; 2 invocations/14d; not CloudFront-fronted) and is carried as a cross-linked follow-up issue (it
  must receive the same `Qualifier=live` protection BEFORE it is ever re-fronted). Other `lambda-url` CloudFront
  distributions are unrelated tenants.

---

## Report back to ENC-TSK-I24 / ENC-ISS-306
Provide for evidence stamping: CloudFront update-distribution result + `Deployed` status; delete-function-url-config
confirmation; the IMPORT change-set review (1×Import) + `IMPORT_COMPLETE`; the clean-deploy run id/result; the B3
broken-`$LATEST` validation result (mcp.jreese.net stayed healthy) + rollback confirmation; the LSN-056 before/after
probe. ISS-306 closes on AC-0..4 once B3 (IaC-sourced validation) passes.

## Abort / rollback
- If A0 shows the qualified URL unhealthy: STOP; do not repoint.
- If after A1 `mcp.jreese.net` degrades: revert the CloudFront origin DomainName to `bufpvmgszu...` (re-run A1 with
  the old domain + current ETag) and invalidate; the unqualified URL still exists until A2.
- Do A2 (delete unqualified URL) only AFTER A1 is verified healthy — it is the point of no easy return for the
  unqualified URL (it would have to be recreated, yielding a new domain).
- B1/B2 are non-destructive (Import + Retain); a failed import change-set can be deleted with no stack impact.
