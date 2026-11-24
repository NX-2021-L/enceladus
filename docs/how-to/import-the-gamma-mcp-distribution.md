# How to import the gamma MCP CloudFront distribution into CloudFormation (ENC-TSK-S57-b)

The distribution `E2KVDHFSQ5G5VE` (alias `mcp-gamma.jreese.net`) was created out of band. `infrastructure/cloudformation/14-mcp-edge-gamma.yaml` reproduces its live configuration exactly, and `resource-import-mcp-edge-gamma.json` names it for a change-set IMPORT into the new stack `enceladus-mcp-edge-gamma`. The import adopts the distribution and changes nothing about it. Production (`E3IRO1VSMFENCC`) is not part of this and must not be.

## What the template does and does not carry

One `AWS::CloudFront::Distribution`, `McpEdgeDistribution`, with `DeletionPolicy: Retain` and `UpdateReplacePolicy: Retain`. It holds both origins, the default behavior (to the Function URL, with the Lambda@Edge origin-response association) and `/api/*`, the alias and ACM certificate, and the scalar settings. The five parameters default to the live values (two origin hosts, certificate ARN, Lambda@Edge version ARN, and the gamma-only `EnvironmentSuffix`); keep the defaults for the import.

It omits only live values that mean "unset", plus fields CloudFormation does not model: `CallerReference`, `GrpcConfig`, empty `DefaultRootObject`, `WebACLId`, `ContinuousDeploymentPolicyId`, `OriginPath`, `OriginAccessControlId`, `FieldLevelEncryptionId`, zero-length custom headers, signers, key groups, function associations, error responses and origin groups, and disabled `Logging`. There are no tags live, so the template has none. Do not edit values before the import: any change makes the next change-set a Modify.

## Prerequisites

1. `14-mcp-edge-gamma.yaml` and the manifest are on `v4/main` (or on a branch pushed to origin, see `source_ref`).
2. The live distribution is unchanged since the template was written (ETag `EN1VRQENFRJN5` on 2026-11-24): `aws cloudfront get-distribution-config --id E2KVDHFSQ5G5VE --query ETag`. If the ETag moved, re-diff the live config against the template before dispatching.
3. Nothing else is queued against `v4-gamma`; the workflow serialises per stack name.

## Dispatch (preview first, then the import)

Workflow: `.github/workflows/cfn-resource-import.yml` ("CFN Resource Import / Recovery"). The `import` job's environment is `v4-gamma` because the stack name contains `-gamma` (no reviewer gate).

**Dispatch ref.** It must be `v4/main` (or `main`): the job refuses any other ref, and the CloudFormation role's OIDC trust allows only `refs/heads/main`, `refs/heads/v4/*` and the environments `v4-gamma` and `v3-prod`. `v4/main` carries the gamma plane, so use it.

| Input | Value |
| --- | --- |
| `mode` | `import` |
| `stack_name` | `enceladus-mcp-edge-gamma` |
| `template_file` | `infrastructure/cloudformation/14-mcp-edge-gamma.yaml` |
| `manifest_file` | `infrastructure/cloudformation/resource-import-mcp-edge-gamma.json` |
| `parameter_overrides` | blank (a new stack has no previous values; the template defaults are the live values) |
| `capabilities` | leave the default (the template creates no IAM; the capabilities are harmless) |
| `preview_only` | `true` for the first run, then `false` |
| `source_ref` | **blank** once the files are on `v4/main`. The default is `agent/enc-tsk-j13-import-staged`, an old branch; left alone it is checked out too, and files are taken from it only if they exist there, so blank is the safe value. Before the merge, set it to the pushed branch `agent/enc-tsk-s57-b-gamma-cdn-import` and dispatch with `--ref v4/main`. |
| `reason` | for example `ENC-TSK-S57-b: import gamma MCP distribution E2KVDHFSQ5G5VE, zero diff` |

```bash
gh workflow run cfn-resource-import.yml --ref v4/main \
  -f mode=import -f stack_name=enceladus-mcp-edge-gamma \
  -f template_file=infrastructure/cloudformation/14-mcp-edge-gamma.yaml \
  -f manifest_file=infrastructure/cloudformation/resource-import-mcp-edge-gamma.json \
  -f preview_only=true -f source_ref= -f reason="ENC-TSK-S57-b preview"
```

What the run does: it checks the dispatch ref, assumes the CloudFormation role, uploads the template to `s3://enceladus-cfn-staging-us-west-2/imports/enceladus-mcp-edge-gamma/`, creates an `IMPORT` change-set (this creates the stack in `REVIEW_IN_PROGRESS` because it does not exist yet), and runs `tools/assert_changeset_safe.py --mode import`, which fails the run unless the change-set holds only `Import` actions: exactly one, `AWS::CloudFront::Distribution McpEdgeDistribution`. Then `tools/pre-deploy-health-gate.sh` runs (checks 1 to 6 and 9 pass for this template; check 7 is skipped by design; check 8 warns "inconclusive" because the stack does not exist yet, which is not a failure). A preview run deletes the change-set and does not execute it. The stack stays in `REVIEW_IN_PROGRESS` after a preview; the real run re-uses it.

Run it again with `preview_only=false` to execute. It then waits for `IMPORT_COMPLETE` and prints the resource counts (expect one `AWS::CloudFront::Distribution`).

The region is fixed at us-west-2 in the workflow, so the stack lives there like `07-ui-cdn.yaml` and `12-mcp-signin.yaml`. CloudFront is global, so this does not change the distribution; the Lambda@Edge version and the ACM certificate stay us-east-1 ARNs, as CloudFront requires.

## The role and what it can do

The job assumes the secret `AWS_CLOUDFORMATION_ROLE_TO_ASSUME`, the role `enceladus-cloudformation-deploy-github-role` (`CloudFormationDeployRole` in `04-github-roles.yaml`). Checked live on 2026-11-24 (role policies read, plus `iam simulate-principal-policy` on the role):

| Need | Result |
| --- | --- |
| OIDC trust from `v4/main` and from the `v4-gamma` environment | allowed |
| `cloudformation:CreateChangeSet`, `DescribeChangeSet`, `ExecuteChangeSet`, `DeleteChangeSet`, `DescribeStacks`, `ListStackResources`, `DeleteStack` on `stack/enceladus-*/*` in us-west-2 | allowed (inline `CloudFormationStackOps`); the new stack name matches `enceladus-*` |
| `cloudfront:GetDistribution`, `GetDistributionConfig`, `UpdateDistribution`, `TagResource`, `ListTagsForResource`, `DeleteDistribution` on `*` | allowed (attached `enceladus-ui-cdn-deploy`, `UiCdnDeployPolicy` in `04-github-roles.yaml`) |
| `s3:PutObject` to the staging bucket path | allowed |
| `cloudformation:DetectStackDrift` | **not granted** (implicit deny) |

So the role can perform the import. This was verified by reading the live policies and simulating them; it was not verified by running the import. The workflow needs no change for the import. The one gap is drift detection: the role cannot call `detect-stack-drift`, and the workflow has no drift step, so run the check as an operator (below).

## Verify: zero drift

After the import run (as `product-lead`, or any identity that may call it):

```bash
aws cloudformation describe-stacks --region us-west-2 --stack-name enceladus-mcp-edge-gamma --query 'Stacks[0].StackStatus'   # IMPORT_COMPLETE
id=$(aws cloudformation detect-stack-drift --region us-west-2 --stack-name enceladus-mcp-edge-gamma --query StackDriftDetectionId --output text)
aws cloudformation describe-stack-drift-detection-status --region us-west-2 --stack-drift-detection-id "$id"   # wait for DETECTION_COMPLETE
aws cloudformation describe-stack-resource-drifts --region us-west-2 --stack-name enceladus-mcp-edge-gamma     # expect IN_SYNC
aws cloudfront get-distribution-config --id E2KVDHFSQ5G5VE --query ETag --output text                          # expect EN1VRQENFRJN5, unchanged
```

`IN_SYNC` is the pass. If the resource shows `MODIFIED`, read the property differences before doing anything else: the import itself changed nothing, so the difference is a template property that disagrees with the live value, and the fix is a template edit followed by a normal update. `mcp-gamma.jreese.net` must keep answering throughout.

## Roll back

Deleting the stack is safe: `DeletionPolicy: Retain` leaves the distribution alone.

```bash
aws cloudformation delete-stack --region us-west-2 --stack-name enceladus-mcp-edge-gamma
```

A failed or preview-only run needs nothing beyond that (a preview leaves an empty `REVIEW_IN_PROGRESS` stack, which can be deleted the same way). Confirm afterwards that `E2KVDHFSQ5G5VE` still exists and is `Deployed`.

## Next step (ENC-TSK-S57-d): add the sign-in origin and five behaviors (stack UPDATE)

`14-mcp-edge-gamma.yaml` now also carries the origin `enceladus-mcp-signin-gamma-furl` (Function URL of `enceladus-mcp-signin-gamma`, alias `live`; new parameter `SigninFunctionUrlOriginDomainName`, default `3rnsgocycmgl3hs37gqzpcw33q0ckhws.lambda-url.us-west-2.on.aws`, from stack output `FunctionUrl`), and five behaviors routed to it, placed after `/api/*`:

| Pattern | Serves |
| --- | --- |
| `/.well-known/oauth-authorization-server*` | authorization-server metadata, with or without a `/...` suffix |
| `/register` | `POST` dynamic client registration |
| `/authorize` | `GET`, redirects to Cognito |
| `/callback` | `GET`, returns from Cognito |
| `/token` | `POST` code exchange |

All five use `redirect-to-https`, the seven methods of the existing behaviors, `CachingDisabled` (`4135ea2d-...`), `AllViewerExceptHostHeader` (`b689b0a8-...`, so query string, `Origin` and `Content-Type` reach the service and `Host` does not), `Compress: true` (as the default behavior) and no Lambda@Edge (the 401-header function stays on the default behavior only). The origin has the same https-only, TLSv1.2, 30 s read, 5 s keep-alive, 3 attempts and 10 s connect settings as `enceladus-mcp-gamma-furl`. The template also gains an `Outputs` section (`DistributionId`, `DistributionDomainName`; no exports): an UPDATE may add outputs, they read from the resource and change nothing live.

Path patterns are anchored and evaluated in list order. None of the five can match `/oauth/token`, `/oauth/register`, `/.well-known/oauth-protected-resource*`, `/`, `/mcp` or `/api/*` (checked with a glob matcher over those paths and `/register/`, `/mcp/token`: no hit). Everything else, including the default behavior, `/api/*`, the aliases and the certificate, is unchanged. Production (`E3IRO1VSMFENCC`) is not touched.

### What the change-set must show

Exactly one change: `Modify AWS::CloudFront::Distribution McpEdgeDistribution`, `Replacement: False`. No Add, Remove, Replace or Dynamic. A rendered-versus-live comparison (template defaults substituted, compared with `aws cloudfront get-distribution-config --id E2KVDHFSQ5G5VE`) showed zero value differences and exactly these additions: one origin and five behaviors.

### Which workflow applies it, and the gap

`.github/workflows/cfn-resource-import.yml` (dispatch ref `v4/main` or `main`; environment `v4-gamma` for a stack name containing `-gamma`, no reviewer) is the only workflow that can run an UPDATE against an arbitrary stack name and template path. Every other stack-deploy workflow (`cloudformation-ui-cdn-stack-deploy.yml`, `-compute-`, `-api-`, `-monitoring-` and the rest) has its own template hard-wired and none names `14-mcp-edge-gamma.yaml` or `enceladus-mcp-edge-gamma`; there is no stack allow-list in the import workflow.

| Mode and inputs | Change-set type | Assertion | Applies a Modify? |
| --- | --- | --- | --- |
| `import`, manifest required | `IMPORT` | `--mode import`: Import only | no, any Modify aborts |
| `monitoring-recover`, **manifest blank** | `UPDATE` | `--mode recover`: Add and in-place Modify allowed; Remove, Replace, Conditional and Dynamic refused | yes |
| `monitoring-create`, manifest blank | `CREATE` | `--mode create`: same rules | no, the stack exists |

So the route is `mode=monitoring-recover`, `stack_name=enceladus-mcp-edge-gamma`, `template_file=infrastructure/cloudformation/14-mcp-edge-gamma.yaml`, `manifest_file` blank, `parameter_overrides` blank (the five stored parameters are re-used with `UsePreviousValue`; the new parameter takes its default, which is the live value), `source_ref` blank once the file is on `v4/main` (or the pushed branch before then), dispatched with `--ref v4/main`. `preview_only=true` is the plan-only run: it creates the change-set, runs the assertion and the health gate, deletes the change-set and executes nothing. `preview_only=false` executes it. There is no separate approval gate for a `-gamma` stack.

```bash
gh workflow run cfn-resource-import.yml --ref v4/main \
  -f mode=monitoring-recover -f stack_name=enceladus-mcp-edge-gamma \
  -f template_file=infrastructure/cloudformation/14-mcp-edge-gamma.yaml \
  -f manifest_file= -f parameter_overrides= -f source_ref= \
  -f preview_only=true -f reason="ENC-TSK-S57-d preview: gamma sign-in origin and behaviors"
```

**This does not work as-is today.** In `recover` mode the workflow does not set `HEALTH_GATE_SKIP_DRIFT`, so `tools/pre-deploy-health-gate.sh` Check 7 (`audit_cfn_drift.py --environment gamma --fail-on-drift --pre-deploy`) runs and fails the job before the change-set can execute. Run locally on 2026-11-24 against live gamma, it reports one live-only API route unrelated to this stack, `GET /api/v1/feed/plan-scope` (declared in no template on this branch or on `origin/v4/main`), and the gate ends `FAILED (1 errors)`. The other checks pass for this template: Check 8 reports `MODIFY 1 / REMOVE 0 / CREATE 0`, Checks 5, 6 and 9 pass. So the preview run fails closed until that route is adopted into a template or removed, or the gate is told to skip Check 7 for this stack.

Smallest workflow change that would make it work (a separate PR, not part of this one): add a `modify` assertion mode and a `modify` option to the workflow, so the unrelated drift check is skipped the way it is for imports and the assertion is stricter than `recover`:

1. `tools/assert_changeset_safe.py`: accept `--mode modify`, where every change must be `Action=Modify` with `Replacement=False` (no Add, no Import), plus a self-check case.
2. `cfn-resource-import.yml`: add `modify` to the `mode` choices, and in "Resolve operation parameters" add `modify) cst="UPDATE"; assert_mode="modify"; skip_drift="1" ;;`, requiring a blank manifest.

That keeps a gamma-only, Modify-only, replacement-refusing path with the existing preview/execute split. Until it lands, either fix the unrelated drift first (then `monitoring-recover` works unchanged) or use the fallback.

**One more risk, not verified by running it.** The CloudFormation deploy role has `cloudfront:UpdateDistribution` and `lambda:GetFunction` but `iam simulate-principal-policy` gives an implicit deny for `lambda:EnableReplication` on `enceladus-mcp-edge-401-header:1`. CloudFront checks the caller's permission to associate a Lambda@Edge version when it validates an update, and the default behavior keeps that association. If the update fails with a permission error naming the Lambda@Edge function, the role needs an io-gated grant (the repo's `iam-cfn-deploy-role-*-patch.yml` pattern) or the fallback below applies. A failed update rolls back and leaves the distribution as it was.

### Fallback: hand-run change-set (needs io's explicit OK first)

The header of `cfn-resource-import.yml` forbids running `deploy` or `execute-change-set` from an agent terminal. These commands are for a human with `product-lead`, or for an agent only after io says so in chat. Save the live config first; it is the emergency rollback.

```bash
export AWS_PROFILE=product-lead AWS_REGION=us-west-2
STACK=enceladus-mcp-edge-gamma; CS=s57d-signin-$(date -u +%Y%m%dT%H%M%SZ)
aws cloudfront get-distribution-config --id E2KVDHFSQ5G5VE > pre-s57d-distribution-config.json   # keep it
aws cloudformation create-change-set --region $AWS_REGION --stack-name $STACK --change-set-name $CS \
  --change-set-type UPDATE --template-body file://infrastructure/cloudformation/14-mcp-edge-gamma.yaml \
  --parameters ParameterKey=EnvironmentSuffix,UsePreviousValue=true ParameterKey=FunctionUrlOriginDomainName,UsePreviousValue=true \
    ParameterKey=ApiOriginDomainName,UsePreviousValue=true ParameterKey=AcmCertificateArn,UsePreviousValue=true \
    ParameterKey=EdgeFunctionVersionArn,UsePreviousValue=true
aws cloudformation wait change-set-create-complete --region $AWS_REGION --stack-name $STACK --change-set-name $CS
aws cloudformation describe-change-set --region $AWS_REGION --stack-name $STACK --change-set-name $CS --output json > cs.json
python3 tools/assert_changeset_safe.py --changeset-json cs.json --mode recover   # and read it: one Modify, Replacement False
aws cloudformation execute-change-set --region $AWS_REGION --stack-name $STACK --change-set-name $CS
aws cloudformation wait stack-update-complete --region $AWS_REGION --stack-name $STACK
aws cloudfront get-distribution --id E2KVDHFSQ5G5VE --query 'Distribution.Status' --output text   # InProgress, then Deployed
```

`create-change-set` never executes; stop after `describe-change-set` for a plan-only run. Stop and delete the change-set (`aws cloudformation delete-change-set ...`) if it shows anything but the single Modify.

### Verify after the update

```bash
aws cloudformation describe-stacks --region us-west-2 --stack-name enceladus-mcp-edge-gamma --query 'Stacks[0].[StackStatus,Outputs]'   # UPDATE_COMPLETE
aws cloudfront get-distribution --id E2KVDHFSQ5G5VE --query 'Distribution.Status' --output text                                       # Deployed
curl -s -o /dev/null -w '%{http_code}\n' https://mcp-gamma.jreese.net/.well-known/oauth-authorization-server                          # 200 from the sign-in service
curl -s https://mcp-gamma.jreese.net/.well-known/oauth-authorization-server | python3 -m json.tool | head                               # issuer, endpoints on mcp-gamma.jreese.net
curl -s -o /dev/null -w '%{http_code}\n' https://mcp-gamma.jreese.net/.well-known/oauth-protected-resource                            # unchanged, still the MCP server
```

Propagation takes a few minutes; `Status` stays `InProgress` until it finishes, and the old configuration keeps serving meanwhile.

### Roll back

Re-apply the previous template, which is the import template without the sign-in origin, behaviors and outputs. It has five parameters, not six, so the rollback must name the five explicitly: the workflow's blank-override default would pass `UsePreviousValue` for the new parameter, which CloudFormation rejects as not in the template.

```bash
git show 5b0907ab:infrastructure/cloudformation/14-mcp-edge-gamma.yaml > /tmp/14-mcp-edge-gamma.prev.yaml   # last revision before S57-d
```

Through the workflow: put that file at the template path on a `v4/*` branch (a revert of the S57-d commit does exactly that) and dispatch `mode=monitoring-recover` as above with `parameter_overrides="EnvironmentSuffix=-gamma FunctionUrlOriginDomainName=fby2jguax4ymmqnfwj3t5whyei0zbhfx.lambda-url.us-west-2.on.aws ApiOriginDomainName=hi0dzmvqrc.execute-api.us-west-2.amazonaws.com AcmCertificateArn=arn:aws:acm:us-east-1:356364570033:certificate/2fe2e1cc-cc0f-4d24-94d7-dba31a9ac47e EdgeFunctionVersionArn=arn:aws:lambda:us-east-1:356364570033:function:enceladus-mcp-edge-401-header:1"` (the same Check 7 gap applies). By hand, use the change-set commands above with that file and the five `UsePreviousValue` parameters. The result is one Modify that removes the origin and the five behaviors.

Emergency path, when CloudFormation itself is the problem: restore the saved pre-change configuration straight onto the distribution (this makes the stack drift from its template until the previous template is re-applied):

```bash
etag=$(aws cloudfront get-distribution-config --id E2KVDHFSQ5G5VE --query ETag --output text)
python3 -c "import json;print(json.dumps(json.load(open('pre-s57d-distribution-config.json'))['DistributionConfig']))" > restore.json
aws cloudfront update-distribution --id E2KVDHFSQ5G5VE --if-match "$etag" --distribution-config file://restore.json
```

CloudFront propagation is a few minutes either way. Neither path touches production or the Lambda functions; the sign-in service keeps running unrouted.
