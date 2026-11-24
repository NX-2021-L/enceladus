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

## Not in this step

The sign-in behaviors (`/.well-known/oauth-authorization-server*`, `/register`, `/authorize`, `/callback`, `/token`) and the Function URL origin of `enceladus-mcp-signin-gamma` are the next step. They go in as an ordinary update to this template once the stack is `IMPORT_COMPLETE` and `IN_SYNC`; that update runs through a normal CloudFormation deploy, not the import workflow, whose assertion rejects anything but `Import`.
