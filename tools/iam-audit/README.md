# 02-compute IAM Role Policy Audit & Codification — ENC-TSK-G95 / ENC-ISS-313

**Date:** 2026-06-17 · **Account:** 356364570033 (prod) · **Region:** us-west-2
**Supersedes:** DOC-FBD770A9483B (April 2026 audit — invalidated because it predates the
`deploy.sh` tombstoning in ENC-TSK-G43, so its "zero functional gaps" conclusion no longer holds).

## Why this exists

The per-Lambda `deploy.sh` scripts used to apply IAM grants out-of-band via
`ensure_role()` (`aws iam put-role-policy`). When they were tombstoned for the GitHub
Actions matrix build (ENC-TSK-G43), those grants were never back-ported to
`infrastructure/cloudformation/02-compute.yaml`. The CFN template is therefore **not** the
source of truth for these roles. A future CFN operation that reconciles inline policies
would strip the live-only grants — a latent fleet-wide Sev1 (ENC-ISS-313).

## Method (all reproducible — see scripts in this dir)

1. `dump_live_iam.py product-lead` → `live-iam-dump-20260617.json` — live inline + attached
   policies for all 25 roles defined in 02-compute.yaml (run under `product-lead`/io-dev-admin;
   `product-lead-inspect` is denied `iam:ListRolePolicies`/`GetRolePolicy`). **AC-1.**
2. Gamma dump → `live-iam-dump-gamma-20260617.json` (the `enceladus-compute-gamma` stack is
   deployed; its roles are the dual-environment oracle).
3. `build_diff.py` → `cfn-vs-live-diff-20260617.md` — action-level CFN-vs-live diff. **AC-2.**
4. `codify_roles.py` → `codify-report-20260617.md` — parameterize each live statement
   (`356364570033`→`${AWS::AccountId}`, `us-west-2`→`${AWS::Region}`, `-gamma`→`${EnvironmentSuffix}`)
   and **prove** it resolves identically to prod-live (suffix `''`) AND gamma-live (suffix `-gamma`).
5. `splice_codify.py` — insert only **dual-env-proven** statements as a `G95RestoredGrants`
   inline policy per role. **AC-4** (additive-only: 599 insertions, 0 deletions vs origin/main).
6. `cfn-vs-live-diff-POST-codify.md` — re-run diff confirming the proven actions are now covered.

## Findings

**Drift is far broader than ENC-ISS-313's stated minimum** (which named ~5 grants on 2 graph
roles): **20 of 25 roles** had live IAM actions absent from CFN — most of the fleet's real
DynamoDB / S3 / Logs / SNS / Bedrock-agent / Cognito permissions existed only in
`deploy.sh`-applied inline policies. Several roles also carry out-of-band *attached managed*
policies not modelled in CFN.

### Codified in this PR (dual-env proven)
- **GraphSyncRole** — `SecretsManagerNeo4j` + `BedrockTitanV2InvokeModel` (hand-codified; the ISS-313 core).
- **GraphQueryApiRole** — `CloudWatchLogs` + `SecretsManagerNeo4j` (Bedrock already added by merged ENC-TSK-G94).
- **10 roles via `G95RestoredGrants`:** CoordinationApi (22 stmts), DocumentApi (7), DeployIntake (6),
  DeployOrchestrator (6), BedrockActions (9), ProjectService (3), ChangelogApi (3), CoordinationMonitor (2),
  ReferenceSearch (2), TrackerMutation (1).

### Residual — needs human codification (NOT machine-emitted, intentionally)
These reference prod-specific or gamma-divergent resources where blind parameterization would
risk the live gamma stack. Each must be codified by hand with the correct env handling
(likely a CFN `Condition` or mapping):

| Role | Missing | Why deferred |
|---|---|---|
| FeedPublisherRole | dynamodb, s3, sns:publish, events:PutEvents, cloudfront:CreateInvalidation | prod-only policy (gamma role lacks it); prod CloudFront distro `E2BOQXCW1TA6Y4` |
| DeployFinalizeRole | dynamodb, logs, s3:putobject | gamma role has **no** inline policies |
| DocPrepRole | dynamodb, logs, s3:getobject | gamma role has **no** inline policies |
| AuthRefreshRole | cognito-idp:InitiateAuth | `us-east-1` user pool `us-east-1_b2D0V3E1k` (cross-region, prod-specific) |
| FeedQueryRole | dynamodb read | gamma role lacks the dynamodb-read policy |
| GovernanceAuditRole | sns:publish | prod-only `devops-project-json-sync` topic grant |
| ProjectServiceRole | s3:deleteobject/putobject | anomalous live resource `jreese-net/gamma/mobile/...` on the **prod** role — verify intent |
| CoordinationApiRole | lambda:InvokeFunction | `InvokeBedrockActionLambda` target ARN diverges from gamma |
| FeedPipeRole / GraphPipeRole | sqs:GetQueueAttributes | low-risk; pipe target queue — codify alongside the import work |

## Deploy mechanics — IMPORTANT (re-frames AC-5/AC-7/AC-10)

- The prod CloudFormation stack **`enceladus-compute` does not exist** (only `enceladus-compute-gamma`).
  Confirms ENC-ISS-174. The prod roles exist live, created by `deploy.sh`, under **no** stack.
- Therefore `aws cloudformation deploy` against prod is a **CREATE**, which would (a) fail
  `EntityAlreadyExists` on the fixed `RoleName`s already live, and (b) risk stomping live Lambda
  code via the template's placeholder `ZipFile`. **It is not a safe additive update.**
- The safe path to bring the pre-existing fleet under CFN is a **resource import**
  (`create-change-set --change-set-type IMPORT`), scoped and reviewed, run under the
  `product-lead` terminal — `iam:CreateRole` is denied to the GHA deploy role (ENC-ISS-252).
- **Landmine:** `.github/workflows/cloudformation-compute-stack-deploy.yml` triggers on push to
  `main` for this path. **Merging this PR would auto-trigger the (currently-failing) prod compute
  deploy.** Do not merge until the import strategy is in place / the workflow is guarded.

## Idempotency validation (AC-5)

A literal `aws cloudformation deploy --no-execute-changeset` cannot be validly produced for prod
(no stack exists; a CREATE changeset would show every resource as Add and is not idempotency-meaningful).
The idempotency guarantee provided here is **logical and stronger**: the post-codify diff proves
CFN ⊇ live for every codified statement (no live grant is dropped) and the change is additive-only
(0 deletions). The prescribed execution-time validation is an IMPORT change-set scoped to the IAM
roles, reviewed under `product-lead`, documented as the supervised next step.
