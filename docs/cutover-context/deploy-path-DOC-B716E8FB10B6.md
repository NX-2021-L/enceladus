# DOC-B716E8FB10B6 v3-Prod Surgical Deploy Brief (io-gated, pre-cutover)

**Project**: enceladus
**Related**: DOC-499FA089EC30, ENC-PLN-006, ENC-PLN-020, ENC-ISS-455, ENC-TSK-J08, ENC-FTR-120
**Created**: 2026-07-01
**Updated**: 2026-07-02 (ENC-TSK-J66 — Channel A rewritten for the ENC-FTR-120 plan/apply environment gates)
**Author**: io

---

## Purpose

A standing, reusable roadmap for an agent to make ONE small, io-approved, surgical deploy to the frozen v3-prod stack, using only the normal git -> GitHub Actions path (no direct AWS writes). It exists because DOC-499FA089EC30 freezes v3-prod during the ENC-PLN-006 v4 migration, yet io occasionally needs a targeted prod fix before the v4 cutover. This brief is the narrow, per-invocation exception to that freeze.

Read this brief in full before acting on it. It does NOT unfreeze prod, does NOT authorize batch deploys, and does NOT authorize promoting PLN-006 v4 work to prod (the cutover is still io's separate, explicit decision per DOC-499FA089EC30).

## The Consent Protocol (READ FIRST)

io triggers a surgical v3-prod deploy by typing, in substance:

    deploy this task to v3 DOC-B716E8FB10B6

together with the target task id (e.g. ENC-TSK-NNN). **The presence of THIS brief's own document id (DOC-B716E8FB10B6) in that instruction is io's explicit, per-invocation consent** to run the process below for the single named task. The DOC id is the consent token; typing it = "I have read this brief and I authorize this specific v3-prod deploy."

Rules of consent:
- No DOC id, a different DOC id, or a mistyped id => NO v3 deploy. Do not infer consent. Treat the task as normal frozen/gamma work and ask io to re-issue with the token.
- Consent is scoped to exactly ONE task per command. It does not carry to other tasks, follow-ups, re-runs, or a second deploy of the same task later.
- Consent authorizes REACHING the deploy; every prod channel now also has its own reviewer gate (the v3-prod GitHub Environment) which is a SEPARATE, additional io action the agent still cannot self-satisfy.
- Consent never overrides the Standing Invariants below.

**Consent vs enforcement (ENC-FTR-120).** These are two independent layers and both are required. The DOC-id token is the AUTHORIZATION layer: it tells the agent that io wants this specific deploy attempted at all. The v3-prod GitHub Environment required-reviewer gate is the ENFORCEMENT layer: it structurally pauses every prod-mutating job as a reviewable, rejectable request that only io's approval click can execute. The token cannot bypass the gate, and an accidental gate approval does not substitute for the token. Before FTR-120 the CFN lane had only the token (procedure, not enforcement); that gap — "the merge IS the prod deploy" — is closed.

## Standing Invariants (hold even WITH consent)

- Agent identity is enceladus-agent-cli (read-only AWS). Every prod change goes through git merge -> GitHub Actions. NEVER run aws cloudformation deploy, aws lambda update-*, or aws dynamodb put-item directly. A direct CLI CFN deploy caused the ENC-TSK-1292 Sev1 (DOC-2CACF0D1E7E6).
- Before ANY prod CFN stack deploy, run tools/pre-deploy-health-gate.sh and require it to pass (ENC-PLN-020). A failing or skipped gate is a hard stop.
- NEVER a full-environment CFN replace and never let a deploy strip out-of-band env vars / inline policies (the PLN-047 / ENC-LSN-053 Sev1 class). Deploys must be incremental, minimal change-sets. Review the plan job's change-set summary before requesting io's approval.
- Re-verify the PROD MCP connector before any governed mutation: ToolSearch 045c9b27 and confirm connection_health graph_projection.configured=true (name gds_standing_enceladus). Gamma is test data.
- Surgical = the smallest diff that accomplishes the task. No opportunistic edits, no drive-by refactors, no unrelated file churn.
- main and v4/main are independent (sync disabled; DOC-499FA089EC30). Landing on one does not land on the other.

## Step 0 - Interpret and scope

1. Confirm the consent token (this brief's DOC id, DOC-B716E8FB10B6) is present in io's instruction; resolve the target task id.
2. Load the task; confirm it is real, in a workable state, and prod-appropriate (already validated on gamma where applicable, or inherently low blast radius).
3. Restate to io in one line what will deploy to v3 and by which channel (Step 1) before merging.

## Step 1 - Classify the change, pick the deploy channel

Decide by which files the task actually modifies:

- Channel A - CFN template (infrastructure/cloudformation/01-data.yaml, 02-compute.yaml, 03-api.yaml, 05-monitoring.yaml, 07-codedeploy.yaml): a push/merge to main fires the matching cloudformation-*-stack-deploy.yml, which since ENC-FTR-120 (ENC-TSK-J62/J63) is split into a PLAN job and an APPLY job. The plan job creates the change-set with `aws cloudformation deploy --no-execute-changeset` (parameter-reuse semantics preserved for the ENC-LSN-053 guards) and writes a resource-level change-set summary to the run's job summary. The apply job runs inside the v3-prod GitHub Environment and PAUSES on its required-reviewer rule — **the merge is no longer the prod deploy; it creates a paused, reviewable, rejectable change-set request, and io's approval click on the Environment is what executes it.** Review the change-set summary before asking io to approve. Run pre-deploy-health-gate first regardless. If the change would ADD or adopt a resource that already exists live out-of-band, change-set creation fails AWS::EarlyValidation::ResourceExistenceCheck in the plan job (no stack wedge — plan is non-mutating); that needs a privileged change-set IMPORT (ENC-ISS-386 / ENC-ISS-394 pattern, via cfn-resource-import.yml whose import job is itself environment-gated) - STOP and hand to io.
- Channel B - Lambda function code: use the promote path. Land on v4/main, let "Deploy Lambda Artifacts (Gen2)" go green; promote-gamma-to-prod-request.yml then dispatches a v3-prod _deploy.yml request that PAUSES on the v3-prod GitHub Environment required-reviewer rule. io's approval click on that Environment is the second gate and the actual prod Lambda swap. The agent cannot approve. (Equivalent manual form: workflow_dispatch _deploy.yml ref=main target_environment=v3-prod, which also waits for approval.)
- Channel C - CI tooling / tools/** / .github/workflows/** / 04-github-roles.yaml: no push-deploy fires. Merging to main lands the change; validate by dispatching the relevant workflow (e.g. cfn-drift-audit.yml). An IAM/github-roles change that must alter the live role needs a manual github-roles stack deploy (privileged) - hand to io if so. Note the iam-* patch workflows and ui-backend-deploy.yml are also v3-prod environment-gated (ENC-TSK-J64), and tools/prod_gate_coverage_guard.py (ENC-TSK-J65) fails CI if any new workflow ships an ungated prod lane.

If a task spans channels, treat each file group by its channel and sequence the riskiest (A) last, after the health gate.

## Step 2 - Execute (github_pr_deploy lifecycle)

1. Mint an agent session (agent.type.register -> agent.register => ENC-SES-NNN) and checkout.task the target (set components first).
2. Create a worktree from origin/main; make the surgical edit; validate locally (compile/lint/parse; pre-deploy-health-gate for Channel A).
3. advance coding-complete (CAI) -> commit -> push -> advance committed with commit_sha (CCI).
4. Open the PR to main with the CCI token in the body (PR Commit Gate). Wait for required checks green.
5. Merge. Then drive the Channel from Step 1: Channel C completes on merge; Channels A and B both proceed to a paused v3-prod Environment request whose approval is io's action alone — surface the run URL and the change-set summary to io and wait.
6. Capture deploy_evidence (a completed+success GitHub Actions Jobs API object - the apply job for A, the v3-prod _deploy job for B, or the validating workflow run for C) and advance deploy-init -> deploy-success.
7. Live-validate, then advance closed with live_validation_evidence. Set acceptance evidence on all criteria first.

## Step 3 - Auto-promote discipline

Any v4/main push whose gamma Lambda deploy goes green will fire a v3-prod promote request that waits on the Environment gate. Likewise any main push touching a CFN template or its workflow leaves a paused v3-prod apply request. Unless THIS task's v3 channel is exactly that request AND io approves, leave it unapproved (let it sit, or io rejects it). Never approve any v3-prod Environment request on the agent's own initiative.

## Step 4 - Record and report

Worklog the deploy (branch, run id, commit, health-gate result); submit deploy.history where applicable; report back to io: what landed on v3, the run/commit ids, the health-gate outcome, and anything still pending io's Environment approval or a privileged import.

## Hard stops - escalate to io, do not proceed

- The CFN change requires a resource IMPORT (resource exists out-of-band).
- pre-deploy-health-gate.sh fails or cannot run.
- The change looks like a full-env CFN replace or would touch shared out-of-band env vars / inline policies (PLN-047 class).
- The task is unvalidated or has broad blast radius.
- The MCP connector is gamma, or governed write-auth fails.
- Consent token is absent, wrong, or ambiguous.

## Scope and sunset

This brief is a bridge measure valid only until the v4 -> v3-prod cutover. At cutover (io's explicit approval per DOC-499FA089EC30) this process and its consent token are retired. Until then it is the ONLY sanctioned way for an agent to touch v3-prod, and only one task at a time, only with this brief's DOC id supplied by io.


---

## COE — 2026-07-08: SCI (FTR-122) reverted from v3-prod by a main-ref Lambda deploy

**Source incident**: ENC-ISS-441 (reopened) · **Remediation**: ENC-TSK-M44 · **Added**: 2026-07-08 (diagnostic session, product-lead read-only AWS)

**Summary.** An io-approved, believed-surgical prod deploy whose ref was `main` rebuilt the ENTIRE per-env prod Lambda set and silently reverted FTR-122 SCI (session-claim mint + enforcement), a feature built v4-first that only ever lived on `v4/main`. This reopened ENC-ISS-441 (unclaimed / any-session tracker mutation, fail-open) on v3-prod. A Claude desktop agent surfaced it as "cannot get an SCI minted."

**Timeline (precise, as reconstructed from CloudTrail + prod agent-sessions + git):**

```yaml
2026-07-02T11:46Z: FTR-122 SCI (the ISS-441 fix) surgically promoted to v3-prod as v4/main x86 artifact 12f7016 (io-gated, DOC-B716 Channel B). First SCI session ENC-SES-02O at 2026-07-02T12:02:53Z.
2026-07-02_to_07-08: SCI live continuously on prod — 155 SCI-bearing sessions, ENC-SES-02O -> ENC-SES-07A (2026-07-08T22:19:35Z).
2026-07-08T15:16Z: newer v4/main x86 artifact 85dad944d6 promoted to prod (still SCI-bearing).
2026-07-08T22:22:15Z: io dispatched _deploy.yml ref=main@cb71380 -> v3-prod and approved the v3-prod Environment gate, intending to ship the ISS-501/M43 escalation_decision change. The Gen2 Lambda lane is ALL-OR-NOTHING per env: it rebuilt all ~30 prod Lambdas from main.
2026-07-08T22:25:44-22:26:25Z: coordination_api + checkout_service + tracker_mutation + mcp-code + coordination_monitor_api overwritten with main (cb71380). SCI mint (J92) and enforcement gate (J93) both gone.
2026-07-08T22:35:04Z: first broken claim ENC-SES-07C (status=claimed, no sci_token_id). ISS-441 reopened fail-open. Reproduced live on ENC-SES-07D.
```

**Root cause.** FTR-122 was built v4-first and only ever lived on `v4/main` (main <-> v4/main sync disabled since ENC-TSK-H63). It reached prod exclusively by surgical promotion; `main` never contained it. Any deploy whose ref is `main` therefore reverts it. The trigger was believed to be a scoped, one-touch prod change, but the Gen2 `_deploy.yml` lane rebuilds the whole per-env Lambda set from the ref — it is not single-function.

**The pre-cutover trap — generalize this.** During this temporary pre-cutover stage, prod's true desired state is a HYBRID: the `main`-lineage baseline PLUS a set of v4-first features surgically promoted to prod ahead of cutover (currently at least FTR-122 SCI). Every prod deploy channel is whole-env, not single-resource:

- `_deploy.yml ref=main -> v3-prod` rebuilds ALL Lambdas from main.
- A CFN `*-stack-deploy` from main replaces the whole stack.

So approving a prod deploy to unblock v4/main development (a needed IAM role, a main-side fix, anything) can force a full prod rebuild that reverts any v4-first surgical prod feature absent from `main`.

**Guardrail (mandatory until cutover).** Before approving ANY v3-prod deploy: enumerate the "v4-first features surgically live on prod" set and confirm the deploy ref (`main`) contains them. If it does not, expect them reverted — STOP and surface. Never treat a Gen2 `_deploy.yml` or CFN stack deploy as a single-resource "surgical" change; it is per-env whole-stack. The durable fix for each such feature is to backport it to `main` so it survives a main deploy (SCI backport tracked: ENC-TSK-M44).

**Why this is temporary.** At cutover, v4 becomes stable on `main` and continuous v4.x runs on gamma with auto-promote; the hybrid divergence and this trap dissolve. Until then it is the single most dangerous foot-gun of the pre-cutover stage, and this COE is the standing warning.



---

## Registry — v4-first features required on v3-prod (LIVING; check before every pre-cutover main deploy)

**Purpose.** The set of features built v4-first (present on `v4/main`, ABSENT from `main`) that have been surgically promoted to v3-prod ahead of cutover and are relied upon in production. A `main`-ref prod deploy reverts every entry here (see the COE above). Before approving ANY v3-prod deploy, confirm the deploy ref carries these — or expect them reverted. Keep this list current: remove an entry once it is backported to `main` and confirmed live on prod from a main artifact; add an entry whenever a new v4-first feature is surgically promoted to prod.

**Audit basis (2026-07-08).** CloudTrail shows 31 prod Lambdas were rebuilt from `main` (cb71380) at 22:25–22:26Z; before that they ran FULL `v4/main` x86 artifacts (12f7016 from 2026-07-02, then 85dad944d6 from 2026-07-08 15:16Z). IMPORTANT: the promote path ships WHOLE v4/main artifacts, not surgical diffs — so prod actually carried far more v4 code than these named features (intent classifier, provider adapters, cursor webhook, feed rebuild, dedup, arc-walker, etc.). The 22:25 revert to main was correct for that bulk; the harm is that it also dropped the governance features below, which prod legitimately needs pre-cutover. Only `enceladus-mcp-streamable` remains on v4/main (85dad944d6); every other core Lambda is now on `main`.

```yaml
registry:
  - feature: ENC-FTR-122
    name: Session Claim ID (SCI) — mint + enforcement gate + revocation + MCP passthrough
    lambdas: [devops-coordination-api, enceladus-checkout-service, devops-tracker-mutation-api, enceladus-mcp-code]
    on_main: false
    prod_status: REVERTED 2026-07-08T22:25Z (mint + gate gone; ISS-441 fail-open) — functionally reproduced live
    first_live_prod: 2026-07-02T12:02:53Z (ENC-SES-02O)
    backport_task: ENC-TSK-M44
    impl_refs: [ENC-TSK-J92 mint, ENC-TSK-J93 gate, ENC-TSK-J94 sweeps/revoke, ENC-TSK-K10 mcp-passthrough]
  - feature: ENC-FTR-121
    name: Escalations — escalation.request/mint + applyEscalatedMutation applier + watch + SNS notify
    lambdas: [devops-coordination-api, devops-tracker-mutation-api]
    on_main: false   # request/mint/applier flow is v4-first; only the escalation_decision authorizer (M43/ISS-501) is on main
    prod_status: REVERTED 2026-07-08T22:25Z — request/mint/applier gone; escalation-decision-authorizer present but orphaned; prod escalations broken
    first_live_prod: 2026-07-02 (prod ENC-ESC-001 deploy_arc_change + ENC-ESC-002 direct_state_override; prod UAT jreese.net/enceladus/escalations)
    backport_task: pending (parallels ENC-TSK-M44)
    impl_refs: [ENC-TSK-J68 request, ENC-TSK-J69 applier, ENC-TSK-J70 PWA+decision, ENC-TSK-J71 watch, ENC-TSK-J72 notify]

not_in_registry:
  - ENC-FTR-117 (session register/claim + SES/AGT stores): ON MAIN — survives main deploys. Base session identity is not v4-first; only the SCI layer built on top of it (FTR-122) was.
  - ENC-FTR-119 (session-stall watchdog): ships from the isolated enceladus-support repo, status=planned — never on the enceladus v3-prod stack; excluded.

maintenance:
  method: "For any candidate feature F: v4-first == (git grep signature present on origin/v4/main AND absent on origin/main). Prod-live == the owning prod Lambda's current source SHA is a v4/main-only commit. Reverted == owning Lambda now on a main SHA (cb71380 as of 2026-07-08)."
  cutover_sunset: "At cutover (stable v4 on main + auto-promoted v4.x on gamma) main and v4/main reconverge; this registry and its risk dissolve."
```




---

## Registry maintenance — 2026-08-14: BOTH registry entries are DISCHARGED

**Added by**: session ENC-SES-0CV during ENC-FTR-131 (io-consented, DOC-B716E8FB10B6) · **Method**: the `maintenance.method` procedure defined in the registry block above.

**The `registry:` block above is now STALE and should be read as empty.** Both entries were verified present on `main` on 2026-08-14. A `main`-ref prod deploy therefore does **not** revert them, and the guardrail they encode ("confirm the deploy ref carries these — or expect them reverted") no longer has anything to catch. The COE above remains valid as a standing warning about the pre-cutover trap; only the two registry rows are discharged.

```yaml
discharged:
  - feature: ENC-FTR-122
    name: Session Claim ID (SCI) — mint + enforcement gate + revocation + MCP passthrough
    was: "on_main: false / prod_status: REVERTED 2026-07-08T22:25Z"
    now: ON MAIN — discharged by the ENC-TSK-M44 backport
    code_evidence: "sci_token_id present on origin/main in backend/lambda/coordination_api/lambda_function.py and agent_id_alloc.py (plus test_agent_id_alloc.py and governance_data_dictionary.json)."
    live_evidence: "Prod minted SCI-d6ae519cb4d24ad99a10fcf1d2db77bf for session ENC-SES-0CV at 2026-08-14T01:51:15Z via coordination(agent.claim). At that moment prod Lambdas were running the 2026-08-08T10:29Z main-lineage build — so SCI was demonstrably live FROM A MAIN ARTIFACT, which is exactly the condition the maintenance rule requires for removal."
    post_deploy: "Prod Lambdas were rebuilt again from main@5ba0fc3e0594945bc9f37a35d6221c7e4f7b8459 on 2026-08-14T02:41-02:47Z; SCI is on main, so it survives that and every future main deploy."

  - feature: ENC-FTR-121
    name: Escalations — escalation.request/mint + applyEscalatedMutation applier + watch + SNS notify
    was: "on_main: false / prod_status: REVERTED 2026-07-08T22:25Z"
    now: ON MAIN — backport landed
    code_evidence: "escalation_request / applyEscalatedMutation present on origin/main in backend/lambda/tracker_mutation/lambda_function.py and backend/lambda/coordination_api/lambda_function.py, plus test_escalation_j68.py, test_escalation_applier_j69.py, test_escalation_notify_j72.py and governance_data_dictionary.json."
    live_evidence: "DEPLOYMENT LINEAGE ONLY — prod Lambdas were rebuilt from main@5ba0fc3 on 2026-08-14T02:41-02:47Z and the code is on main, so the deployed artifact contains it."
    caveat: "NOT functionally exercised in this session. No escalation was raised end-to-end on prod to confirm request -> mint -> applier still works. The revert risk this row guarded against is gone (the code is on main); whether the flow is functionally healthy on prod is a SEPARATE question this entry does not answer. Worth one live escalation before relying on it."
```

**Why this matters operationally.** While these rows read `on_main: false`, the mandatory pre-deploy guardrail instructs the operator to STOP before any `main`-ref prod deploy. That STOP is now a false positive on every future deploy. This maintenance note exists so the next agent or operator running the guardrail resolves it correctly instead of either halting needlessly or — worse — learning to ignore the guardrail.

**Not changed by this note.** The Consent Protocol, the Standing Invariants, the Channel A/B/C classification and the 2026-07-08 COE are all untouched and remain in force.

**Appended, not rewritten.** This section was added via `documents.patch(append_content=...)`; no existing byte of this brief was modified. The `registry:` block above is deliberately left in place rather than deleted, so the audit trail of what was once at risk survives.
