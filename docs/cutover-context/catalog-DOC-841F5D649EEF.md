
# DOC-841F5D649EEF — PLN-006 + PLN-078 Coding-Task Catalog (ADE dispatch source of truth)

**Project**: enceladus
**Related**: ENC-PLN-006, ENC-PLN-078, ENC-PLN-080, ENC-TSK-B63, ENC-TSK-B64, ENC-TSK-B67, ENC-TSK-B69, ENC-TSK-M98, ENC-TSK-M99, ENC-TSK-N01, ENC-TSK-N02, ENC-TSK-N48, ENC-TSK-N63, ENC-TSK-N64, ENC-TSK-N65, ENC-TSK-N66, ENC-TSK-O03, ENC-TSK-O04, ENC-ISS-538, ENC-ISS-543, ENC-ISS-556, ENC-ISS-558, ENC-ISS-559, ENC-ISS-563, ENC-ISS-566, ENC-ISS-603, ENC-ISS-604, ENC-ISS-622, ENC-ISS-623, ENC-ISS-624, ENC-ISS-625, DOC-B716E8FB10B6, DOC-499FA089EC30, DOC-6EFD5DB32CD8, DOC-10A820AC32F2, DOC-0D7E2A94F67C

**Created**: 2026-06-28
**Author**: coord-lead
**Updated**: 2026-08-21 (v137 by claude.ai webui session, io-directed CUTOVER-DAY refresh. v136 was 2026-07-13 — this version reconciles 5+ weeks of drift against live tracker.get / deploy.history reads taken 2026-08-21T18:05Z, governance_hash e04f7eda. io decision of record — B69 CUTOVER EXECUTES TODAY; minor bugs post-cutover flow gamma-first UAT per regular deploy path; DOC-499FA089EC30 suspends at cutover.)

## 🚨 READ THIS FIRST — CUTOVER DAY 2026-08-21

io has committed to executing the ENC-TSK-B69 production cutover today. This catalog version is the reconciled pre-cutover ground truth. Every status below was verified live via tracker.get on 2026-08-21 unless marked UNVERIFIED. Per standing rule, re-verify at dispatch regardless.

```yaml
cutover_gate_path:
  ENC-TSK-B63: "CLOSED 7/7 (2026-07-12, io)"
  ENC-TSK-B64: "CLOSED (Phase 3 MCP modularized + streaming + auth bifurcated)"
  ENC-TSK-B67: "in-progress 23/24 — AC-8 promote-coupled to B69 by design; stamps POST-cutover via re-probe"
  ENC-TSK-B69: "open 1/7 stamped (gamma-teardown AC formally retired/superseded — gamma is DURABLE staging, survives cutover)"
b69_open_acs:
  - showcase jreese.net update (JWO-TSK-023)
  - backend v4 cutover all-traffic
  - v3 Lambda stack decommission
  - 5 lessons w/ evidence chains
  - DOC-6EFD5DB32CD8 final-state update
  - RISK-001..010 mitigated-or-accepted rulings
```

## 🔴 CUTOVER BLOCKER BOARD (verified 2026-08-21)

```yaml
P0_hard_gates:
  ENC-ISS-538:
    status: OPEN
    gates: B69 DIRECTLY
    state: "Audit complete (44 colliding + 10 gamma-only IDs). M98 mirror tool CLOSED and merged (PR #1012, main c99b45ef). N01 first supervised mirror run 0/4 — NEVER EXECUTED. Requires io one-time setup: required_reviewers on gamma-mirror GitHub Environment, then dry-run manifest review, then execute."
    cutover_note: "Promote-corrupting if gamma tracker data merges into canonical. Resolve BEFORE any promote step that touches tracker data; if cutover routes traffic only (no data merge), io must rule explicitly that 538 is promote-orthogonal and re-scope its gate."
  ENC-ISS-559:
    status: OPEN
    category: security
    state: "cognito_session ignores include_tokens:false — leaks live ID token + 30-day refresh token in cookie arrays. Exposed terminal-agent session needs rotation (DOC-3DEFB053DD7D). Related task ENC-TSK-N58 status unverified."
    cutover_note: "Prod cutover raises blast radius of any leaked prod session token. Fix-or-rotate before cutover completion."
P1_lane_blockers:
  ENC-ISS-624:
    status: OPEN
    state: "pre-deploy-health-gate check 5 RED on main. CORRECTED HYPOTHESIS ON RECORD: this is a TRUE positive — enceladus-checkout-service-auto-gamma alone sits on enceladus-shared:11 while all 45 other gamma + 71 prod functions sit on canonical :10. Fix: reconcile that one function to :10, OR retire it (the -auto- segment suggests an experimental artifact), OR raise canonical and roll all consumers."
    cutover_note: "HARD STOP for every Channel A (CFN) prod deploy per DOC-B716E8FB10B6. The cutover cannot use the CFN lane while this stands. Fix first — it is a one-function reconcile."
  ENC-ISS-566:
    status: OPEN (untouched since 2026-07-13)
    state: "embedding_refresh crash-loops at import (No module named 'embedding'). Blocks N48 close. AC-2 requires establishing whether the tenant EVER ran cleanly on gamma before attributing to the 07-13 deploys."
    arm_wheel_class: true
  ENC-ISS-558:
    status: OPEN
    state: "MCP tracker.list total computed over one capped page (~8x undercount) + separately-observed 50-row silent window with false partial:false. Do NOT cite tracker.list totals. Primary task ENC-TSK-N62 unverified."
  ENC-ISS-563: {status: OPEN, state: "FTR-096 consolidation 24h lookback still producing structural zero — N63 window widening NOT yet landed"}
  ENC-ISS-603: {status: OPEN, state: "commit validation doubles owner prefix for enceladus repo — verify impact on cutover-day PR flow before dispatching code tasks"}
  ENC-ISS-604: {status: OPEN, state: "intelligence-project corpus governance exists only on frozen main, not v4/main — cutover survival risk for INT lane"}
  ENC-ISS-597: {status: OPEN, state: "orphaned checkout wedges records permanently — operational risk during a long multi-session cutover day"}
P2_watch:
  ENC-ISS-623: "all seven live enceladus-prod alarms have AlarmActions [] — prod codesize alarm CURRENTLY IN ALARM notifying nobody. Post-cutover prod observability is silent until fixed."
  ENC-ISS-625: "devops-github-integration has zero layers + no in-repo CFN resource — cannot import enceladus_shared; O07 AC-1 deliberately unstamped on it."
  ENC-ISS-556: "gamma compute-stack deploy jobs exit 1 on N49 post-apply S3-lifecycle step (UNVERIFIED today — recent gamma deploys 0.0.133–137 recorded success, may be resolved or routed around)."
```

## 📦 POST-v136 ACTIVITY RECONCILED (deploy.history 2026-08-21)

```yaml
deploys_since_catalog_v136:
  0.0.130: "2026-07-13 — ISS-557 fix (sense.py cursor-exhausting count). ISS-557 CLOSED."
  0.0.131_132: "2026-07-13/14 — PRs #1047/#1049/#1051 gamma"
  0.0.133_134: "2026-08-01 — PRs #1060/#1061 gamma"
  0.0.135: "2026-08-05 — PR #1068 gamma"
  0.0.136: "2026-08-14 — ENC-TSK-N91/ENC-ISS-614 tracker.create unified relation intake — deployed to v3-PROD (io-gated, merge 8533d968, PR #1090)"
  0.0.137: "2026-08-17 — PR #1095 gamma (PLN-080 O07 shared github_app_auth)"
new_plan:
  ENC-PLN-080: "drafted — ENC-ISS-621 remediation / GitHub-integration hardening (DOC-10A820AC32F2). O05/O06/O08 closed; O07 deploy-success 3/4; O03 merged-main 3/5 STAGED for v3-prod deploy awaiting io (gh workflow run _deploy.yml -f target_environment=v3-prod -f commit_sha=1f8af94...); O04 draft PR #1094 BLOCKED on ISS-624. ENC-ISS-622 put-role-policy form needs product-lead terminal."
still_open_from_v136_era: [ENC-TSK-N48 (blocked on ISS-566 + primary-artifact S3 read), ENC-TSK-N01, ENC-TSK-N02 (unverified), N63-N66 (N63 evidently not landed per ISS-563)]
```

## 🎯 CUTOVER-DAY CRITICAL GOALS (io, 2026-08-21)

```yaml
goal_1_mcp_down_context_contingency:
  requirement: "agent sessions must acquire context WITHOUT Enceladus MCP while cutover/debug is in flight"
  mechanism: "pre-cutover CONTEXT FREEZE BUNDLE — export to git (repo docs/cutover-context/) AND io-local: this catalog v137, DOC-6EFD5DB32CD8 (blueprint), DOC-B716E8FB10B6 (prod deploy path), DOC-FFB4C9D87BCC (dispatched-agent prompt), DOC-586FB8D3DF02 (coord-lead prompt), agents.md, governance dictionary snapshot, connection_health snapshot w/ governance_hash"
  session_protocol_while_down: "terminal agents boot from the file bundle; ALL tracker-state claims marked UNVERIFIED-OFFLINE; NO governed writes attempted; work queue captured as F6 HANDOFF blocks in local .md for post-restore reconciliation; mcp-gamma read-only is the secondary surface ONLY if its plane is not the one being debugged"
goal_2_arm_wheel_verification:
  requirement: "graph traversals, tracker read/write, and common dev-task management verified working on arm64/py3.12 before declaring cutover done"
  known_arm_class_defects: [ENC-ISS-566 (import/packaging crash), ENC-ISS-624 (layer :10 vs :11 drift), ENC-ISS-625 (zero-layer function)]
  verification_slice: "post-route-flip smoke on prod surface: tracker.get + tracker.create + tracker.set + checkout arc on a throwaway record; tracker.graphsearch neighbors on ENC-PLN-006; documents.get + documents.patch round-trip; graph_sync projection write; native-wheel imports (numpy/scipy class) across all promoted functions — grep ImportModuleError across ALL /aws/lambda/* log groups in the first hour"
```

## ⚠ HARD RULES (standing, carried from v136)

Graph never status-authoritative (ISS-543 still OPEN). tracker.list never a completeness proof (ISS-558 OPEN — totals lie, 50-row window). Telemetry over inference. Checked-out records reject third-party writes — route through holder or wait. Agent S3 read DENIED on jreese-net (primary-artifact ACs need io-dev-admin or a grant). Issue category enum [bug, debt, performance, risk, security]. document_subtype enum [coe, context-node, doc, handoff, idea, skill, wave]. NO GFM pipe tables (ENC-LSN-026). transition_type sealed at create. documents.patch is full replacement. Premise errors #1–#12 stand; #10 (acceptance-on-deferred-proof) is the cutover-day watch — B69 ACs stamp on LIVE artifacts only.

## 🎯 io QUEUE (cutover day, sequenced)

```yaml
pre_cutover:
  1: "ISS-624 fix (reconcile enceladus-checkout-service-auto-gamma to :10 or retire) — unblocks Channel A lane"
  2: "ISS-538/N01 mirror run OR explicit io ruling that cutover is traffic-route-only and 538 re-scopes post-cutover"
  3: "ISS-559 fix + terminal-agent token rotation"
  4: "context freeze bundle exported (goal 1)"
  5: "O03 v3-prod deploy decision — ship staged 1f8af94 BEFORE cutover or fold into cutover; do not leave straddling"
cutover: "per DOC-B716E8FB10B6 + DOC-6EFD5DB32CD8 sequencing — route flip, arm-wheel smoke (goal 2), B69 AC evidence capture live"
post_cutover: "suspend DOC-499FA089EC30; B67 AC-8 re-probe + Bucket-C promote-coupled re-probes; ISS-623 alarm actions; ISS-566/N48; N63-N66; minor bugs via gamma-first UAT flow"
```

🔒 CREDENTIAL BOUNDARY intact.
