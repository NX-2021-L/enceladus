# DOC-AGENTS Agent Rules

**Project**: enceladus
**Related**: ENC-TSK-D88, ENC-LSN-026, ENC-PLN-024
**Created**: 2026-04-13
**Author**: product-lead terminal session
**Governance-Revision**: 2026-06-30.09
<!-- ENC-TSK-I31 machine-readable governance_revision token: read verbatim by the ENC-TSK-I27 recompute via the line-anchored regex `governance_revision:`. Keep in lockstep with the **Governance-Revision** display label above and `governance_data_dictionary.json`'s `version`. This is the value the §13 version-agreement gate compares across the three surfaces.
governance_revision: 2026-06-30.09
-->

> The `Governance-Revision: YYYY-MM-DD.NN` token above is the monotonic governance-version label for the canonical governance bundle. It mirrors `governance_data_dictionary.json`'s `version` field and is bumped on every §13 byte change to any `governance/live/*` file (see §13 → "Canonical governance bundle, deterministic hash, and the governance_revision token"). `NN` is a two-digit intra-day sequence (`.01`, `.02`, …) reset each new UTC date. The recompute (ENC-TSK-I27) extracts the revision from the machine-readable `governance_revision:` token embedded in the HTML comment immediately below the display label; the display label, that machine token, and the dictionary `version` MUST be bumped together — the §13 version-agreement gate fails if they disagree across surfaces.

A summary of preferred working rules, principles, processes, and methods that guide agent work in the Enceladus project.

You are a product engineering team with a group of agents who operate through the Enceladus MCP server for all governed resource access. All tracker operations, governance updates, document management, and deployment requests route through HTTP APIs via MCP tools — agents have zero direct DynamoDB, S3, or Lambda write access. Your goal is to maximize the number of tasks completed during the session from the task database for the current project. We use agile principles to ensure we're always prioritizing the most logical next task across the entire project. To do this effectively, we aggressively maximize the preservation of available facts about a specific scope of work within a project such that all facts which could influence a future strategic recommendation by another agent about that scope of work are exhaustively documented and updated.

---

## Session Initialization

Execute these steps in order before any work:

1. `connection_health()` — confirm DynamoDB ok, S3 ok, capture `governance_hash` for all writes.
2. `search(action="governance.dictionary")` — load compact entity index (~1k tokens). Note dictionary version.
3. `search(action="governance.get", arguments={file_name: "agents.md"})` — load agent rules and governance policies.
4. `search(action="tracker.list", arguments={project_id: "enceladus", record_type: "task", status: "open"})` — open tasks.
5. `search(action="tracker.pending_updates", arguments={project_id: "enceladus"})` — pending PWA update notes.
6. **Load institutional memory:** `search(action="tracker.list", arguments={project_id: "enceladus", record_type: "lesson", page_size: 10})` — scan recent lessons for patterns, failure modes, and principles relevant to the session. Cite lessons in worklogs when they inform decisions.
7. **Assess plan health:** For any active plan, call `search(action="plan.objectives_status", arguments={record_id: "<plan_id>"})` to understand workstream progress before picking tasks.
8. Brief the user (3–5 paragraphs): project status, recent updates, priority tasks, pending updates, **relevant lessons**. **Do not execute tasks yet.**

---

## Resume Reverification — Untrusted-Memory Invariant (DOC-79631EBFF71D)

Session memory is a cache, not a source of truth. Across a context gap or
reload, the live records an agent saw earlier may have moved. Treat session
memory of governed record state as UNTRUSTED on resume and re-verify against
live Enceladus reads before producing output that asserts or depends on that
state.

**Gate (unconditional on resume).** Before emitting any of these four output
classes, re-read the records it depends on:

1. a plan or plan revision,
2. a dispatch prompt or agent-session directive,
3. resumed work on a dispatched assignment,
4. a status summary or session brief.

This is distinct from pre-mutation reconciliation (ENC-LSN-043), which gates
writes. The Resume Reverification Gate gates outputs — including read-only ones.
A stale status brief is the canonical failure ENC-LSN-043 never catches.

**Two-channel verification.** `governance_hash` (from `connection_health`) is a digest of
the governance data-dictionary snapshot, rotated only by the `governance.update` S3 sync
path. It does NOT reflect a raw `agents.md` write (confirmed empirically — an `agents.md`-only
write leaves it unchanged), nor tracker/docstore RECORD changes (task status, issue
open/close, plan objectives). A matching hash proves only that the dictionary is unchanged,
never that the agent-rules prose or the records an output depends on are current. Targeted
live reads are mandatory:

- `tracker.list` / `tracker.get` for the tasks and issues in scope,
- `plan.objectives_status` for any plan in scope,
- `tracker.pending_updates` for PWA notes,
- `documents.get` for any document the output cites,
- a fresh `governance.get` for `agents.md` itself when an agent-rules change is suspected,
  since the hash will not flag it.

**Scope by churn.** Re-read the records the output depends on, weighted by how
fast they change: tasks (7-day staleness half-life) and issue/plan state churn
fast and are re-read every resume; lessons (180-day half-life) and closed plans
are effectively static. The gate is unconditional rather than time-thresholded —
an agent cannot perceive elapsed wall-clock time — but it is scoped to the
output's dependency set, not the whole project.

---

## MCP Connector Surface Discipline (ENC-LSN-056 / ENC-ISS-410)

More than one Enceladus MCP connector may be enabled on a single account (e.g. "enceladus v2" = prod
@ mcp.jreese.net; "enceladus gamma" = v4/gamma @ mcp-gamma.jreese.net). Connector enablement is
ACCOUNT-WIDE, not session-scoped, so a bare "enceladus" reference can be ambiguous across concurrent
sessions.

Do NOT rely on a connector's name/label to determine which compute or corpus you are operating on.
Before any surface-dependent governed write:
1. Default to the prod connector for all production, coordination, and real-corpus work.
2. Verify the live surface behaviorally — connection_health (governance_hash + graph projection) plus a
   surface-specific compute-version probe (current discriminator in ENC-LSN-056). Live write-path behavior
   supersedes any label, dictionary claim, or deploy-success report.
3. Treat a v4/gamma-only capability as UNREACHABLE until a probe proves the surface serves it; escalate to
   io if a task needs gamma compute the surface will not confirm.

Incident of record: ENC-ISS-410 — a 2026-06-25 gamma-connector misroute made it indistinguishable from
prod and silently directed writes at the prod corpus.

---

## Lazy-Loaded Sections (ENC-ISS-142 refactor)

To keep this core lean (it loads at every agent boot), heavy/specialized reference material lives in separate governance files. Load only the one whose trigger applies, via search(action="governance.get", arguments={file_name:"agents/<name>.md"}):

- agents/component-proposal.md — proposing/validating a component (component.propose, components.create); component registry, capability fields, graph edges. (Formerly the duplicate "§14 Component Proposal Protocol".)
- agents/mcp-tool-inventory.md — full MCP code-mode tool/action reference (search/execute/get_compact_context/coordination/connection_health surfaces).
- agents/deploy.md — deploy evidence schemas, governance dictionary deployment gate, and deploy capability governance (consolidated §11 + §12 + Deploy Capability Governance).
- agents/dispatch-subagent.md — dispatch protocol and subagent governance inheritance.
- agents/graph-search.md — tracker.graphsearch relational queries (neighbors/keyword/path/traversal). See also agents/graphsearch-guide.md.
- agents/document-storage.md — docstore put/patch, subtypes, document maturity lifecycle.
- agents/lesson-primitive.md — Lesson primitive, knowledge graph, constitutional scoring.
- agents/generation-conventions.md — generation-scoped conventions (v3/v4/gamma).
- agents/ogtm.md — Ontological Graph Traversability Mandate (OGTM) compliance gate.
- agents/documentation-discipline.md — Diataxis documentation discipline + the per-merge documentation-impact evaluation required across v4 (ENC-PLN-006). Load when preparing a merge/PR or when a change touches code, architecture, or /docs.

The init-critical trio (§6 Tracker Operations / ID Boundary, §8 Multi-Agent Repo Safety, §13 Governance File Authority) and the lifecycle essentials remain inline below. Section-number gaps above are intentional — the missing numbers were externalized to the files listed here.

## §0 — Project North Star (project=enceladus)

PRIMARY GOAL: ENC-PLN-006 (v4 greenfield migration).

All governed agent sessions MUST surface this at init: while ENC-PLN-006
is active, it is the primary goal for project=enceladus. Task selection,
dispatch prioritization, and "what next" defaults bias toward PLN-006
objectives unless io explicitly overrides.

GATE (self-voiding): This directive is conditional on
plan.objectives_status(ENC-PLN-006).status != "complete".
When ENC-PLN-006 reaches status="complete", this §0 is VOID and MUST be
removed in the next governance sync. Sessions SHOULD verify plan status
live at init rather than trusting this line statically.

## §2 Checkout Requirement (ENC-FTR-037)

> **⚠️ CRITICAL: NO code or repository changes of any kind are permitted unless a task is checked out.**

**Non-negotiable prerequisites before editing any file:**
1. A tracker task exists to track the changes (create via `tracker.create`).
2. `task.components` is set to the component registry IDs that will be changed.
3. `task.transition_type` is set to the correct lifecycle arc (see §3).
4. The task is checked out via `checkout.task` for this session.
5. Only after receiving a successful checkout response may coding begin.

**Task status transitions MUST use `checkout.advance`** — NOT `tracker.set(field="status")`. Direct `tracker.set` for task status is rejected with HTTP 403.

**Task worklogs MUST use `checkout.append_worklog`** — NOT `tracker.log`. The task must be checked out before a worklog can be appended.

### CAI / CCI Token Gates — NOT OPTIONAL

The commit workflow is gated by two tokens issued by the checkout service. **You cannot skip these.**

```text
checkout.task
  → [write code]
  → checkout.advance(coding-complete)         → returns CAI-xxx (Commit Approval ID)
  → [create git commit]
  → checkout.advance(committed, commit_sha)   → validates SHA via GitHub API; returns CCI-xxx (Commit Complete ID)
  → [open PR — body MUST include CCI-xxx]
  → GitHub PR Commit Gate validates CCI-xxx before merge is allowed
  → checkout.advance(pr)
  → checkout.advance(merged-main, pr_id + merged_at)
  → checkout.advance(deploy-init)
  → checkout.advance(deploy-success, deploy_evidence)
  → checkout.advance(closed, live_validation_evidence)
```

**CAI (Commit Approval ID):** Issued when the task advances to `coding-complete`. Records that coding is complete and commit work is authorized. Stored on the task record until `deploy-success` clears it.

**CCI (Commit Complete ID):** Issued when the task advances to `committed` with a valid `commit_sha`. Proves the commit SHA was validated against GitHub. Must appear verbatim in the PR body. Validated by the GitHub `PR Commit Gate` workflow. Cleared after `deploy-success`.

If the task has no `commit_complete_id`, the `pr` transition will be rejected.

---

## §3 Task Lifecycle & Commit Workflow

### Full default arc (`github_pr_deploy`)

```text
open → in-progress → coding-complete → committed → pr → merged-main → deploy-init → deploy-success → closed
```

### Re-entry arc (after a live deploy)

```text
deploy-success → coding-updates → coding-complete → committed → pr → merged-main → deploy-init → deploy-success
```

### Plan lifecycle (ENC-FTR-058)

Plans use a simplified 4-state lifecycle:

```text
drafted → started → complete | incomplete
```

- `drafted`: initial state on creation
- `started`: at least one objective task has been checked out
- `complete`: all objectives in `objectives_set` are closed
- `incomplete`: abandoned with reason

Advance plan status via `plan.advance`. Plans use a simplified checkout contract — no CAI/CCI tokens.

### Transition type strictness ranking

```yaml
transition_type_strictness:
  - transition_type: github_pr_deploy
    rank: 0
    meaning: full PR + merge + deploy + live validation
  - transition_type: lambda_deploy
    rank: 1
    meaning: PR + merge + Lambda deploy evidence
  - transition_type: web_deploy
    rank: 1
    meaning: PR + merge + web verification evidence
  - transition_type: code_only
    rank: 2
    meaning: PR + merge, no deploy stage
  - transition_type: no_code
    rank: 3
    meaning: no GitHub/deploy arc
```

**Rule:** A task's `transition_type` must be at least as strict as every component it modifies. Set `transition_type` via `tracker.set` BEFORE calling `checkout.task` — it is immutable after checkout.

### Key enums (quick reference)

- **task status:** open, in-progress, coding-complete, committed, pr, merged-main, deploy-init, deploy-success, coding-updates, closed
- **issue status:** open, in-progress, closed
- **feature status:** planned, in-progress, completed, production, deprecated
- **plan status:** drafted, started, complete, incomplete
- **lesson status:** draft, proposed, accepted, active, superseded, archived
- **priority:** P0, P1, P2, P3
- **task category:** implementation, investigation, documentation, maintenance, validation
- **issue category:** bug, debt, risk, security, performance
- **feature category:** epic, capability, enhancement, infrastructure
- **deploy change_type:** patch, minor, major

### Preflight before every transition

Call `search(action="tracker.validation_rules", arguments={record_id, target_status, provider})` before advancing. Returns exact `transition_evidence` fields required, allowed next statuses, and checkout requirements.

---

## §5 Agent Efficiency (ENC-TSK-805)

1. **Before exploring code**, retrieve the component registry via `get_compact_context(mode="project", project_id=..., include_code_map=true)` or `get_compact_context(mode="topic", query=..., domain=...)`. Never call `search(action="code_map.get")` — this action does not exist in code mode and will return an `unknown_action` error. Never grep/glob blindly when the registry can provide direct file paths.

2. **When spawning Explore subagents**, include `CONTEXT ALREADY KNOWN` with files already read. Load `search(action="governance.get", arguments={file_name: "agents/session-efficiency.md"})` for the full subagent prompt template.

3. **When creating issues**, always populate `hypothesis` OR `technical_notes` with a `location_hint`. This is server-enforced — issue creation without location context will be rejected.

4. **Use `get_compact_context`** to load record/project/topic context in a single call — avoid multi-call patterns.

5. **Use `reference.search`** for targeted architecture queries — never load full docs.

6. **Use `execute` with multiple steps** to batch mutations — reduces round trips.

7. **Use `execute(dry_run=true)`** to validate multi-step workflows before committing.

8. **Leverage context node scoring** when assembling context budgets. Lesson records have a 180-day staleness half-life (vs 7 days for tasks), structural importance baseline of 0.8, and `model_routing_hint: opus`. This means lessons stay relevant much longer and are prioritized in context assembly. When `get_compact_context` includes lesson-backed context, prefer it over ephemeral task context for architectural decisions.

9. **Check plan objectives before picking tasks.** Call `search(action="plan.objectives_status", arguments={record_id: "<plan_id>"})` to see which phases are done vs open. Pick the next logical phase rather than arbitrary open tasks. This prevents redundant work and ensures bottom-up completion ordering.

10. **Mine the lesson corpus for relevant institutional memory** before starting implementation. A 30-second `tracker.list` with `record_type: "lesson"` or keyword graphsearch can surface patterns that save hours of debugging. Lessons about Lambda routing, checkout service behavior, or deployment patterns are directly applicable to most implementation work.

---

## §6 Tracker Operations (MCP-Only)

**CRITICAL: All tracker operations MUST use MCP tools. Direct DynamoDB access is denied at IAM level (explicit deny on `devops-project-tracker` and `projects` tables).**

### Read operations (via `search`)
- `tracker.get(record_id)` — read a single record
- `tracker.list(project_id, record_type, status, page_size, cursor)` — list/filter records with pagination
- `tracker.graphsearch(project_id, search_type, ...)` — graph-indexed relational search (see §4)
- `tracker.pending_updates(project_id)` — check pending PWA update notes
- `tracker.validation_rules(record_id, target_status, provider)` — preflight before any transition
- `plan.objectives_status(record_id)` — plan objectives with completion summary
- `tracker.list(project_id, record_type="lesson", page_size, cursor)` — list lesson records

### Write operations (via `execute`)
- `tracker.create(project_id, record_type, title, ...)` — create a record
- `tracker.set(record_id, field, value, governance_hash)` — update a field (NOT for task status — use `checkout.advance`)
- `tracker.log(record_id, description, governance_hash)` — append worklog (NOT for tasks — use `checkout.append_worklog`)
- `tracker.set_acceptance_evidence(record_id, criterion_index, evidence, evidence_acceptance, governance_hash)` — set feature AC evidence
- `tracker.create(project_id, record_type="lesson", title, observation, insight, evidence_chain, pillar_scores, ...)` — create a lesson
- `plan.create(project_id, title, objectives_set?, related_feature_id?, ...)` — create a plan
- `plan.checkout(record_id, active_agent_session_id, governance_hash)` — check out a plan
- `plan.advance(record_id, target_status, provider, governance_hash)` — advance plan lifecycle
- `plan.add_objective(record_id, objective_task_id, governance_hash)` — add objective to plan
- `plan.remove_objective(record_id, objective_task_id, governance_hash)` — remove objective from plan (blocked for closed objectives)
- `plan.reorder_objectives(record_id, ordered_objective_ids, governance_hash)` — reorder objectives (permutation only)
- `plan.replace_objectives(record_id, objective_ids, governance_hash)` — bulk replace objectives (drafted status only)

### Checkout operations (via `execute`)
- `checkout.task(record_id, active_agent_session_id, governance_hash)` — check out a task; REQUIRED before any code changes
- `checkout.release(record_id, provider, governance_hash)` — release checkout on a task
- `checkout.advance(record_id, target_status, provider, governance_hash, transition_evidence?)` — advance task through lifecycle with gate validation
- `checkout.append_worklog(record_id, description, provider, governance_hash)` — append worklog to a checked-out task

### parent vs related fields

- **parent** (hierarchical): Use when one record is part of another. Set via: `tracker.set(field="parent", value="ENC-TSK-100")`
- **related** (associative): Use when records are related but not hierarchical. Set via: `related="ENC-ISS-200"` in `tracker.create` call.

Rule of thumb: If it answers "is part of" use parent. If it answers "is related to" use related.


### ID Boundary Rule (ENC-TSK-B99)

> **Agents must never predict, compute, infer, or scan for the
> next available record ID before submitting a `tracker.create`
> call.**

The only correct `tracker.create` pattern is to submit the
minimum valid required attributes. The server-assigned ID in
the success response is the sole authoritative source of that
record's identity.

**Rationale:** Record ID generation is intentionally outside the
knowledge boundary of any Enceladus agent. The tracker mutation
Lambda generates IDs through governed server-side logic (atomic
DynamoDB counters with base-36 encoding). Agents that attempt to
predict IDs introduce brittle sequence dependencies, risk creating
records with incorrect assumptions, and violate the system's
authority as the single source of ID truth.

**Anti-pattern (never do this):** Reasoning that "ENC-FTR-066 was
the last feature ID, so I will create ENC-FTR-067." Scanning
`tracker.list` to determine the next available sequence number.

**Correct pattern:** Submit `tracker.create` with required
attributes only. Receive success response. Read the returned
`record_id`. Use it in all subsequent operations.


---

## §7 Git / PR Workflow (ENC-ISS-073)

Organization-wide ruleset `git-governance` (ID 13297478) requires pull requests for all pushes targeting `main`. This ruleset has NO bypass actors — enforcement is always active.

Rules enforced on `refs/heads/main`:
- **deletion protection**: branch cannot be deleted
- **non_fast_forward protection**: force-pushes are rejected
- **pull_request**: PRs required; 0 required reviewers; stale review dismissed on push; all merge methods allowed
- **required_status_checks (strict mode = true)**: `CI`, `Secrets Scan`, and `PR Commit Gate` must pass. Strict mode means the branch MUST be up-to-date with `main` before a PR can merge.
- **PR Commit Gate** (ENC-FTR-037): PR body MUST contain a `CCI-xxx` token obtained from `checkout.advance(target_status=committed)`. The gate validates the token against the checkout service before allowing merge.

### Required workflow

1. Create task-scoped branch (see §8 for naming).
2. `checkout.task` via MCP (REQUIRED — see §2).
3. Develop; advance to `coding-complete` → receive CAI; then `committed` (with `commit_sha`) → receive CCI.
4. Merge or rebase `origin/main` into the branch to satisfy strict mode.
5. Push branch; open PR with CCI token in the PR body.
6. Merge via PR only — never push directly to `main`.

### Operational rules
- Interpret "commit" / "push" as the branch + PR workflow, not a direct push to `main`.
- Do not retry known-forbidden direct-to-main attempts.
- If `CI`, `Secrets Scan`, or `PR Commit Gate` fails, fix the root cause before merging.
- The `Governance Dictionary Guard` workflow also runs on every PR. Treat its failure as blocking (see §12).
- On each merge, evaluate whether the change warrants v4 documentation updates per the Diataxis documentation-discipline contract (agents/documentation-discipline.md); act within task / plan / wave / handoff scope (ENC-TSK-H77).

---

## §8 Multi-Agent Repo Safety

**Always assume other agents are active.** Multiple agent sessions may be running concurrently on the same machine. Each agent uses a **dedicated folder** (a separate clone or worktree) on the machine, not the shared main checkout.

### Mandatory pre-task procedure — every task pickup, without exception

1. **Confirm you are in the correct folder.** Verify your working directory is your agent's dedicated folder, NOT the shared main checkout at `/Users/jreese/enceladus/repo/`.

   ```bash
   git rev-parse --show-toplevel  # must NOT be /Users/jreese/enceladus/repo
   ```

2. **Confirm you are on the correct branch.** Verify your branch matches the task you are working on.

   ```bash
   git branch --show-current  # must be agent/<tracker-id>-<slug>
   ```

3. If not in a dedicated folder, create one before proceeding:

   ```bash
   bash /Users/jreese/enceladus/repo/tools/agent-worktree-init.sh <TRACKER-ID>-<slug>
   ```

### Branch naming convention (enforced)

```text
agent/<TRACKER-ID>-<slug>
```

where `<TRACKER-ID>` is the lowercase tracker ID and `<slug>` is 2–4 hyphenated words.
Examples: `agent/enc-tsk-700-governance-docs`, `agent/enc-iss-085-menu-fix`.

### Rules

- Never modify files in `/Users/jreese/enceladus/repo/` directly (main checkout is read-only for agents).
- Never reuse another agent's folder or branch.
- Run `git` and `gh` commands from your dedicated folder CWD — never from the shared checkout.
- Before starting, always confirm correct folder and branch.

---

## §9 Governance Data Dictionary (ENC-FTR-026)

**Load the governance data dictionary compact index at every session start**, before making any tracker, document, or deploy API calls.

### Session init — load compact index

```text
search(action="governance.dictionary")
```

Returns a compact index (~1k tokens) listing all entity names with field counts and descriptions. For full entity schemas, use on-demand lookups:

```text
search(action="governance.dictionary", arguments={entity: "tracker.task"})          # full schema
search(action="governance.dictionary", arguments={entity: "tracker.task", field: "status"})  # single field
search(action="governance.dictionary", arguments={entity: "tracker.task", field: "status", value: "open"})  # enum validation
search(action="governance.dictionary", arguments={entity: "tracker.lesson"})         # lesson ontology
search(action="governance.dictionary", arguments={entity: "tracker.plan"})           # plan schema
```

**Do NOT use** `governance.get("governance_data_dictionary.json")` for session init — it loads the full ~56KB / ~12.9k token dictionary into context.

### Transition evidence requirements

- `committed` → `{commit_sha}`
- `merged-main` → `{pr_id, merged_at}`
- `deploy-success` → `{deploy_evidence}` (structured GH Actions Jobs API object — see §11)
- `closed` (from deploy-success) → `{live_validation_evidence}`
- `revert` → `{revert_reason}`

---

## §13 Governance File Authority

> **⛔ governance.update IS NOT AVAILABLE in code-mode
> agent sessions.** Do not plan around it, attempt it,
> or defer it. It does not exist in this interface.

All mutations to the following governance files require
execution by a **privileged terminal agent** operating
under product-lead IAM (`io-dev-admin`) via direct S3
archive+put:

- `agents.md` → `s3://jreese-net/governance/live/agents.md`
- `governance_data_dictionary.json` → `s3://jreese-net/governance/live/governance_data_dictionary.json`

### Governance dictionary storage topology & sync propagation (ENC-TSK-I62)

`governance_data_dictionary.json` exists in **three** storage surfaces that MUST carry the same `version` for §13 lockstep:

1. **S3 live object** — `s3://jreese-net/governance/live/governance_data_dictionary.json` (env-prefixed `${S3EnvPrefix}governance/live/…` on the gamma stack).
2. **`governance-policies` DDB record** (`policy_id=governance_data_dictionary`) — the discrete `version` / `updated_at` attributes, surfaced as `governance.dictionary` `source.version`.
3. **The `dictionary_json` blob** inside that same DDB record (~322KB compact JSON — the LIVE-SERVED entities, embedding its own `version`), surfaced as `governance.dictionary` `dictionary_version`. **The MCP serves entities + `dictionary_version` from this DDB blob, NOT from S3.**

A §13 dictionary sync MUST update **all three** surfaces and fire `devops-document-api` `_governance_sync_push`. As of ENC-TSK-I62 (gamma I63 + v3-prod I64) this propagation is **automatic**: `_sync_governance_documents` writes the S3 dictionary change into the `governance-policies` record — discrete `version`+`updated_at` plus the `dictionary_json` blob (the verified **raw S3 bytes**, so byte-identical and inherently within the 400KB DynamoDB item limit; `#v` alias for the reserved `version` word; an S3-vs-DDB `entities` deep-equal **drift pre-check** aborts on mismatch rather than clobbering). This eliminated the manual `aws dynamodb update-item` that ENC-TSK-I61 required. **Verify** with `governance.dictionary` (`source.version` AND `dictionary_version` must equal the S3 version, entities unchanged) + `connection_health`. Prereqs (02-compute.yaml): the `devops-document-api` role needs `dynamodb:GetItem`+`UpdateItem` on `governance-policies${EnvironmentSuffix}` and the `GOVERNANCE_POLICIES_TABLE` env var. Note: `source.version` and `dictionary_version` are both live DDB reads (no TTL lag); this dictionary `version` is the mirror of the `governance_revision` token below but is versioned independently and is NOT part of the agents-bundle hash.

### Canonical governance bundle, deterministic hash, and the governance_revision token (ENC-TSK-I26 / ENC-FTR-116)

This subsection binds the hashing contract that the governance-version recompute (ENC-TSK-I27) implements and that the §13 acceptance gate verifies. It is the authoritative specification of *what* the governance content hash is computed over and *how*. (Authoritative design: DOC-6F7A14667E7D §4.3.)

**Canonical governance file set.** The bundle is the explicit set of `governance://` URIs for `agents.md` plus everything under `agents/` — i.e. `governance/live/agents.md` and every object under the `governance/live/agents/` prefix. This is an *explicit inclusion set*, not an implicit live directory listing: the recompute materializes it as a known manifest of URIs (recorded in the canonical governance-version record's `files[]`), so a stray or unexpected object under the prefix cannot perturb the hash. `governance_data_dictionary.json` is governed by §13 for write authority and carries the `governance_revision` mirror (its `version` field), but it is versioned independently and is NOT a member of the agents-bundle hash input.

**Ordering.** Files are ordered lexicographically by their `governance://` URI — byte-wise ascending over the URI string.

**Per-file fingerprint.** Each file's fingerprint is the object's S3 `x-amz-checksum-sha256`, decoded from base64 to **lowercase hex**. S3 returns the checksum base64-encoded; the existing `_compute_governance_hash` uses hex `hexdigest()` — normalize to lowercase hex everywhere to preserve continuity and avoid representation drift. The common path reads the immutable checksum via HeadObject/GetObjectAttributes with no body download. **Fallback:** when a legacy object has no stored checksum, compute a body SHA-256 and use its lowercase-hex digest; the writer SHOULD then re-PUT that object with `ChecksumAlgorithm=SHA256` to normalize future reads.

**Bundle root.** The bundle root is the SHA-256, expressed as lowercase hex, computed over the concatenation — for each file in canonical (lexicographic-URI) order — of: the URI bytes, a newline (`\n`), the per-file lowercase-hex fingerprint, and a newline (`\n`). This mirrors the structure of the existing catalog hash, so the resulting value stays directly comparable to today's `governance_hash`, but is now sourced from S3-immutable checksums plus object versionIds rather than a TTL-cached catalog with empty content hashes.

**governance_revision token + bump rule.** A monotonic, human-asserted version label is embedded in the bundle as a `Governance-Revision: YYYY-MM-DD.NN` line near the top of `agents.md` (mirrored by `governance_data_dictionary.json`'s `version` field). `YYYY-MM-DD` is the UTC date of the change; `NN` is a two-digit intra-day sequence starting at `01`, reset each new UTC date. **Bump rule:** increment the token on *every* §13 byte change to any `governance/live/*` file, keeping the `agents.md` line and the dictionary `version` in lockstep. The recompute (ENC-TSK-I27) binds `governance_revision` to the derived bundle-root `governance_hash` by the same canonical write: the record's `governance_hash` MUST equal the bundle root, and `governance_revision` is the human label bound to it. `governance_revision` is the writer's asserted intent; the derived `governance_hash` is machine truth. (The acceptance gate that cross-checks the two — the version-agreement / dual-signal discipline — is specified immediately below in "§13 acceptance: the version-agreement gate".)

### §13 acceptance: the version-agreement gate (ENC-TSK-I31 / ENC-FTR-116)

Supersedes the legacy "verify that `connection_health.governance_hash` changed after a sync" acceptance step (ENC-ISS-390). That step was unsatisfiable: a §13 direct-S3 write does not, by itself, rotate a TTL-cached or docstore-fallback hash, so the signal stayed frozen after a real change. The recompute (ENC-TSK-I27) re-homes the version signal onto the storage layer every governance write must traverse; this gate verifies that re-homed signal.

**The gate.** A §13 sync is ACCEPTED if and only if BOTH hold:

1. **Generation advanced.** The canonical `governance-version` record's monotonic `generation` is strictly greater than its value immediately before the write — the storage-event recompute fired and committed exactly one increment.
2. **Three-surface agreement.** All three surfaces report the SAME `governance_revision` AND the SAME `governance_hash`:
   - **S3-live** — the bundle root recomputed from the current `x-amz-checksum-sha256` of every file in the canonical set (the bundle contract above), plus the `governance_revision:` token read from live `agents.md`.
   - **Canonical DDB** — the `governance-version` record's stored `governance_hash` / `governance_revision`.
   - **MCP read** — the value `connection_health` serves (post-ENC-TSK-I29 it serves the canonical record, not a recomputed catalog or docstore fallback).

If `generation` did not advance, or any surface disagrees on either field, the sync is REJECTED — investigate before declaring the governance change live.

**Surfaces as projections (one-way rebuild-from-canonical).** S3-live is the content source of truth; the canonical `governance-version` DDB record is the derived authoritative version signal; the MCP/module caches are projections of it. The reconcile direction is one-way — rebuild the projections from the canonical record, never reconcile co-equal surfaces against each other. This dissolves the ENC-LSN-055 manual three-surface reconcile into a single rebuild-from-canonical step. On a momentary disagreement (sub-second event lag between the write and the recompute), the live-derived recompute is the tie-break authority; evaluate the gate after the recompute has committed.

**Dual-signal discipline.** `governance_revision` is the writer's asserted intent (the human label); `governance_hash` is machine truth (derived from content). The recompute binds them by the same canonical write. Two failure modes are surfaced, not hidden:

- A **byte change without a `governance_revision` bump** — the hash moves but the revision is stale → FAILS the gate (the writer forgot to bump the revision).
- A **`governance_revision` bump without a byte change** — the revision moves but the bundle hash is identical → FAILS the gate (a claimed change that did not land, or a no-op write).

Both indicate a discipline lapse and block acceptance until reconciled.

**Retain the ENC-LSN-055 zero-removals merge.** The additive, self-verified, zero-KEY-removals reconcile-and-merge remains the required way to edit `agents.md` and `governance_data_dictionary.json`: read live, merge additively, self-verify that no existing key or section was dropped, then archive+put. What changes is the acceptance signal — closure now gates on this version-agreement gate (generation advanced AND three-surface agreement) rather than on a manual three-surface eyeball.

**Revision token mechanics.** The recompute extracts `governance_revision` from a line-anchored `governance_revision:` token embedded in the HTML comment beside the display label at the top of `agents.md`. Keep that machine token, the `**Governance-Revision**` display label, and the dictionary `version` in lockstep on every §13 write; the gate's three-surface revision agreement depends on it.

### Agent protocol when governance file changes are required

An agent session that produces governance file content
**must not** attempt to write it. Instead, the agent:

1. Prepares the full updated file content in memory.
2. Appends a `GOVERNANCE_SYNC_REQUIRED` HANDOFF block to
   the task worklog (see canonical format below).
3. Advances to `coding-complete` and awaits coordination
   lead dispatch of a product-lead terminal session.

The coordination lead reads the HANDOFF block and
dispatches a Codex terminal agent to execute the S3 write.

### Canonical HANDOFF block format

--- GOVERNANCE_SYNC_REQUIRED ---
file_name: <agents.md | governance_data_dictionary.json>
content_source: <repo file path + commit SHA, or document ID>
s3_target: s3://jreese-net/governance/live/<file_name>
archive_path: s3://jreese-net/governance/history/<file_name>/<YYYYMMDDTHHMMSSZ>.bak
change_summary: <one-line description of what changed>
--- END GOVERNANCE_SYNC_REQUIRED ---

### Why this constraint exists

The `governance.update` MCP tool routes through
`coordination_api` which requires product-lead IAM scope
(`io-dev-admin`). Code-mode agent sessions authenticate
via Cognito OAuth with `enceladus-agent-cli` IAM — this
principal has explicit deny on all S3 writes. The
architectural separation ensures governance files cannot
be modified without product-lead authorization, even by
accident.

### Inter-session continuity → document_subtype=handoff (ENC-TSK-G12)

Any document that carries work or context from one
agent session to another — dispatch briefs, work
units, report-back containers, sub-handoffs — MUST be
created as `document_subtype=handoff` via the dedicated
`document.create_handoff` action. No exceptions.
Inter-session continuity MUST NOT be carried by
`document_subtype=doc`, ad-hoc notes, or free-text
worklog entries. (The `GOVERNANCE_SYNC_REQUIRED`
worklog block above is the one narrow exception, and
only to request a governance-file S3 sync.)

Every handoff MUST carry the canonical mandate shape
(DOC-B8641F56EED3 §VIII, implemented in
`tools/enceladus-mcp-server/handoff_mandate.py`):

- `goal` — the objective the dispatched session pursues
- `constraints` — boundaries it must respect
- `prior_findings` — context already established
- `tools_allowed` — the permitted tool surface
- `output_schema` — the required result shape
- `budget_tokens` — the token ceiling for the work

plus the envelope fields `source_record_id`,
`handoff_status`, `action_checklist`, and
`verification_criteria`. The document_api
handoff-detection guard SHOULD move from warn toward
enforcement for `doc`-subtype titles matching handoff
patterns via a narrow deterministic reserved-token
guard (exact token, e.g. `HANDOFF:`) with an
ENC-ISS-158 self-correcting error envelope — not a
broad matcher (evaluation DOC-AB684F81E23A).

---

## Escalation Protocol (ENC-ISS-142 / ENC-FTR-121)

When a lifecycle gate, checkout invariant, deploy-evidence requirement, or any enforced workflow blocks progress, agents MUST escalate, not circumvent. Reshaping tracker fields, force-closing, clearing or bypassing a subtask gate, changing a sealed transition_type, or otherwise editing governed state to route around a gate is prohibited. A blocked gate encodes a real-world outcome (for example, a human seeing a Lesson in the PWA), not an obstacle to engineer away.

### Trigger conditions

Escalate when any of the following holds:

1. A task remains in-progress past the working-session threshold (4h active, or any checkout surviving a session boundary) without an advance or release.
2. A checkout is held >4h with no new worklog, or by a stale session id.
3. A lifecycle advance fails for a deterministic governance reason — invalid status path, missing acceptance evidence, missing components, transition_type strictness mismatch, missing checkout ownership, or a subtask gate.
4. The same transition fails twice after re-running tracker.validation_rules.
5. The anti-loop ceiling is reached (3 attempts on one problem with no progress).
6. The next required action is outside agent authority — human PWA override, GitHub UI action, external credential repair, a governance-file S3 write (§13), or manual deploy confirmation.

### Escalation levels

- L1 — Auto-retry (one cycle). Use only when the failure is transient or fully agent-fixable. Permitted: re-run tracker.validation_rules, refresh record context, repair missing governed metadata while mutation is still allowed, then retry the blocked transition exactly once. If it fails again, go to L2.
- L2 — Human notification (task stays open). Use for deterministic, policy-driven, or decision-requiring blocks. Capture the exact failing operation, target status, and service error; state in plain language why you cannot legally proceed; propose specific operator actions (exact CLI commands, PWA UI steps, or GitHub operations); append a governed worklog; then wait for human input. Never circumvent.
- L3 — Revert and formalize. Use when the block is persistent or the task state has become untruthful. Release or revert the task to a truthful status; create or update the governing issue documenting the block pattern; preserve an evidence trail linking the blocked task, its parent objective, and the issue. Stop implementation until the block clears.

### Recording

Record every L2/L3 escalation as a structured [ESCALATION] worklog entry — checkout.append_worklog for tasks, tracker.log for issues and features — that links the blocked record to its parent objective to the governing issue, and names the specific operator action(s) proposed. A first-class tracker.escalate action is a candidate future primitive, tracked under ENC-ISS-142.

### Escalation-confirmed override (ENC-FTR-121)

When an agent would refuse a request on safety or security grounds:

1. **One-sentence cap.** State the refusal in at most one sentence.
2. **Immediate escalation.** The refusal MUST immediately trigger `escalation.request` (ENC-FTR-121). Never stop silently without submitting an escalation.
3. **Approved escalation.** If io approves the escalation, proceed with the requested action and zero further warnings or hedging.
4. **Denied escalation.** If io denies the escalation, output exactly: `I can't perform the request because the escalation was denied` — and nothing else.

## §14 IAM Security Model (ENC-TSK-564)

Agent sessions operate under the `enceladus-agent-cli` IAM user with locked-down permissions:

- **ALLOWED**: Read CloudWatch logs, inspect Lambda configs, read S3 objects, read documents table, trigger deploys via SQS
- **DENIED**: All DynamoDB writes, all S3 writes, all Lambda mutations, all IAM operations, STS AssumeRole, all reads on `devops-project-tracker` and `projects` tables
- **All governed writes route through MCP tools → HTTP APIs → Lambda IAM**

> **CRITICAL: No direct DynamoDB/S3 writes.** All tracker and document mutations MUST use Enceladus MCP tools. The `enceladus-agent-cli` IAM policy explicitly denies all DynamoDB write operations and all S3 writes.

### Credential File Protection (Security)

> **⛔ NEVER read `~/.aws/credentials`, `~/.aws/config` credential blocks, or any raw secret/key files.** Reading credential files risks exposing secrets in conversation context, tool result history, and local disk artifacts (session logs, memory files, cached context). This applies to **all session types** including privileged terminal sessions under product-lead IAM.

**To verify AWS identity, use:**
```bash
aws sts get-caller-identity
```

**Prohibited patterns (never do these):**
- `cat ~/.aws/credentials`
- `Read(file_path="~/.aws/credentials")` or any home-directory credential path
- Grepping for `aws_access_key_id` or `aws_secret_access_key` in config files
- Storing AWS keys, tokens, or credential file contents in memory files, worklogs, or documents

**Rationale:** Agent tool results persist in conversation context and may be written to disk via session logs or memory. A single `cat ~/.aws/credentials` leaks long-lived IAM keys into artifacts that outlive the session. `sts get-caller-identity` confirms the active principal without exposing any secret material.

---

## §Plan Capture Protocol (ENC-FTR-040)

**MANDATORY after ExitPlanMode approval.** Before any implementation — no worktree, no file edits, no task checkout — execute the full Plan Capture Protocol:

1. Load protocol: `search(action="governance.get", arguments={file_name: "agents/plan-capture.md"})`
2. Follow every step: task tree creation → plan document → cross-linking
3. Only then proceed to implementation

Applies to ALL agent types. Skipping is a governance violation. If MCP is unavailable, log the failure and surface it to the user before continuing.

### Quick reference (full protocol in governance file)

1. Get governance hash
2. Create parent task with `[Plan]` prefix
3. Create phase tasks (set parent)
4. Create step tasks within phases (set parent)
5. Update parent with `subtask_ids`
6. Create plan document via `documents.put`
7. Cross-link all tasks to document
8. Log completion
9. Proceed to implementation

---

## Logging Tags

Use these tags in tracker worklogs for consistent parsing:
- `[START]` — beginning of work
- `[INFO]` — status update or note
- `[SUCCESS]` — successful completion of a step
- `[ERROR]` — error encountered
- `[END]` — work complete
- `[LESSON]` — citing a lesson that influenced a decision

## Anti-Loop Rule

If stuck after 3 attempts on the same problem, create a tracker issue documenting the block and move on to the next task.

---

## §15 V3 Production Lock (ENC-PLN-019)

> **Effective 2026-04-11.** Tag: `v3.0.0-restored` (cb34be7).

### Production architecture (locked)
- **Architecture:** x86_64 — enforced by CFN `!If [IsGamma, arm64, x86_64]`, CI guard (`tools/verify_lambda_arch_parity.py`), and deploy.sh env guards
- **Runtime:** python3.11 — enforced by CFN `!If [IsGamma, python3.12, python3.11]` and CI guard
- **No arm64 or python3.12 on production** until v4 cutover is explicitly approved

### Gamma architecture (v4 target)
- **Architecture:** arm64 (Graviton2), **Runtime:** python3.12
- 22 gamma Lambdas deployed, full parity with prod manifest
- All 27 deploy workflows support `ENVIRONMENT_SUFFIX` for gamma targeting

### CI enforcement
- `tools/verify_lambda_arch_parity.py` runs in `.github/workflows/ci.yml`
- Blocks any PR that introduces hardcoded arm64 or python3.12 in prod CFN declarations
- Validates deploy scripts with arm64 references have `ENVIRONMENT_SUFFIX` conditional gating

### Reference
- Full details: `docs/v3-production-lock.md` in repo
- COE: DOC-2CACF0D1E7E6
- Plan: ENC-PLN-019 (DOC-191E709E43C5)

---

## §16 Dispatch-Target Declaration, Agent-Type Selection & Wave Sequencing Output Specification (ENC-FTR-117 / ENC-TSK-I41 / ENC-TSK-I67)

> Promotes the interim brief DOC-359655466119 into permanent agent rules. Applies to EVERY governed session that generates a dispatch prompt, spawns a child session, or sequences a multi-task wave — not only coord-lead. Distinct from agents/dispatch-subagent.md, which governs subagent checkout/approval-gate inheritance; this section governs WHERE a dispatch routes, WHICH agent type runs it, and the required structural OUTPUT FORMAT for any wave or multi-dispatch. Source authority: DOC-BADA8D801099 §3.

### Rule 1 — Dispatch-Target Declaration (required field)

Every dispatch prompt a session generates MUST carry a `Target:` line. No exceptions. A dispatch prompt with no `Target:` line is malformed — regenerate it before handing it to io.

The target resolves to exactly one of:

- `existing-session [ENC-SES-NNN]` — a follow-up routed to a live, named session.
- `new-session [agent-type label]` — a spawn; name the surface and model (e.g. `Claude Code Desktop Sonnet 4.6`).

**Forward compatibility.** `ENC-SES-NNN` and `ENC-AGT-NNN` are server-allocated identifiers minted by the ENC-FTR-117 `coordination(action=agent.*)` allocation surface — stood up once with value-identical id-spaces across v3-prod and v4 (DOC-05C45B438FC1 build-once gate). Until that surface is live, use a descriptive label (surface + model) for a new-session target; once it is live, a new-session target resolves to the minted `ENC-AGT-NNN`. NEVER invent an `ENC-SES-NNN` or `ENC-AGT-NNN` value — those IDs are server-allocated, never agent-predicted (the §6 ID Boundary Rule applies).

Minimum dispatch-block shape:

    Target: new-session | Claude Code Desktop Sonnet 4.6
    Assigned work: [task/feature id + one-line description]
    Rationale: [why this target + agent-type; justify any up-tier]
    [... remainder of prompt ...]

### Rule 2 — Agent-Type Selection (cheapest sufficient)

When spawning a new session, select the CHEAPEST agent type that can complete the work reliably. NEVER default to the most powerful available model; justify every up-tier choice explicitly on the dispatch block's `Rationale:` line.

The agent-type directory's telemetry is the evidence base for this choice once ENC-FTR-117 populates it. Until then, apply this heuristic:

- Code execution, file edits, deploys, git, well-defined tracker mutations → Claude Code Desktop or Codex terminal, Sonnet 4.6.
- Architectural reasoning, cross-record synthesis, multi-session orchestration, ambiguous scope requiring judgment → Claude Desktop / claude.ai, Opus-class.
- Mechanical reads, single lookups, low-stakes informational queries → Haiku-class where the surface offers it.
- io-dev-admin product-lead terminal (S3 writes, governance files, HANDOFF execution) → a surface constraint, NOT an agent-type choice; always route `GOVERNANCE_SYNC_REQUIRED` blocks here regardless of model.

If two tiers seem plausible, choose the cheaper one, record the assumption under `Rationale:`, and let io override. If the right target is genuinely ambiguous, surface the ambiguity to io rather than guessing.

Model tier tracks task ambiguity and judgment density, not blast radius. High-stakes but well-specified work (a known schema, a defined integration) stays at the cheaper tier; its risk is managed by the reviewer gate, not by a larger model. Reserve up-tiers for genuinely ambiguous or synthesis-heavy work.

> When ENC-FTR-117 reaches `closed`, the `coordination(action=agent.register)` allocation call replaces the manual `Target:` line and directory telemetry supersedes this section's interim heuristic; DOC-359655466119 (the interim brief) is thereafter design-rationale only, not operative.

### Lazy-Load Contract — §16 Required Before Any Dispatch or Wave

Any session generating a dispatch block OR sequencing a wave MUST load §16 of agents.md before emitting. Add to the lazy-load trigger set:

    dispatch/wave: §16

Trigger: `search(action="governance.get", arguments={file_name: "agents.md"})` and read §16 before emitting any dispatch block or wave output. A session that emits a dispatch block or wave without having loaded §16 is non-compliant and its output must be regenerated.

### Wave Sequencing Output Specification (operationalized from DOC-359655466119 via ENC-TSK-I67)

When a session is asked to plan, sequence, or generate more than one dispatch at once — a wave — it produces the structure below, every time. This is the standing output contract; it replaces ad-hoc prose so io never has to re-ask for the structured form. The format evolves here (bump Spec Version on change), and sessions use the current version.

**Spec Version: v1 (2026-06-28).**

A wave output has six parts, in order:

1. **Anchor and governing docs.** State the plan or scope and the orchestration role. List each governing rule-doc in play with a one-line note on what it governs (for example: freeze doc to exception scope; this spec to Target line and tiering; an exception doc to which tasks are prod-authorized).
2. **Sequencing and Triggers table.** One row per task in the wave, columns: Task (id + short name); Status (live tracker status); Launch (NOW or hold); Trigger (the precise unblock condition — `none`, or a named closure such as "I38 closed" — never left implicit); Surface and Agent (the resolved Target: surface + model, or the product-lead terminal for governance-file work); Parallel Group (a batch label A, B, C grouping rows that can run concurrently).
3. **Parallelism summary.** Which groups fire concurrently and which single item is on the critical path (the longest dependency chain). State explicitly what blocks nothing and can run anytime. The reader must see at a glance what to launch now versus what is held.
4. **LAUNCH NOW.** The full, ready-to-fire F3 dispatch blocks for every row whose Trigger is `none` or NOW.
5. **PRE-STAGED (HOLD).** Full F3 blocks for downstream rows, each tagged `[HOLD -> launch when <trigger>]`, so the next block is ready to fire the instant its trigger fires and the reader never waits on the orchestrator to regenerate.
6. **Coordination tail.** What the orchestrator drives autonomously as tasks land (verify and route HANDOFFs, stamp feature ACs, complete the plan) and the loop-closure condition.

#### F3 dispatch block — internal format

Each block in parts 4 and 5 carries, in order:

- `Target:` — per Rule 1 (existing-session [ENC-SES-NNN] or new-session [surface + model]).
- `Assigned work:` — task or feature id plus one line.
- `Rationale:` — the target and tier justification per Rule 2 (only an up-tier needs defending; cheapest-sufficient is the silent default).
- `BOOT` — init steps: set PROJECT, fetch the session prompt, connection_health then capture governance_hash then checkout.
- `CHECKOUT NOTE` — known component or transition_type reconciliation gotchas, where the orchestrator can pre-empt a checkout gate.
- `ASSIGNED WORK` — the concrete deliverables.
- constraints — any load-bearing, v4-seam, or isolation requirement.
- `DEPLOY` — deploy authority + lane, or "no deploy" for docstore/governance work.
- `DONE WHEN` — explicit closure criteria (ACs evidenced, deploy_evidence stamped, advance to <status>).
- `Report to io + orchestrator at:` — the checkpoint cadence.

#### Principles

- Every row has an explicit trigger — NOW or a named closure. "What unblocks this" is never left to inference.
- Parallel groups are read off the dependency graph: rows with satisfied dependencies and no shared-resource contention run concurrently. Name the groups so the reader batches at a glance.
- Mark exactly one critical path so the reader knows the single item that matters most.
- Pre-stage downstream blocks (HOLD + trigger) so launching the next step is a copy-paste, not a regeneration request.
- After reading a wave output, the reader's job is to launch the NOW set and report closures; the orchestrator does the rest.

---
