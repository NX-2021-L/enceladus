# F2: Handoff Document Generator

Reference for the Coordination Supervisor Skill handoff generation capability.

Handoff documents are the supervisor's primary output artifact. The supervisor
NEVER executes handoff actions itself -- it generates a `handoff`-subtype
document via `documents.put` and io routes it to the appropriate downstream
session (agent, product-lead terminal, or coordination lead).

All templates below emit documents with `document_subtype: "handoff"`
(ENC-FTR-077 canonical subtype).

---

## Two-Step ID Boundary Pattern

When creating any handoff document, the supervisor MUST follow the two-step
boundary:

1. **Create** -- Call `documents.put` with all required fields. Do NOT predict
   or hardcode the `document_id`. The docstore assigns it.
2. **Read** -- Extract the assigned `document_id` from the `documents.put`
   response.
3. **Patch (optional)** -- If the H1 title should include the doc ID for
   traceability, issue a `documents.patch` to update the title after creation.

Violating this pattern (e.g., embedding a guessed `DOC-*` ID in the body
before creation) produces dangling references.

---

## Template 1: Dispatched Agent Work Unit

Use when dispatching a Claude Code desktop session or Codex terminal agent to
execute a scoped task.

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `document_subtype` | `"handoff"` | Canonical handoff subtype (ENC-FTR-077) |
| `source_record_id` | string | Tracker ID of the task being handed off (e.g., `ENC-TSK-1234`) |
| `target_provider` | string | Execution target: `claude-code-desktop`, `codex-terminal`, or `claude-code-cli` |
| `scope_statement` | string | What the agent session SHOULD do. Scoped to a single deliverable. |
| `scope_prohibitions` | string[] | What the agent MUST NOT do. Explicit exclusions prevent scope creep. |
| `acceptance_criteria` | string | Pointer to acceptance criteria on the source task record, or inline criteria if the task has none. |
| `prerequisite_state` | object | State that must be true before the agent begins (e.g., `{"task_status": "open", "branch": "none"}`) |
| `action_checklist` | string[] | Ordered steps the downstream agent should execute |
| `verification_criteria` | string[] | How the supervisor (or io) confirms the handoff was fulfilled |

### Worktree and Branch Convention

The dispatched agent MUST create a worktree with branch name:

```
agent/<tracker-id>-<slug>
```

Example: `agent/enc-tsk-1234-fix-deploy-gate`

The slug is derived from the task title, lowercased, hyphenated, max 40 chars.

### Boot Prompt

Step 1 of every dispatched agent session fetches the dispatched agent session
prompt:

```
documents.get(document_id="DOC-FFB4C9D87BCC")
```

This document contains the full boot sequence for agent sessions that were
dispatched (as opposed to user-initiated). The handoff document itself is
referenced inside the boot prompt context.

### Example `documents.put` Call

```json
{
  "action": "documents.put",
  "arguments": {
    "project_id": "enceladus",
    "title": "Handoff: ENC-TSK-1234 Fix deploy gate timeout",
    "document_type": "handoff",
    "document_subtype": "handoff",
    "content": "## Dispatched Agent Work Unit\n\n**Source Task:** ENC-TSK-1234\n**Target:** claude-code-desktop\n\n### Scope\nFix the deploy gate timeout in `backend/lambda/deploy-gate/lambda_function.py`...\n\n### Scope Prohibitions\n- Do NOT modify infrastructure stacks\n- Do NOT deploy -- commit and PR only\n\n### Acceptance Criteria\nSee ENC-TSK-1234 acceptance_criteria field.\n\n### Action Checklist\n1. Fetch DOC-FFB4C9D87BCC (boot prompt)\n2. Create worktree: agent/enc-tsk-1234-fix-deploy-gate\n3. Checkout task via execute(checkout.task)\n4. Implement fix\n5. Run tests\n6. Commit and open PR\n7. Advance checkout to coding-complete\n\n### Verification\n- PR passes CI\n- Checkout evidence contains CAI token",
    "source_record_id": "ENC-TSK-1234",
    "prerequisite_state": {"task_status": "open"},
    "action_checklist": [
      "Fetch DOC-FFB4C9D87BCC",
      "Create worktree agent/enc-tsk-1234-fix-deploy-gate",
      "Checkout task",
      "Implement fix",
      "Run tests",
      "Commit and open PR",
      "Advance to coding-complete"
    ],
    "verification_criteria": [
      "PR passes CI checks",
      "Checkout evidence contains CAI token",
      "No scope prohibition violations"
    ]
  }
}
```

---

## Template 2: GOVERNANCE_SYNC_REQUIRED

Use when a governance file must be updated in S3. Only a product-lead terminal
session running under the `io-dev-admin` IAM role may write to the governance
S3 paths. The supervisor generates this handoff; io routes it to the
product-lead terminal.

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `document_subtype` | `"handoff"` | Canonical handoff subtype (ENC-FTR-077) |
| `source_record_id` | string | Tracker ID that triggered the governance change |
| `file_name` | string | Target governance file: `agents.md` or `governance_data_dictionary.json` |
| `content_source` | string | Where the new content lives: repo file path + commit SHA, or a document ID |
| `s3_target` | string | Destination: `s3://jreese-net/governance/live/<file_name>` |
| `archive_path` | string | Backup path: `s3://jreese-net/governance/history/<file_name>/<ISO-timestamp>.bak` |
| `change_summary` | string | One-line description of what changed and why |
| `prerequisite_state` | object | State required before sync (e.g., PR merged, commit SHA verified) |
| `action_checklist` | string[] | Steps for the product-lead terminal |
| `verification_criteria` | string[] | How to confirm the sync succeeded |

### Boot Prompt for Product-Lead Terminal

The product-lead terminal session should:

1. Verify IAM identity is `io-dev-admin` (not `enceladus-agent-cli`)
2. Download the current live file as the archive backup
3. Upload the new content to the live path
4. Run `connection_health()` to verify the governance hash changed
5. Confirm the new hash matches expected content

### Example `documents.put` Call

```json
{
  "action": "documents.put",
  "arguments": {
    "project_id": "enceladus",
    "title": "GOVERNANCE_SYNC_REQUIRED: agents.md update for ENC-TSK-900",
    "document_type": "handoff",
    "document_subtype": "handoff",
    "content": "## Governance Sync Required\n\n**File:** agents.md\n**Source:** repo `tools/enceladus-mcp-server/governance/agents.md` @ commit abc1234\n**S3 Target:** s3://jreese-net/governance/live/agents.md\n**Archive:** s3://jreese-net/governance/history/agents.md/2026-04-16T12:00:00Z.bak\n\n### Change Summary\nAdded section 3.15 documenting the checkout evidence schema for deploy-success transitions.\n\n### Action Checklist\n1. Verify IAM identity is io-dev-admin\n2. aws s3 cp s3://jreese-net/governance/live/agents.md s3://jreese-net/governance/history/agents.md/2026-04-16T12:00:00Z.bak\n3. aws s3 cp tools/enceladus-mcp-server/governance/agents.md s3://jreese-net/governance/live/agents.md\n4. connection_health() -- verify hash changed\n\n### Verification\n- Archive backup exists at history path\n- connection_health() returns new governance hash\n- governance.get('agents.md') returns updated content",
    "source_record_id": "ENC-TSK-900",
    "prerequisite_state": {"pr_merged": true, "commit_sha": "abc1234"},
    "action_checklist": [
      "Verify IAM identity is io-dev-admin",
      "Archive current live file to history path",
      "Upload new content to live path",
      "Verify governance hash via connection_health()"
    ],
    "verification_criteria": [
      "Archive backup exists at history/<file_name>/<timestamp>.bak",
      "connection_health() returns updated governance hash",
      "governance.get returns new content"
    ]
  }
}
```

---

## Template 3: Coordination Lead Session Init

Use when initializing a new coordination lead session to hand off ongoing work
context -- plan execution, multi-task orchestration, or session continuity.

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `document_subtype` | `"handoff"` | Canonical handoff subtype (ENC-FTR-077) |
| `source_record_id` | string | Plan ID or parent task ID scoping the work |
| `assigned_work` | string | Plan ID (e.g., `ENC-PLN-020`) or task scope description |
| `session_prompt_ref` | string | `DOC-586FB8D3DF02` -- Coordination Lead Session Prompt |
| `boot_prompt_ref` | string | `DOC-38CEFAE346E6` -- Coordination Lead Boot Prompt |
| `governance_hash` | string | Current governance hash from `connection_health()` |
| `active_plan_status` | string | Summary of the plan's current state -- completed phases, active phase, blockers |
| `carry_forward_items` | string[] | Key context the new session must be aware of |
| `prerequisite_state` | object | What must be true before the session starts |
| `action_checklist` | string[] | Boot sequence for the coordination lead |
| `verification_criteria` | string[] | How to confirm the session initialized correctly |

### Example `documents.put` Call

```json
{
  "action": "documents.put",
  "arguments": {
    "project_id": "enceladus",
    "title": "Coordination Lead Session Init: ENC-PLN-020 Phase 3",
    "document_type": "handoff",
    "document_subtype": "handoff",
    "content": "## Coordination Lead Session Init\n\n**Assigned Work:** ENC-PLN-020 (v3 Production Restoration)\n**Session Prompt:** DOC-586FB8D3DF02\n**Boot Prompt:** DOC-38CEFAE346E6\n**Governance Hash:** sha256:abc123...\n\n### Active Plan Status\nPhases 1-2 complete. Phase 3 in progress: R3 (Lambda deploy pipeline) blocked on deploy.sh canonicalization. R4-R5 pending.\n\n### Carry-Forward Items\n- Deploy gate script at backend/lambda/deploy-gate/deploy.sh needs x86_64 assertion\n- ENC-ISS-088 Cloudflare 1010 workaround verified for Lambda-to-Lambda calls\n- Checkout service deployed and stable\n- No open governance sync requests\n\n### Action Checklist\n1. Fetch DOC-586FB8D3DF02 (session prompt)\n2. Fetch DOC-38CEFAE346E6 (boot prompt)\n3. Run connection_health() -- verify governance hash matches\n4. Load plan context: get_compact_context(mode='record', record_id='ENC-PLN-020')\n5. Review open tasks: tracker.list(project_id='enceladus', status='open')\n6. Summarize session brief to user\n\n### Verification\n- Governance hash matches carry-forward value\n- Plan context loaded without errors\n- Open task list retrieved",
    "source_record_id": "ENC-PLN-020",
    "prerequisite_state": {"plan_status": "in-progress"},
    "action_checklist": [
      "Fetch DOC-586FB8D3DF02 (session prompt)",
      "Fetch DOC-38CEFAE346E6 (boot prompt)",
      "Verify governance hash via connection_health()",
      "Load plan context via get_compact_context",
      "Review open tasks",
      "Deliver session brief"
    ],
    "verification_criteria": [
      "Governance hash matches expected value",
      "Plan context loaded successfully",
      "Open task list retrieved",
      "Session brief delivered to user"
    ]
  }
}
```

---

## Lambda-Deploy Rule (v3)

> **MANDATORY.** Every handoff document that includes a Lambda deployment step
> MUST comply with these rules. Violations caused Sev1 incident ENC-TSK-1292.

### Rule 1: Canonical Deploy Script

All Lambda deploy handoffs MUST reference the canonical deploy script:

```
backend/lambda/<function_name>/deploy.sh
```

The handoff document MUST NOT embed ad-hoc `zip` commands, inline packaging
logic, or any deployment sequence that bypasses the deploy script. All
packaging, zipping, and upload logic is encapsulated in `deploy.sh`.

### Rule 2: Architecture and Runtime Assertions

The handoff MUST include architecture and runtime assertions derived from the
**live Lambda configuration**, not from assumptions or documentation:

```bash
aws lambda get-function-configuration \
  --function-name <function_name> \
  --query '{Architecture: Architectures[0], Runtime: Runtime}'
```

The handoff action checklist MUST include a step that verifies the live config
matches the expected architecture (e.g., `x86_64`) and runtime (e.g.,
`python3.11`) BEFORE any deploy operation proceeds.

### Rule 3: DOC-733D76F4849B Lessons (L1-L3)

Every Lambda-deploy handoff MUST cite these lessons from the v3 production
restoration post-mortem (DOC-733D76F4849B):

| Lesson | Statement | Handoff Implication |
|--------|-----------|---------------------|
| **L1** | Observability precedes deployability | Handoff must include a pre-deploy health gate step (`tools/pre-deploy-health-gate.sh`) |
| **L2** | Manual Lambda deploys use canonical script | Handoff must reference `backend/lambda/<fn>/deploy.sh`, never ad-hoc commands |
| **L3** | Architecture/runtime declared not discovered | Handoff must assert expected arch/runtime and verify against live config |

### Lambda-Deploy Action Checklist Fragment

Any handoff that includes a Lambda deploy MUST include these steps in its
`action_checklist`:

```
1. Run pre-deploy health gate: tools/pre-deploy-health-gate.sh
2. Verify live Lambda config:
   aws lambda get-function-configuration --function-name <fn>
   Assert: Architecture=x86_64, Runtime=python3.11
3. Execute canonical deploy script: backend/lambda/<fn>/deploy.sh
4. Verify deployment:
   aws lambda get-function-configuration --function-name <fn>
   Confirm update timestamp changed
5. Smoke test the deployed function
```

---

## Migration Note

Six organic handoff patterns exist in the docstore from before ENC-FTR-077:

- Dispatch {Letter} (e.g., Dispatch A, Dispatch B)
- HANDOFF
- GOVERNANCE_SYNC_REQUIRED
- EXECUTION_REQUIRED
- Coordination Agent Status Handoff
- TSK-scoped Handoff

All new handoff documents MUST use `document_subtype: "handoff"` as defined by
ENC-FTR-077. Legacy documents retain their original shape but are not templates
for new work. The three templates in this file are the canonical patterns going
forward.
