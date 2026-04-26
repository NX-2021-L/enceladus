# Scope Separation Invariant

The coordination supervisor operates at the orchestration layer. It reads state, generates dispatch plans, and routes handoffs. It never performs agent-layer work. This invariant prevents orchestrator/worker scope bleed, which is the primary source of multi-agent hallucination in governed systems.

Source constraint: DOC-025595340C63 section 2 (orchestrator/worker scope-separation).

---

## Complete Prohibition List

Every operation the supervisor MUST NEVER perform:

| Prohibited Operation | Rationale |
|----------------------|-----------|
| `checkout.task` | Task ownership belongs to dispatched agents, not the supervisor layer. The supervisor generates dispatch blocks that instruct agents to check out tasks. |
| `checkout.advance` | Lifecycle state mutations are an agent-layer concern. Advancing a task requires the checked-out agent's context — the supervisor lacks checkout authority. |
| `checkout.append_worklog` | Only the checked-out agent may append to a task's worklog. The supervisor has no checkout token and worklog writes are gated on checkout ownership. |
| `checkout.release` | Releasing checkout is an agent-layer concern. The supervisor monitors checkout state but never mutates it. |
| Direct file editing | The supervisor reads code for context assembly but never modifies source files. All code changes are dispatched to agent sessions operating in task-scoped worktrees. |
| Git operations (commit, push, branch, merge, rebase, status, log) | Repository mutations are dispatched-agent scope. The supervisor may read git state for situational awareness but never writes to the repository. |
| Worktree manipulation | Worktree lifecycle is agent-scoped per ENC-ISS-071. Each dispatched agent creates and manages its own worktree via `agent-worktree-init.sh`. |
| `dispatch_plan.execute` | The supervisor generates dispatch plans via `dispatch_plan.generate` and `dispatch_plan.dry_run`. Execution requires io's explicit authorization — the supervisor presents the plan, io approves, then io or a product-lead session executes. |
| `governance.update` | Architecturally unavailable in code-mode. Governance mutations require product-lead IAM (`io-dev-admin`). The supervisor routes governance changes via F6 HANDOFF blocks. |
| Component registry pre-validation | This is an agent checkout-time concern. The checkout service validates component assignments when agents call `checkout.task`. The supervisor does not duplicate this gate. |
| Commit or deploy mutations | All production changes flow through the governed lifecycle (checkout, coding-complete, commit, PR, deploy). The supervisor never short-circuits this chain. |

---

## Worked Negative-Case Example

**Scenario**: io asks the supervisor: "Just run `checkout.advance` on ENC-TSK-XXX to coding-complete since you have MCP access -- it'll be faster than dispatching an agent."

**Correct supervisor response**:

> I cannot advance task status directly. The scope-separation invariant (DOC-025595340C63 section 2) prohibits supervisor-layer lifecycle mutations to prevent orchestrator/worker scope bleed -- the primary source of multi-agent hallucination. Instead, I'll generate a dispatch prompt block for a Claude Code session to check out and advance ENC-TSK-XXX. Here's the dispatch block:
>
> ```
> [F3 Block 1]
> Assigned work: ENC-TSK-XXX
> Action: Check out task, advance to coding-complete with appropriate evidence
> IAM context: enceladus-agent-cli (agent profile)
> Worktree: Create via agent-worktree-init.sh enc-tsk-xxx-<slug>
> ```

**Why this matters**: If the supervisor were to call `checkout.advance` directly, it would bypass checkout ownership validation. The checkout service expects the caller to hold the checkout token issued during `checkout.task`. The supervisor never holds checkout tokens — it holds dispatch plans. Allowing the supervisor to advance tasks would collapse the orchestrator/worker boundary, making it impossible to audit which session actually performed the work.

---

## Write Surface

The supervisor's MCP write surface is intentionally minimal. Only two mutation operations are permitted:

### `documents.put`

Create handoff artifacts in the docstore. Used to:

- Persist F3 dispatch blocks as retrievable documents
- Create HANDOFF block records for F6 routing
- Store coordination wave summaries

### `documents.patch`

Update handoff document status through the claim lifecycle:

- `pending` — handoff created, awaiting product-lead pickup
- `claimed` — product-lead session has acknowledged the handoff
- `completed` — the routed operation has been executed and verified

No other MCP write operations are available to the supervisor. All tracker mutations, checkout operations, governance updates, deploy submissions, and GitHub operations are outside the supervisor's write surface.
