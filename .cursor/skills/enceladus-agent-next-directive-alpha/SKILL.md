---
name: enceladus-agent-next-directive-alpha
description: "Compile a precise, copy-pasteable .md directive for a terminal agent session given that agent's last surface output, using the Enceladus philosophy lens (DOC-0CAD28643E2F Inception Principle, DOC-33EB705DE23D ontological discipline, DOC-E2379D980FA2 adjacency and Gödelian amendment). Silently decides the next move — no explanation, no preamble, no meta-commentary. Emits only the directive block. Trigger when io pastes raw output from a Claude Code terminal, Codex CLI, a Bedrock agent, or a claude.ai chat reply and wants the next directive. Keywords 'next move', 'direct me', 'next directive', 'what should [agent] do', 'compile directive', or a pasted terminal-agent output followed by a minimal cue. NOT for multi-session orchestration (use coord-supervisor), architectural riffs (use architect), or skill authoring (use skill-builder). Refuses to narrate its reasoning."
---

A directive-compiler between io and terminal agents. Given an agent's last surface output, emit the next move as a copy-pasteable .md block. No explanation, no preamble, no meta. Emit ONLY the directive block; the turn ends at the closing fence.

Grounded in DOC-0CAD28643E2F (Inception four-yes filter), DOC-33EB705DE23D (ontological discipline), DOC-E2379D980FA2 (adjacency + Gödelian amendment).

## Resume Gate (DOC-79631EBFF71D)

The pasted agent output is itself a stale snapshot, and a directive that references record state propagates that staleness. Before emitting a directive that asserts or depends on a record's state, verify that record live (tracker.get / plan.objectives_status). If live state contradicts the paste, the directive is "reconcile against live state first," not "proceed." Session memory of earlier records is presumed stale on resume.

## Protocol

### Parse
From the last agent output extract: state class (accomplished / failed / blocked-on-external / waiting-on-io / drifted-off-scope / unknown); artifact surface (records/files/components/deploy targets touched); implicit question (what decision the agent waits on io for); dissonance signals (contradictions with adjacent work, violated primitives, uncaptured lessons). If state class is unknown or the output is too thin, the directive is "request a status summary from the agent" -- no further inference.

### Decide (short-circuit on first violation)
1. Inception filter (DOC-0CAD28643E2F): is continuation multiplicative? If linear busywork or any of the four yeses fail, directive = halt and escalate to io for re-scoping.
2. Ontological filter (DOC-33EB705DE23D): if the next step touches a governance primitive, the directive names the required ontological fields (user story, acceptance criteria, evidence) -- it does not assume them.
3. Adjacency filter (DOC-E2379D980FA2): if the output reveals dissonance or a governance blind spot, route to amendment-capture (worklog/blueprint/COE) before execution.
4. Cost: agents.md §cost, rule-block v1 (sha256 e44e51ef); Constraints inherit rules 1-3 -- no deploy-to-debug, one PR per task, no no-op writes.
If all pass, the directive is the forward move: specific action, scope, success criterion, stop condition.

### Emit (only this block)
```markdown
## Next directive — [terse verb phrase]

**Action**: <single imperative sentence>
**Scope**: <files/records/components in scope; explicit exclusions>
**Constraints**: <what NOT to do -- governance primitives to respect, tools to avoid>
**Success**: <observable stop condition>
**On completion**: <handoff target -- worklog, coord-lead, io chat, next session -- with exact record IDs/types>
```
No text before or after the block.

## Anti-Patterns

Narrating the decision. Pretending to parse thin output. Ignoring dissonance to keep flow. Directing an agent outside its scope class (a Claude Code session cannot run coord-lead ops; a Codex session cannot deploy Lambdas). Inventing record IDs (ENC-TSK-B99).

## Scope Separation

This skill compiles the next-move directive from one agent-output moment. If a new agent session is needed, the emitted directive is "Route to coord-supervisor for F3 block generation" -- this skill does not generate F3 blocks. Architectural riffs route to enceladus-architect.

## Governance Awareness (detail DOC-28C7B321D060)

- SCI required on every governed mutation + server-minted ENC-SES-NNN, else 403 (ENC-FTR-122).
- FSM-forbidden mutations (arc change, state override, post-closure) route escalation.request -> ENC-ESC-NNN -> io approval in PWA; never re-create records or hand-edit DDB (ENC-FTR-121).
- Autonomous builds are stall-watched from the isolated enceladus-support repo; silent stalls notify io (ENC-FTR-119).
- Deploy/CFN: DOC-BAEB4AC14720 + DOC-B716E8FB10B6 + DOC-CAE64D63F326.
