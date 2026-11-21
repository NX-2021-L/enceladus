---
name: enceladus-skill-builder-prod
description: "Operate and evolve the Enceladus skill library. Terminal stage after alpha (scaffold), beta (harden), skill-creator (tune). Extends enceladus-skill-builder-beta (DOC-61E0D1112A56) with autopoietic evolution per DOC-44A03B36305F section 10.5 -- scans the live library, computes graph-health signals (adjacency completeness, Dreyfus-stage consistency, cross-reference integrity, Options-signature alignment), and writes governed proposals for promotion, deprecation, supersession, refactor, or new-skill creation. Documents-only write surface -- proposes, never executes; hands off to coord-supervisor or coord-lead for any mutation. Trigger on 'skill library health', 'skill-builder-prod', 'which skills should I promote or deprecate', 'run autopoietic review', 'SkillClaw round', 'library coherence check', or when the library has grown enough to need self-maintenance. NOT for authoring new skills (use alpha/beta) or tuning triggers and evals (use skill-creator)."
---

The operational and evolutionary layer of the skill-authoring pipeline. Alpha drafts, beta hardens, skill-creator tunes; prod operates -- it watches the library over time and writes governed proposals to keep it healthy.

Grounded in DOC-61E0D1112A56, DOC-44A03B36305F §10.5, DOC-E2379D980FA2, DOC-0CAD28643E2F.

## Resume Gate (DOC-79631EBFF71D)

Session memory is a cache, not truth. On resume, a prior scan or prior-pass blueprint set is presumed stale. Before running a health scan, filing a proposal, or producing a status summary, re-read the live library (ls /mnt/skills/user/) AND the live docstore cross-reference AND prior-pass blueprints.

## Init Protocol

1. connection_health -- capture governance_hash.
2. ls -la /mnt/skills/user/ -- discover live library.
3. get_compact_context(mode=project, project_id=enceladus, query="canonical SKILL.md docstore copy", top_n=20) -- cross-reference docstore.
4. Load prior prod-pass blueprints -- do not re-propose what io declined.

## Health Scan -- Nine Signals (default mode)

Per skill: 1/ description_chars (<=1024); 2/ dreyfus_declared; 3/ adjacency_reciprocity; 4/ canonical_docstore_exists; 5/ governance_compliance; 6/ anchor_word_alignment; 7/ name_reserved_word_check -- BLOCKING (no reserved words, e.g. claude); 8/ yaml_frontmatter_check -- BLOCKING (SKILL.md starts at byte 0 with valid --- frontmatter); 9/ last_touched.

Report a per-skill table with all nine signals plus Dreyfus candidacy (ready-for-promotion / demotion-candidate / hold). Signals 7 and 8 are blocking: REFACTOR before any promote/deprecate. Also flag any skill missing the cost rule-block reference: agents.md §cost, rule-block v1 (sha256 e44e51ef).

## Operational Modes

- Health Scan (default) -- nine signals, candidacy flags.
- Promotion -- check declared criteria, count evidence, file blueprint if met.
- Deprecation -- verify stale, check supersession first. Deprecated != deleted.
- Supersession -- B's scope must be a proper superset of A's. File supersedes edge + deprecated stage for A.
- SkillClaw Autopoietic Round -- classify each skill Refine / Create / Skip; one blueprint per Refine and Create; guard against re-proposals.

## Proposal Schema

Filed via documents.put, subtype blueprint. Required: proposal type, affected skill, evidence cited, recommended action, handoff target, confidence (HIGH/MEDIUM/LOW). Close with a decision prompt to io.

## Anti-Patterns

Proposal inflation (top-k, default k=3). Re-proposal drift. Deletion without supersession. Reserved-word naming (REFACTOR first). Missing YAML frontmatter (REFACTOR first). Execution drift (hand off to coord-supervisor). Split-field patch (see invariant below).

## Write Surface

Allowed: documents.put, documents.patch (full body). Forbidden: tracker.create, tracker.set, checkout.advance, deploy.submit, governance.update, file moves or deletes.

**Skill doc patch invariant:** For `document_subtype=skill`, `full_description` (DDB, skill manager) and `content` (S3, PWA) are independent fields -- always pass BOTH in the same `documents.patch` call, or the unset one goes stale. `full_description` is hard-capped at 4096 chars (DOC-28C7B321D060); trim non-rule prose to fit.

## Governance Awareness (detail DOC-28C7B321D060)

- SCI required on every governed mutation + server-minted ENC-SES-NNN, else 403 (ENC-FTR-122).
- FSM-forbidden mutations (arc change, state override, post-closure) route escalation.request -> ENC-ESC-NNN -> io approval in PWA; never re-create records or hand-edit DDB (ENC-FTR-121).
- Autonomous builds are stall-watched from the isolated enceladus-support repo; silent stalls notify io (ENC-FTR-119).
- Deploy/CFN: DOC-BAEB4AC14720 + DOC-B716E8FB10B6 + DOC-CAE64D63F326.
