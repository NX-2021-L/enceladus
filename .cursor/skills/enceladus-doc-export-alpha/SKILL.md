---
name: enceladus-doc-export-alpha
description: "Convert and export an in-context object (text, file contents, transcript, or structured payload) into an Enceladus docstore document via documents.put, preserving formatting and structure, then capture ENC-* record IDs or DOC-* IDs that should receive edges and apply them via documents.patch. When invoked with no input, runs a guided three-prompt flow in order (1) 'What is the document content?' identifies the payload, (2) 'Do you want to define the document_subtype?' validates input against governance.dictionary valid values and combinatorics with a follow-up if intent is not probably certain, (3) 'Provide any record IDs or document IDs that should receive edges:' captures targets. Trigger on 'export to docstore', 'save as doc', 'documents.put this', 'stash in docstore', 'canonicalize as a doc', or when io produced a chat payload that should be governed as a linked document. NOT for tracker records, governance files, or skill authoring."
---

Wraps `documents.put` to canonicalize an in-context object as a governed docstore document, then captures and applies edges.

Grounded in DOC-E2379D980FA2 (sheaf adjacency), DOC-33EB705DE23D (ontological discipline), DOC-0CAD28643E2F (Inception Principle).

## Resume Gate (DOC-79631EBFF71D)

Before applying edges, confirm each edge target exists live (a quick tracker.get / documents.get), not merely that it matches the ID regex -- a target may have been created, renamed, superseded, or removed since any earlier read. Session memory of targets is presumed stale on resume; the regex proves shape, the live read proves existence.

## Init Protocol

1. `search(action="system.connection_health")` — capture `governance_hash`
2. Content + subtype + edges inline → Mode A. Otherwise → Mode B.

## Mode A — Direct invocation

1. Validate `document_subtype` via Subtype Validation Protocol
2. Derive title (≤80 chars, content-reflective; ask if ambiguous)
3. `documents.put` with subtype + title + content + required subtype fields + `governance_hash`
4. Capture `document_id`
5. Edges supplied → `documents.patch`; else run Prompt 3
6. Emit decision prompt

## Mode B — No-input invocation (guided flow)

Three prompts, strict order. Do not infer past a prompt.

**Prompt 1 — Content:** "What is the document content?"
Accept: pasted text, prior-turn reference, file path (Read tool), or structured payload. Echo "Captured: <N> lines, <format>" before advancing. Preserve formatting verbatim; wrap structured payloads in fenced code blocks.

**Prompt 2 — Subtype:** "Do you want to define the document_subtype?"
Decline → default `note`. Provide → run Subtype Validation Protocol.

**Prompt 3 — Edges:** "Provide any record IDs or document IDs that should receive edges:"
Accept comma/newline-separated or "none". Validate `ENC-(TSK|ISS|FTR|PLN|LSN)-\d+` or `DOC-[A-F0-9]+`. Malformed → re-ask for that token only.

## Subtype Validation Protocol

1. Fetch: `search(action="governance.dictionary", arguments={field: "document_subtype"})`
2. Exact match → accept silently
3. Fuzzy (case-insensitive, synonyms, stem) → propose "Did you mean `<canonical>`?"
4. No probable match → list 3–5 candidates with one-line defs, ask "Which fits?"
5. Combinatorics (subtype × required companion fields) → one disambiguating follow-up

Probable certainty threshold ~0.85. Below → ask. Silent coercion is a governance violation.

## Write Surface

Allowed: `documents.put` (new doc), `documents.patch` (edges on this invocation's doc only).
Forbidden: tracker.*, governance.update, patch on other docs, filesystem writes, checkout.*, deploy.*.

## Decision Prompt

```text
document_id: DOC-...
subtype:     <validated>
title:       <applied>
edges:       <count> (<target> → <relation>, ...)
```
Ask: "Anything else to attach, or close out?"

## Anti-Patterns

- Subtype guessing — ask, don't coerce
- Edge inflation — only user-named edges
- Format flattening — preserve source verbatim
- Over-titling — ≤80 chars, content-reflective
- Prompt skipping — all three in order on Mode B
- Scope creep — one doc + its edges; nothing else

## Governance Awareness (detail DOC-28C7B321D060)

- SCI required on every governed mutation + server-minted ENC-SES-NNN, else 403 (ENC-FTR-122).
- FSM-forbidden mutations (arc change, state override, post-closure) route escalation.request -> ENC-ESC-NNN -> io approval in PWA; never re-create records or hand-edit DDB (ENC-FTR-121).
- Autonomous builds are stall-watched from the isolated enceladus-support repo; silent stalls notify io (ENC-FTR-119).
- Deploy/CFN: DOC-BAEB4AC14720 + DOC-B716E8FB10B6 + DOC-CAE64D63F326.
