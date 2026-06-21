# ENC-TSK-G45 — Diataxis audit of top-20 code-mode tool descriptions

**Task:** ENC-TSK-G45 (A3.7) · **Co-required with:** ENC-TSK-G12 · **Plan:** ENC-PLN-044 · **Feature:** ENC-FTR-099
**Source of truth:** DOC-E88C197AE0F3 RULE-06 ("Reference must mirror system architecture and be neutral")
**Scope:** the per-action descriptions surfaced to agents through the code-mode `search()` / `execute()`
meta-tools, defined as `Tool(... description=...)` in `tools/enceladus-mcp-server/server.py`.

## Frequency ranking method

No request-level tool telemetry exists in-repo, so "highest-frequency" is ranked by lifecycle
ubiquity — the read/write actions every governed session exercises across init → discovery →
checkout → code → evidence → advance → documents. The 20 below are the canonical high-traffic
actions enumerated in the Gamma session prompt's "Canonical Search/Write Expectations" sections,
split 10 reads (`search()`) / 10 writes (`execute()`).

## Diataxis classification (RULE-06)

Reference must describe *what a tool is and what it returns* — neutral, austere, architecture-mirroring.
Violations are How-to (imperative sequencing, "use X before Y", "use at session start") and
Explanation (rationale, "avoids…", "part of the … handshake") content leaking into Reference.

| # | Action (tool) | Surface | Leak class | Disposition |
|---|---|---|---|---|
| 1 | `tracker.get` (tracker_get) | search | none | verb-normalize |
| 2 | `tracker.list` (tracker_list) | search | none | verb-normalize |
| 3 | `tracker.validation_rules` | search | How-to ("before calling tracker_set") | rewrite → How-to H1 |
| 4 | `documents.get` | search | none | verb-normalize |
| 5 | `documents.search` | search | none | verb-normalize |
| 6 | `documents.list` | search | none | verb-normalize |
| 7 | `reference.search` | search | Explanation ("Avoids downloading…") | rewrite → How-to H4 |
| 8 | `governance.get` | search | How-to ("Use to load … during bootstrap") | rewrite → How-to H3 |
| 9 | `governance.dictionary` | search | none (param reference table) | keep |
| 10 | `system.connection_health` | search | How-to ("Use at session start") | rewrite → How-to H3 |
| 11 | `tracker.create` | execute | none | verb-normalize |
| 12 | `tracker.set` | execute | How-to (status→advance, worklogs→append) | rewrite → How-to H2 |
| 13 | `tracker.set_acceptance_evidence` | execute | Explanation ("Part of the … handshake") | rewrite (neutralize to constraint) |
| 14 | `checkout.task` (checkout_task) | execute | How-to ("REQUIRED before coding", "Set … before checkout") | rewrite → How-to H1 |
| 15 | `checkout.advance` (advance_task_status) | execute | How-to (preflight, "Advance children before the parent", "Query governance_dictionary…") | rewrite → How-to H1 |
| 16 | `checkout.append_worklog` (append_worklog) | execute | How-to ("For issues/features use tracker_log") | rewrite → How-to H2 |
| 17 | `tracker.log` | execute | How-to ("For tasks, use append_worklog") | rewrite → How-to H2 |
| 18 | `documents.put` | execute | none (mild architectural note kept) | verb-normalize |
| 19 | `documents.patch` | execute | none (mild architectural note kept) | verb-normalize |
| 20 | `deploy.submit` (deploy_submit) | execute | How-to ("require release notes via documents_put (guidance returned…)") | rewrite → How-to H4 |

Two param-level How-to leaks inside in-scope tools are also neutralized:
`advance_task_status.transition_evidence` ("Use tracker_validation_rules to see required fields")
and `tracker_set.transition_evidence` ("Task status transitions must use advance_task_status tool").

The four code-mode meta-tool descriptions themselves (`search`, `coordination`,
`get_compact_context`, `execute`) were reviewed and already conform to Reference mode — no change.

## Paired How-to documents (RULE-08 / RULE-11 consolidation)

AC-3 asks for a paired How-to "per rewritten tool with leaked guidance." Nine of the twenty leak
guidance. Diataxis RULE-08 (structure emerges from well-formed units, not thin per-tool scaffolding)
and RULE-11 (≤7 items per navigable list) make nine single-tool stubs an anti-pattern: most of the
leaked content is the *same* task — operating the governed task lifecycle. The relocated guidance is
therefore consolidated into four well-formed How-to guides, each the documented paired home for the
tools whose guidance moved into it. No guidance is lost; every leaking tool maps to exactly one guide.

| How-to | DOC id | Title | Paired tools (leaked guidance relocated here) |
|---|---|---|---|
| H1 | DOC-679FDAF75135 | How to operate the governed task lifecycle (checkout then advance) | checkout.task, checkout.advance, tracker.validation_rules |
| H2 | DOC-1D350453A081 | How to choose the right tracker write and worklog tool | tracker.set, tracker.log, checkout.append_worklog |
| H3 | DOC-ED44D3A6B18B | How to bootstrap a governed session | system.connection_health, governance.get |
| H4 | DOC-6284E229896E | How to submit a deployment with release notes | deploy.submit, reference.search (efficiency note) |

**Title-guard note:** `document_api` hard-rejects `Word:`-prefixed titles
(`DOC_TITLE_COLON_PREFIX_DISALLOWED`, regex `^[A-Za-z][A-Za-z-]{1,30}:`), so the handoff's literal
`"How-to: <action>"` title pattern is impossible; the type word goes in `subtypepattern="how-to"`
and titles are phrased "How to …". This existing guard is cited as evidence in the G12 AC-6
evaluation (server-side hard-rejection of title patterns is already precedented).
