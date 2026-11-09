---
name: enceladus-elr
description: "Brief the session on the Enceladus Local Runner (ELR) and route Enceladus READS through it instead of the MCP read surface, which returns whole records and burns context. Trigger on 'use ELR', 'enceladus-elr', 'save tokens on enceladus calls', 'read this record or document efficiently', 'brief me on ELR', 'count or list records', or at the start of any long or autonomous Enceladus session that will perform many governed reads. Also trigger BEFORE spawning subagents or a Workflow that will read Enceladus records, because the ELR contract block must be pasted into every subagent prompt (subagents inherit CLAUDE.md, not skills). Runs enceladus-diagnostics-elr as a mandatory step 0 and falls back to MCP in one line if the host is not READY. Lists and counts route through elr list --census (ENC-PLN-093); ranked context via elr compact_context. NOT for tracker lifecycle (checkout, advance, worklog, acceptance evidence), which is MCP-only and charter-barred from ELR. NOT for governed writes performed by a subagent."
---

Use the Enceladus Local Runner for Enceladus READS: a ~300-byte JSON digest, bodies on local disk.

## Step 0, the gate

No shell (claude.ai web/mobile): MCP for ALL reads, lists via `tracker.list mode=census`; stop.
Otherwise run `enceladus-diagnostics-elr` FIRST (mandatory in Claude Code/terminal; Cowork if READY). Not READY -> ONE line, ALL reads via MCP; never half-deliver ELR. READY = every project reads
through ELR (checks 8, 9); DEGRADED sends EVERY read to MCP. It resolves <PY>, <ELR>.

## Routing

    read records (any project)   elr_batch_get.py --ids "A,B"
    count or enumerate a list    elr_list.py --project P [--type T] [--status S] --census
    read a document body         elr_doc_get.py <ID> --out-dir ~/.enceladus/docs
    manifest or outline only     elr_doc_digest.py <ID>
    ranked context / lessons     elr_compact_context.py --mode M (--record-id ID|--query ".") --order fused
    patch one section            elr_doc_patch.py --doc <ID> ...   (--dry-run first)
    validate before a write      elr_validate.py validate ...
    TRACKER CEREMONY             MCP ONLY. ELR is charter-barred from checkout.* (ENC-FTR-134 AC-9)

Entry: `~/.enceladus/elr/elr <sub>` == `<PY> <ELR>/elr_<sub>.py`.

Context (ENC-FTR-147): `compact_context --mode record|issue|task|feature|project|document|topic
(--record-id ID | --query "..") [--top-n 20] [--order final|fused]`: digest only, top-N inline;
bodies in `~/.enceladus/context/<run_id>/`, `<run_id>.ids` -> `batch_get --ids-file`. Use `--order
fused` while ENC-ISS-836 is open. Exit 6 (no hybrid): MCP
`get_compact_context`; 8 shape drift; 7 no credential.

Lists (ENC-PLN-093): default to census/projection; never total one page. Census gives `count`, `exhausted`, `count_truncated`
(a floor; say so), `ids` (<=500), cursors. Rows: `--page <cursor>` or `--pages N` (<=10) -> ids file
-> `batch_get --ids-file`. Exit 6: MCP `tracker.list mode=census`; other filters: MCP `tracker.list`.

Bodies land on DISK: read a SLICE (`grep`, `sed -n`), never the whole file.

## Credentials

ELR resolves its own (ENC-TSK-Q35): FTR-074 credential, internal-key env vars, then
`~/.enceladus/internal_key` (0600). Never export, print, grep, or read a key from config
(agents.md s14). Exit 7 `no_credential_configured` = NOT READY: io runs `elr_provision_key.py`.

## Traps

`document_id` is POSITIONAL for doc_get/doc_digest, a `--doc` FLAG for doc_patch. doc_get's `--out-dir`
defaults to `~/.enceladus/elr/cache`, doc_patch reads `~/.enceladus/docs`: pass `--out-dir
~/.enceladus/docs` or `--dry-run` fails `local-body-cache-missing`. The digest side file is the SOLE
`if_match` source, stale at 24h (exit 2). Abbreviated flags rejected. Writes never retry on 5xx.
batch_get `outcome`: found|not_found|forbidden|error; `not_found` is a result.
`sentinel_route_unsupported_by_server` = plane predates ENC-TSK-Q10: use MCP.

## Subagents

Subagents inherit CLAUDE.md, NOT this skill. Paste verbatim into EVERY subagent brief/`agent()` prompt,
filling <PY>, <ELR>.

    --- ELR CONTRACT (reads only) ---
    Use ELR for Enceladus reads. Interpreter <PY>. Source dir <ELR>.
    ELR resolves its own credential. Never export, read, or print a key.
    Records:  <PY> <ELR>/elr_batch_get.py --ids "ID1,ID2"
    Context:  <PY> <ELR>/elr_compact_context.py --mode M --query "<noun>" --order fused
    Counts:   <PY> <ELR>/elr_list.py --project P [--type T] [--status S] --census
              report count_truncated as a floor; never total one page
    Document: <PY> <ELR>/elr_doc_get.py <ID> --out-dir ~/.enceladus/docs
              then read a SLICE of that file, never the whole thing
    You are READS ONLY: no elr_doc_patch, no elr_publish, no MCP, no tracker, no git push.
    Never print a document body or a key.
    COST RULES: agents.md §cost, rule-block v1 (sha256 e44e51ef); parent pastes the block after this contract.
    --- END ELR CONTRACT ---

## Never

Use ELR for tracker lifecycle. Let a subagent write. Print a body or a key. Split the read surface. Hand-roll a reader; file an issue.
