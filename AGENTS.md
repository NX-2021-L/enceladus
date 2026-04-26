# Enceladus Workspace — Agent Bootstrap

MCP server `enceladus` is configured via remote HTTP gateway.
- **Cursor Cloud Agents**: configured by `.cursor/mcp.json` (HTTP, proxied through backend — requires `ENCELADUS_COORDINATION_INTERNAL_API_KEY` secret in Cursor Dashboard).
- **Local/Codex sessions**: configured in `~/.codex/config.toml` (run `tools/enceladus-mcp-server/install_profile.sh` to install).
- Gateway URL: `https://jreese.net/api/v1/coordination/mcp`
- Source: `tools/enceladus-mcp-server/server.py` (deployed as Lambda)

## Initialization (REQUIRED — 4 calls, in order)

Token-optimized init derived from `DOC-89D35679FE91` (enceladus-agent-webui-alpha skill). Saves ~15–20k tokens vs. the former 7-call sequence by deferring heavy governance fetches until actually needed.

1. `mcp: connection_health` — verify DynamoDB/S3/API connectivity, capture `governance_hash`
2. `mcp: tracker_list(project_id="enceladus", record_type="task", status="open", page_size=10)` — P0/P1 open tasks
3. `mcp: tracker_list(project_id="enceladus", record_type="lesson", page_size=5)` — recent lessons
4. `mcp: plan.objectives_status(record_id="ENC-PLN-006")` — active plan health

After step 4, produce a 3–5 paragraph briefing: service status, priority tasks, active lessons, plan progress.

## Lazy-Load Triggers (do NOT fetch at init)

| Condition | Load |
|---|---|
| Task involves git / PR workflow | `governance.get("agents.md")` §7, §8 |
| Task involves deploy / evidence schemas | `governance.get("agents.md")` §11 |
| Task involves governance file edits | `governance.get("agents.md")` §13 |
| Task involves OGTM compliance | `governance.get("agents.md")` §2a |
| Creating or validating records | `governance.dictionary` |
| Checking PWA state | `tracker.pending_updates` |
| Full lifecycle arc / strictness rank table | `governance.get("agents/lifecycle-primer.md")` |

Completed plans (e.g. ENC-PLN-012): static state — do not re-check.

## Agent Skills (MCP docstore)

Skills are stored as governed documents in the MCP docstore and loaded dynamically. Do not copy skill content into this file.

```
mcp: documents.search(project_id="enceladus", document_subtype="skill")
```

| Skill doc | Name | Use when |
|---|---|---|
| `DOC-89D35679FE91` | enceladus-agent-webui-alpha | Ad-hoc governed sessions, token-optimized init |
| `DOC-D340B31BDDE9` | enceladus-skill-manual-sync | Export skill to claude.ai skill manager |
| `DOC-84F23F2C80DC` | enc-cognito-auth | Authenticated curl/Playwright against PWA |
| `DOC-654BB71C4420` | enceladus-doc-export-alpha | Canonicalize chat payload as docstore document |

Load a skill: `mcp: documents.get(document_id="DOC-...")` — use `full_description` field as instructions.

## Git Lifecycle Quick Reference

- Set `task.components` and `task.transition_type` before `checkout_task`.
- Treat `task.transition_type` as immutable after creation when either the current or proposed value is `no_code` or `code_only`; agents must never change a task into or out of those sealed types post-creation (ENC-FTR-060, ENC-ISS-145).
- `checkout_task` is required before code changes; never edit from the shared main checkout.
- `coding-complete` returns `CAI-...`; `committed` requires `commit_sha` and returns `CCI-...`.
- Put the `CCI-...` token in the PR body before opening or updating the PR.
- Run `git` / `gh` from the task worktree CWD so branch, PR, and status commands target the right repo state.
- If GitHub says the branch is behind, merge or rebase `origin/main` in the worktree before merging.
- Re-running PR workflows after only editing the PR body can use stale payloads; push or update the PR body before assuming the CCI gate saw the change.
- Read `governance://agents/lifecycle-primer.md` for the full lifecycle arc, strictness rank table, and evidence schema.

## Pre-Code Protocol (every task pickup)

Before modifying any files for a task:
1. Sync main: `git -C <repo> fetch origin && git -C <repo> merge --ff-only origin/main`
2. Create task-scoped worktree: `bash tools/agent-worktree-init.sh <TRACKER-ID>-<slug>`
   - Creates branch `agent/<TRACKER-ID>-<slug>` automatically
   - For v4 (ENC-PLN-006) work: `agent-worktree-init.sh` creates branches with `v4/` prefix
     (e.g. `v4/agent/enc-tsk-xyz-slug`) instead of `agent/` prefix. The v4/main integration
     branch is the base for all v4 work.
3. Query component registry: `mcp: get_code_map(project_id, domain?)` for file paths
4. Check out task: `mcp: checkout_task(record_id, active_agent_session_id, governance_hash)`
5. Work only inside the printed worktree path — never modify files in the main checkout.

Always assume other agent sessions are running concurrently on this machine.
See `governance://agents.md` section 3.10 for full multi-agent safety rules.

## Generation-Scoped Deploy Target Convention (ENC-TSK-D37)

Tasks declare a `deploy_target` field:
- `prod` — targets v3/main (ENC-GEN-001). PR merges to `main`.
- `gamma` — targets v4/gamma stack (ENC-GEN-002). PR merges to `v4/main`.
- `undeclared` — default, awaiting label assignment.

PR label convention: `target:prod`, `target:gamma`, `target:undeclared`.

### Evolution Chapter Contribution

Agent sessions contribute to the active generation's evolution chapter document via
`documents.patch` with pending notes appended to the chapter's `pending_notes` array.
Each note: `{timestamp, session_id, note}`. The chapter doc for ENC-GEN-002 is
DOC-684A5EBDABB6.
