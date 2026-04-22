# Enceladus Workspace — Agent Bootstrap

MCP server `enceladus` is configured via remote HTTP gateway.
- **Cursor Cloud Agents**: configured by `.cursor/mcp.json` (HTTP, proxied through backend — requires `ENCELADUS_COORDINATION_INTERNAL_API_KEY` secret in Cursor Dashboard).
- **Local/Codex sessions**: configured in `~/.codex/config.toml` (run `tools/enceladus-mcp-server/install_profile.sh` to install).
- Gateway URL: `https://jreese.net/api/v1/coordination/mcp`
- Source: `tools/enceladus-mcp-server/server.py` (deployed as Lambda)

## Initialization (REQUIRED — run in order every session)

1. `mcp: connection_health` — verify DynamoDB/S3/API connectivity, get governance hash
2. `mcp: governance_get("agents.md")` — **load full governance rules and execute all steps**
3. `mcp: governance_dictionary` — load compact enum/constraint index
4. `mcp: governance_get("agents/bootstrap-template.md")` — load session init protocol
5. `mcp: governance_get("agents/lifecycle-primer.md")` — load lifecycle gates before any PR work
6. `mcp: tracker_list(project_id="enceladus", record_type="task", status="open")` — open tasks
7. `mcp: tracker_pending_updates(project_id="enceladus")` — pending updates

All operating rules, tool reference, and task policies are in `governance://agents.md`.
Do not proceed with any work until steps 1-5 are complete.

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
