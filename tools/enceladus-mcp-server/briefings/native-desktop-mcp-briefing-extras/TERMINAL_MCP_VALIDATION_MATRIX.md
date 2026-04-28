# Terminal MCP Bootstrap Validation Matrix

## Scope

Validation for:

- `ENC-TSK-476` terminal bootstrap contract
- `ENC-TSK-477` terminal session briefing template
- `ENC-TSK-478` host-v2 one-time MCP connector provisioning
- `ENC-TSK-479` host-v2 fleet bootstrap template
- `ENC-TSK-480` matrix execution and evidence capture
- `ENC-TSK-845` lifecycle primer bootstrap rollout
- `ENC-TSK-850` cross-provider validation for first-session lifecycle awareness
- `ENC-TSK-G48` 5-surface regression matrix post-G47 deploy (this extension)

---

## Part 1: Terminal / Host-v2 Bootstrap Matrix (original)

### Automated Test Evidence

- Coordination API unit tests:
  - Command: `python3 -m pytest -q backend/lambda/coordination_api/test_lambda_function.py`
  - Result: `154 passed`
  - Coverage includes host-v2 MCP bootstrap assertions plus lifecycle-primer prompt inclusion and priority ordering.
- Lifecycle-aware coordination prompt tests:
  - Command: `python3 -m pytest -q backend/lambda/coordination_api/test_lambda_function.py`
  - Result: recorded in `/tmp/enceladus-mcp-lifecycle-primer.28DTHd/coordination_pytest.log`
  - Coverage includes lifecycle-primer prompt inclusion and priority ordering for managed dispatch/bootstrap flows.

### Matrix Results

All scenarios passed in this session.

| Scenario | Method | Result | Evidence |
|---------|--------|--------|----------|
| Local terminal cold start | Run `install_profile.sh` with empty HOME | PASS | `/tmp/enceladus-mcp-matrix/local_cold.log` |
| Local terminal warm start | Re-run `install_profile.sh` with existing profile | PASS | `/tmp/enceladus-mcp-matrix/local_warm.log` |
| Codex cold start lifecycle bootstrap | Run `install_profile.sh` with empty HOME and inspect `.codex/config.toml` + `.codex/AGENTS.md` | PASS | `/tmp/enceladus-mcp-lifecycle-primer.28DTHd/install_cold.log`, `/tmp/enceladus-mcp-lifecycle-primer.28DTHd/home/.codex/config.toml`, `/tmp/enceladus-mcp-lifecycle-primer.28DTHd/home/.codex/AGENTS.md` |
| Claude cold start lifecycle bootstrap | Same cold-start install and inspect `.claude/CLAUDE.md` | PASS | `/tmp/enceladus-mcp-lifecycle-primer.28DTHd/install_cold.log`, `/tmp/enceladus-mcp-lifecycle-primer.28DTHd/home/.claude/CLAUDE.md` |
| Lifecycle warm start idempotence | Re-run installer against the same HOME and confirm lifecycle references remain | PASS | `/tmp/enceladus-mcp-lifecycle-primer.28DTHd/install_warm.log` |
| Bedrock/managed dispatch lifecycle preload | Run `python3 -m pytest -q backend/lambda/coordination_api/test_lambda_function.py` | PASS | `/tmp/enceladus-mcp-lifecycle-primer.28DTHd/coordination_pytest.log` |
| Host-v2 cold start | Run `host_v2_first_bootstrap.sh` against empty host home | PASS | `/tmp/enceladus-mcp-matrix/host_cold.log` |
| Host-v2 warm start | Re-run `host_v2_first_bootstrap.sh` and verify warm skip | PASS | `/tmp/enceladus-mcp-matrix/host_warm.log` |
| Fleet-provisioned host session | Run `host_v2_user_data_template.sh` first-boot path | PASS | `/tmp/enceladus-mcp-matrix/fleet_run.log`, `/tmp/enceladus-mcp-matrix/fleet_userdata.log` |

### Session Governance Check

- Terminal template enforces MCP bootstrap then governance initialization:
  - `SESSION_BRIEFING_TEMPLATE-TERMINAL.md`
- Both templates enforce MCP-only work mode (no direct tracker/docstore/aws/boto3 in normal task execution):
  - `SESSION_BRIEFING_TEMPLATE-UI.md`
  - `SESSION_BRIEFING_TEMPLATE-TERMINAL.md`

### Notes

- Host-v2 and fleet checks were executed as controlled local simulations using host-v2 scripts and isolated HOME paths.
- Runtime capability metadata for host-v2 bootstrap and fleet template is exposed by coordination API code changes and validated by unit tests.

---

## Part 2: ENC-TSK-G48 — 5-Surface Regression Matrix (post-G47 deploy)

**Authored:** 2026-04-28
**Task:** ENC-TSK-G48 (G14-L2: Regression — validate all 5 surfaces post-implementation)
**Session:** `claude-code-jreese-g48-regression-2026-04-28`
**Wave:** DOC-1487FA9B03A5
**governance_hash at capture:** `5b5277ebe1e612e4ebe274f98518ae30afe25d055ebda431614efcbcd6805944`
**origin/main HEAD:** b597e94 (PR #473 merge, G47 DRIFT-1/3/4 + DRIFT-2 auth fixes)

The goal of this extension is to verify that all 5 MCP client surfaces produce
correct tool inventories and byte-identical `governance_hash` values after the
G47 parity implementation. Surfaces 1+2 were captured or validated directly by
this terminal session; surfaces 3–5 require io to paste-and-run the provided
capture snippets.

### Re-run of Pre-existing PASS Rows (post-G47)

**Command:** `PYTHONPATH=backend/lambda/shared_layer/python:$PYTHONPATH python3 -m pytest -q backend/lambda/coordination_api/test_lambda_function.py`
**Result:** `162 passed` (up from 154 — 8 additional tests from G47 additions; no regressions)
**Note on PYTHONPATH:** The shared layer must be on path for local import resolution.
The `ModuleNotFoundError: No module named 'enceladus_shared'` seen without it is a
pre-existing dev-environment issue (not a G47 regression; same import existed at 48061a9).

| Scenario | Method | Result | Evidence |
|---------|--------|--------|----------|
| Local terminal cold start (post-G47) | `HOME=/tmp/g48-coldstart-$$ ENCELADUS_ALLOW_KEYLESS_PROFILE=true bash tools/enceladus-mcp-server/install_profile.sh` | PASS | `/tmp/g48-coldstart-32709` — canonical URL written, all 4 tools with `approval_mode=approve` |
| Local terminal warm start (post-G47) | Re-run installer against same isolated HOME | PASS | Idempotent — `[INFO] already present` for AGENTS.md, CLAUDE.md; mcp.json and config.toml merged correctly |
| Automated tests (post-G47) | pytest with shared_layer PYTHONPATH | PASS | 162 passed, 0 failures |
| Host-v2 / fleet scenarios | Not re-run from this workstation | NOT-RUN | Scope same as Part 1; no G47 changes touch host-v2 bootstrap path |

**Cold-start config verification (DRIFT-1/3/4 fixes confirmed):**

After `install_profile.sh` on a fresh HOME, the generated `~/.codex/config.toml` contains:
```toml
[mcp_servers.enceladus]
type = "http"
url = "https://jreese.net/api/v1/coordination/mcp"   # canonical URL — DRIFT-1 fixed

[mcp_servers.enceladus.tools.search]
approval_mode = "approve"

[mcp_servers.enceladus.tools.coordination]
approval_mode = "approve"                             # DRIFT-3 fixed — coordination now present

[mcp_servers.enceladus.tools.get_compact_context]
approval_mode = "approve"

[mcp_servers.enceladus.tools.execute]
approval_mode = "approve"
```

**Live `~/.codex/config.toml` state (io's workstation as of this session):**
The live config still shows `url = "https://mcp.jreese.net"` and is missing the
`coordination` tool approval entry — the user has not yet re-run `install_profile.sh`
post-G47. The installer correctly prints a migration warning when the legacy URL is
detected and overwrites with the canonical URL on re-install. **Action for io:** run
`ENCELADUS_COORDINATION_INTERNAL_API_KEY=<key> bash tools/enceladus-mcp-server/install_profile.sh`
to bring the live codex config to the G47 post-install state before capturing surface 2.

---

### 5-Surface Validation Table

The **headline AC** is `governance_hash` byte-equality across all 5 surfaces in the same
time window. The expected value (frozen at handoff time and confirmed by this session):

```
governance_hash = 5b5277ebe1e612e4ebe274f98518ae30afe25d055ebda431614efcbcd6805944
```

| # | Surface | Reach | governance_hash | connection_health | governance_get('agents.md') | tracker.list | code_mode_tools | Result |
|---|---------|-------|-----------------|-------------------|-----------------------------|--------------|-----------------|--------|
| 1 | Claude Code HTTP (this terminal) | captured directly | `5b5277…6805944` ✅ | PASS (DynamoDB ok, S3 ok, graph healthy, 2026-04-28T07:24:19Z) | PASS | PASS (total=50, first=ENC-TSK-C64) | `["coordination","execute","get_compact_context","search"]` | **PASS** |
| 2 | Claude/Codex terminal CLI | installer verified; live session requires io | awaiting io capture | installer PASS (canonical URL + all 4 tools written on cold start) | — | — | — | **PARTIAL** — see surface-2 capture snippet below |
| 3 | claude.ai web connector | requires io capture | awaiting io capture | — | — | — | — | **PENDING io** — see surface-3 capture snippet below |
| 4 | Cursor desktop | requires io capture | awaiting io capture | — | — | — | — | **PENDING io** — see surface-4 capture snippet below |
| 5 | Cursor cloud agent | requires io capture | awaiting io capture | — | — | — | — | **PENDING io** — see surface-5 capture snippet below |

**governance_hash equality assertion:** CONFIRMED for surface 1. Assertion will close
on first all-5 capture cycle; surfaces 3–5 entries should be filled by io using the
snippets below and this table updated with observed hash values.

---

### Prod + Gamma Inventory Parity

**Prod tool inventory** (captured live via `coordination.capabilities.get` through this session's MCP client):
```
code_mode_tools = ["coordination", "execute", "get_compact_context", "search"]
```

**Gamma tool inventory** (`https://enceladus-gamma.jreese.net`):
Live tool-list call blocked from this terminal — gamma auth key not available in env.
Code inspection confirms gamma is running the same Lambda deployment artifact as prod
(G47 deploy job 25038975219 success on sha 7566aae62c8b; same `_ENCELADUS_CODE_MODE_TOOLS`
array in `backend/lambda/coordination_api/handlers.py` applies to both environments).
No drift expected or found. **Parity assertion: PASS (code-verified).**

If a live gamma tool-list call is needed for the formal evidence record, io can run:
```bash
curl -s -X POST https://enceladus-gamma.jreese.net/api/v1/coordination/mcp \
  -H "Content-Type: application/json" \
  -H "X-Coordination-Internal-Key: <gamma-key>" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
```

---

### Surface 2 Capture Snippet (Codex CLI — paste-and-run after re-installing profile)

**Pre-requisite:** Run the installer first to update the live `~/.codex/config.toml` to the G47 state:
```bash
ENCELADUS_COORDINATION_INTERNAL_API_KEY=<key> bash tools/enceladus-mcp-server/install_profile.sh
```

Then capture the MCP triple by running a non-interactive codex exec session from the repo root:
```bash
mkdir -p /tmp/enceladus-mcp-matrix/g48/surface-2
codex exec \
  "You are capturing MCP regression evidence for ENC-TSK-G48. Make exactly three tool calls in order and print each raw response verbatim: (1) search(action='system.connection_health'), (2) search(action='governance.get', arguments={path: 'agents.md'}), (3) search(action='tracker.list', arguments={project_id: 'enceladus', record_type: 'task', page_size: 1}). After all three calls, print the governance_hash value from call 1 on a line by itself prefixed with 'GOVERNANCE_HASH:'. Do not do anything else." \
  2>&1 | tee /tmp/enceladus-mcp-matrix/g48/surface-2/capture.log
grep "GOVERNANCE_HASH:" /tmp/enceladus-mcp-matrix/g48/surface-2/capture.log
```

**Expected:** `GOVERNANCE_HASH: 5b5277ebe1e612e4ebe274f98518ae30afe25d055ebda431614efcbcd6805944`
**Expected tools reported by gateway:** `["coordination", "execute", "get_compact_context", "search"]`

---

### Surface 3 Capture Snippet (claude.ai web — Enceladus connector)

From a logged-in claude.ai session with the Enceladus MCP connector active, paste the
following as a user message:

```
Please call these three MCP tools in order and reply with the complete raw response for each, then confirm the governance_hash value:

1. search with action="system.connection_health"
2. search with action="governance.get" and arguments={"path": "agents.md"}
3. search with action="tracker.list" and arguments={"project_id": "enceladus", "record_type": "task", "page_size": 1}

After each tool call, include the raw JSON response verbatim. At the end, print the governance_hash from call 1 on its own line prefixed with "GOVERNANCE_HASH:". This is ENC-TSK-G48 regression evidence capture.
```

**Expected:** `GOVERNANCE_HASH: 5b5277ebe1e612e4ebe274f98518ae30afe25d055ebda431614efcbcd6805944`
Save the full response to `/tmp/enceladus-mcp-matrix/g48/surface-3/capture.txt`.

---

### Surface 4 Capture Snippet (Cursor desktop — `.cursor/mcp.json` connector)

From a Cursor chat window with the Enceladus MCP server connected (`.cursor/mcp.json`
must have `ENCELADUS_COORDINATION_INTERNAL_API_KEY` set in env), paste:

```
ENC-TSK-G48 regression evidence capture. Make exactly three MCP tool calls and print each raw response:

1. search(action="system.connection_health")
2. search(action="governance.get", arguments={"path": "agents.md"})
3. search(action="tracker.list", arguments={"project_id": "enceladus", "record_type": "task", "page_size": 1})

Print each raw JSON response verbatim. End with a line: GOVERNANCE_HASH: <value from call 1>
```

**Expected:** `GOVERNANCE_HASH: 5b5277ebe1e612e4ebe274f98518ae30afe25d055ebda431614efcbcd6805944`
Save the full response to `/tmp/enceladus-mcp-matrix/g48/surface-4/capture.txt`.

---

### Surface 5 Capture Snippet (Cursor cloud agent — dashboard Secrets)

From a new Cursor cloud agent task (ensure `ENCELADUS_COORDINATION_INTERNAL_API_KEY`
is registered in Cursor dashboard Secrets per `CURSOR_CLOUD_SETUP.md`), paste:

```
ENC-TSK-G48 regression evidence capture. Make exactly three MCP tool calls in order:

1. search(action="system.connection_health")
2. search(action="governance.get", arguments={"path": "agents.md"})
3. search(action="tracker.list", arguments={"project_id": "enceladus", "record_type": "task", "page_size": 1})

Print each raw JSON response verbatim. End with a line: GOVERNANCE_HASH: <value from call 1>
```

**Expected:** `GOVERNANCE_HASH: 5b5277ebe1e612e4ebe274f98518ae30afe25d055ebda431614efcbcd6805944`
Save the full response to `/tmp/enceladus-mcp-matrix/g48/surface-5/capture.txt`.

---

### Regressions Found

None. Surface 1 (Claude Code HTTP) produced a PASS triple. Automated tests show 162
passed with no failures (8 tests more than the Part 1 baseline of 154; additions are
from G47 test coverage, not removals or modifications of existing tests). Installer
cold-start and warm-start behavior verified correct with DRIFT-1/3/4 fixes applied.

---

### Doc-only Deploy Gate Question (ENC-LSN-050)

ENC-TSK-G48 was created with default `transition_type=github_pr_deploy`. Per ENC-LSN-050
(born from G46), doc-only tasks with this transition_type stall at the `deploy-init` →
`deploy-success` gate after merge because there is no real Lambda deployment to evidence.

**Gate question for io:** After this PR merges, how should G48 advance past `merged-main`?
Options (same as G46):

- **(a)** `user_initiated` submit via PWA with a `doc-only task` note (same path io used for G46).
- **(b)** A doc-only deploy-success pointing at the current Lambda version (no actual redeploy).

Awaiting io PWA action. This session will not attempt to advance past `pr` status.
