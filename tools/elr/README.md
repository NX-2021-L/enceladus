# ELR (Enceladus Local Runner) -- core transport

ELR is an **alternate client** for the governed Enceladus HTTP APIs, not a
bypass: governance is enforced at the API boundary (the Lambda handlers).
ELR only moves bytes and returns compact digests. Python 3.11, stdlib only
(urllib.request, json, hashlib, argparse, ssl) -- no pip dependencies.

## Profiles

- `internal` (default) -- direct HTTPS calls to the governed APIs, mirroring
  `tools/enceladus-mcp-server/server.py`'s base URLs and its
  `X-Coordination-Internal-Key` header convention.
- `mcp-http` -- JSON-RPC 2.0 against the streaming MCP-over-HTTP gateway
  (`initialize` -> `notifications/initialized` -> `tools/call`), optional bearer.

## Credential (ENC-TSK-Q35 / ENC-ISS-831)

ELR resolves its credential in Python (`elr_lib/config.py`), so the `elr`
launcher, a direct `python3 elr_<sub>.py`, a subagent and a Workflow script
all find the same key. Order: an FTR-074 agent credential
(`ENCELADUS_AGENT_CREDENTIAL` / `~/.enceladus/credential.json`), then the
internal-key env vars below, then ELR's own key file
`~/.enceladus/internal_key` (override with `ENCELADUS_ELR_KEY_FILE`; mode
0600 or 0400, anything wider is ignored with a warning). ELR never reads
`~/.claude.json` or any other MCP launcher config.

io provisions the key file once per host (agents never do):

```
python3 tools/elr/elr_provision_key.py          # prompts with no echo; or pipe the key on stdin
```

With no credential, every auth-required read (`list`, `batch_get`, `compact_context`,
`doc_get`, `doc_digest`, `doc_patch`) refuses locally with exit code 7 and
anomaly `no_credential_configured`, before any network request.
`elr_smoke` issues one authenticated probe besides the health GET and is ok
only when the key is accepted.

## Launcher

`tools/elr/elr` is installed and hash-verified by `elr_sync pull`, which
also pins the interpreter it ran under (`.elr-python`) and points
`~/.enceladus/elr/elr` at it (replacing only a symlink or the legacy
key-scraping wrapper). Usage: `~/.enceladus/elr/elr <subcommand> [args]`.

## Env vars (names only -- values are never printed or logged)

- `ENCELADUS_COORDINATION_API_INTERNAL_API_KEY` / `ENCELADUS_COORDINATION_INTERNAL_API_KEY` /
  `COORDINATION_INTERNAL_API_KEY` / `ENCELADUS_INTERNAL_API_KEY`
  (+ per-API `ENCELADUS_<API>_API_INTERNAL_API_KEY` overrides)
- `ENCELADUS_ELR_KEY_FILE`, `ELR_PYTHON`, `ELR_BIN`
- `ENCELADUS_<API>_API_BASE` (tracker/document/deploy/governance/projects/...),
  `ENCELADUS_HEALTH_API_URL`, `ENCELADUS_GRAPH_QUERY_API_BASE`
- `ENCELADUS_MCP_GATEWAY_URL`, `ENCELADUS_MCP_BEARER_TOKEN` / `ENCELADUS_MCP_API_KEY`

## Run

```
python3 tools/elr/elr_smoke.py                 # prints digest JSON only
python3 -m pytest tools/elr/tests -q
python3 -m unittest discover -s tools/elr/tests -v
```

## Project-agnostic reads (ENC-TSK-Q10)

`elr_batch_get.py` sends only the record id: every tracker read goes to the
sentinel route `GET /_/{record_type}/{record_id}` and the server resolves the
owning project from the id (ENC-ISS-791). ELR carries no prefix-to-project
knowledge -- no prefix map, no cache file; `elr_sync pull` removes a stale
prefix-map cache left under `~/.enceladus` by older installs and lists it in
`removed_paths`. Each row of the batch digest reports one of four outcomes:
`found` (2xx), `not_found` (404 -- reported, never an anomaly), `forbidden`
(401/403), or `error` (5xx, unreachable, unsupported id shape, or a plane that
predates the sentinel route, flagged `sentinel_route_unsupported_by_server`).

## Compact context (ENC-TSK-Q50)

`elr compact_context --mode task --record-id ENC-TSK-Q33 --top-n 10` performs the
governed GET reads behind MCP `get_compact_context` (record, components,
governance, related documents, project, reference, and the graphsearch hybrid
call with query AND anchor), lands every section under
`~/.enceladus/context/<run_id>/` (override with `--out-dir` or
`ELR_CONTEXT_DIR`), and prints one digest: the server-ordered ranking as array
rows, `signals_present` / `signals_absent` with reasons, and the on-disk section
index. `<run_id>.ids` in that directory feeds `elr batch_get --ids-file`.
Digest bytes are bounded by `1024 + 192 * top_n`. Exit codes: 4 TLS, 6
`hybrid_unsupported_by_server`, 7 no credential, 8 `response_shape_drift`.
