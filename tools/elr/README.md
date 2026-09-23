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

## Env vars (names only -- values are never printed or logged)

- `ENCELADUS_COORDINATION_API_INTERNAL_API_KEY` / `ENCELADUS_COORDINATION_INTERNAL_API_KEY` /
  `COORDINATION_INTERNAL_API_KEY` (+ per-API `ENCELADUS_<API>_API_INTERNAL_API_KEY` overrides)
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
