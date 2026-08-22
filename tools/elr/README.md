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
