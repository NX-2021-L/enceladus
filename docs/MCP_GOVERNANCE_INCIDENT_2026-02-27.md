# MCP Governance Access Incident - 2026-02-27

## Summary
Critical session failures were traced to a governance-source split:
- MCP resource reads and tool execution use `tools/enceladus-mcp-server/server.py` with S3 governance resolution (`s3://jreese-net/governance/live/*`).
- Coordination API governance hash flow used a separate local docstore-based hash path in Lambda.

This created stale-hash mismatches (`GOVERNANCE_STALE`) and governance resource read failures (`governance://agents.md` unresolved in affected sessions).

## Actions Implemented
1. Unified governance hash source in coordination API runtime:
- `backend/lambda/coordination_api/lambda_function.py`
- `backend/lambda/coordination_api/mcp_integration.py`

Both now compute governance hash from the MCP server module (`_compute_governance_hash(force_refresh=True)`) first, with legacy docstore as fallback only.

2. Added stale-hash self-healing in MCP server write validation:
- `tools/enceladus-mcp-server/server.py`

If API hash mismatches provided hash, server now forces a fresh local governance recomputation before rejecting.

3. Added fast-path governance resource reads for `governance://agents.md`:
- `tools/enceladus-mcp-server/server.py`

`read_resource` now maps directly to deterministic S3 key (`governance/live/agents.md`) and reads without requiring catalog listing. Added short in-memory body cache to reduce repeated read latency.

4. Reduced heavy S3 catalog behavior for bootstrap paths:
- `tools/enceladus-mcp-server/server.py`

Governance catalog listing no longer fetches all object bodies eagerly; content hashing is now lazy during hash computation.

5. Added tests and smoke checks:
- `tools/enceladus-mcp-server/test_tracker_create_validation.py`
- `backend/lambda/coordination_api/test_lambda_function.py`

## Validation Performed
- `python3 -m py_compile` on modified runtime and test files: pass.
- Targeted unittest:
  - `python3 -m unittest backend.lambda.coordination_api.test_lambda_function.CoordinationLambdaUnitTests.test_compute_governance_hash_local_uses_mcp_server_source`: pass.
- MCP server smoke checks (direct module invocation):
  - stale API hash + fresh local hash acceptance: pass.
  - direct `governance://agents.md` S3 read path (without catalog): pass.

## Current Remote MCP Status (Pre-Deploy)
Live remote MCP still returns:
- `connection_health`: ok
- `coordination_capabilities`: ok
- `governance_hash`: ok
- `read governance://agents.md`: `Governance resource not found`

This confirms code fix is implemented locally but not yet deployed to active Lambda/runtime.

## Deployment and Rollout Notes
- Preferred target: streamable HTTP MCP runtime (Lambda-backed) as canonical path.
- Keep stdio local MCP path as compatibility fallback only.
- Deploy coordination API + MCP server package together to avoid partial hash-source regressions.

## Follow-up
After deployment, verify:
1. `resources/read` for `governance://agents.md` returns S3 content.
2. Hash used by `governance_hash` aligns with write-tool validation (no false `GOVERNANCE_STALE`).
3. P95 read latency for `governance://agents.md` is under 500ms.
