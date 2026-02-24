# Terminal MCP Bootstrap Contract

## Purpose

Define one idempotent startup contract for terminal sessions that may begin without the Enceladus MCP profile preconfigured. This applies to:

- Local desktop terminal sessions
- Host-v2 terminal sessions launched by coordination dispatch
- Fleet-provisioned host-v2 sessions created from a launch template/AMI path

## Bootstrap Contract (Required Order)

1. Detect profile availability.
   - Check whether MCP config contains server name `enceladus`.
   - For host-v2, also check persistent marker file proving prior successful install.
2. Setup if missing.
   - Resolve installer path (primary + fallback candidates).
   - Run installer with bounded retries and backoff.
   - Persist success marker (host-v2) for future session skips.
3. Validate MCP health.
   - Confirm MCP connectivity reaches Enceladus resources.
   - Confirm required startup calls can run:
     - `connection_health`
     - `coordination_capabilities`
     - `governance_hash`
4. Initialize governance.
   - Read `governance://agents.md`.
   - Continue standard governance/session initialization from that file.
5. Enforce MCP-only execution.
   - Use MCP tools/resources for all Enceladus reads/writes.
   - Do not use direct `tracker.py`/`docstore.py`/`boto3`/`aws` calls during normal session task execution.

## Idempotency Rules

- Bootstrap is safe to run repeatedly.
- If profile + marker are already valid, installer is skipped and session continues.
- If marker exists but profile config is missing/corrupt, installer runs again and marker is refreshed.

## Failure Modes and Exit Semantics

| Stage | Failure Code | Action |
|------|---------------|--------|
| Installer discovery | `installer_missing` | Fail fast with explicit path diagnostics |
| Installer execution | `bootstrap_failed` | Retry with backoff; fail after max attempts |
| Profile validation | `profile_missing` | Fail fast and emit remediation instructions |
| MCP connectivity | `connectivity_failed` | Retry bounded loop; fail with structured preflight error |
| Governance init | `governance_unavailable` | Fail and report required resource URI |

## Context-Specific Behavior

### Local Terminal

- Prefer existing developer-installed profile.
- Run setup only when profile is absent/invalid.
- Continue immediately to governance initialization after validation.

### Host-v2 (Single Instance)

- Persist install marker under host home cache.
- Require marker + profile validation before skipping installer.
- Emit structured preflight markers in runtime logs for observability.

### Host-v2 Fleet

- Bake same setup contract into first-boot user-data/bootstrap.
- First boot installs MCP profile and writes marker.
- Coordination-dispatched sessions on those hosts should start in warm state and skip install.

## Required Observability Markers

- `COORDINATION_PREFLIGHT_OK={"stage":"mcp","status":"ok",...}`
- `COORDINATION_PREFLIGHT_MCP=pass`
- `COORDINATION_PREFLIGHT_ERROR={"stage":"mcp",...}` on failure paths

These markers provide deterministic evidence during validation matrix runs.
