# Host-v2 MCP Connector and Fleet Template

## Purpose

Define the production path for host-v2 MCP readiness so coordination-dispatched sessions do not need manual MCP setup each run.

## One-Time MCP Provisioning (Host-v2)

Runtime contract:

1. Check profile + marker.
   - Profile path: `HOST_V2_MCP_PROFILE_PATH` (default `.claude/mcp.json`)
   - Marker path: `HOST_V2_MCP_MARKER_PATH` (default `.cache/enceladus/mcp-profile-installed-v1.json`)
2. If both are valid, skip install (`warm_skip`).
3. If missing/invalid, run installer with retries:
   - Installer: `HOST_V2_ENCELADUS_MCP_INSTALLER`
   - Retry config: `HOST_V2_MCP_BOOTSTRAP_MAX_ATTEMPTS`, `HOST_V2_MCP_BOOTSTRAP_RETRY_BACKOFF_SECONDS`
4. Validate profile includes server `enceladus`.
5. Write marker and emit preflight observability markers.

## Fleet Template (EC2 Host-v2)

Fleet nodes should run MCP bootstrap at first boot through user-data:

- Bootstrap script:
  - `tools/enceladus-mcp-server/host_v2_first_bootstrap.sh`
- User-data template:
  - `tools/enceladus-mcp-server/host_v2_user_data_template.sh`

When a launch template or AMI includes these assets, newly created host-v2 nodes start in warm MCP state for subsequent coordination dispatches.

## Coordination API Capability Surface

`coordination_capabilities` now exposes:

- `host_v2.mcp_bootstrap`
  - mode, profile/marker paths, retry policy, bootstrap script path
- `host_v2.fleet_template`
  - launch template id/version and user-data template path
- `enceladus_mcp_profile`
  - installer path and profile/marker paths

## Required Outcome

- Local terminal and host-v2 sessions share one setup-if-missing contract.
- Host-v2 sessions become one-time provisioned and skip redundant install work.
- Fleet-provisioned hosts can inherit MCP readiness by default.
