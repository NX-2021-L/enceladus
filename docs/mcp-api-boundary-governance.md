# MCP API Boundary Governance

## Policy
All MCP tool handlers must access Enceladus business data through service APIs.

- Allowed: MCP tool -> HTTP API (`/api/v1/...`) -> service auth -> DynamoDB/S3.
- Disallowed: MCP tool handler directly reading/writing DynamoDB business tables.

This prevents transport-specific behavior drift and keeps auth, permissioning,
validation, and audit behavior consistent for terminal, desktop, and web agents.

## Enforcement

- CI workflow: `.github/workflows/mcp-api-boundary-guard.yml`
- Guard script: `tools/check_mcp_api_boundary.py`

The guard fails the build if async MCP tool handlers in
`tools/enceladus-mcp-server/server.py` directly call DynamoDB helpers or DynamoDB
operations.

## Scope

- This guard is focused on MCP *tool handlers*.
- Resource reads and infrastructure health checks are evaluated separately.

## Future Rules

- If a new data-domain tool is added, route it through the domain API first.
- If a direct table access exception is required, document the exception and add a
  scoped allowlist entry in the guard script with rationale and owner.
