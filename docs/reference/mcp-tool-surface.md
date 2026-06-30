# MCP Tool Surface

Reference for the tool and action surface exposed by the Enceladus MCP server. The
implementation is `tools/enceladus-mcp-server/server.py`, deployed as the AWS Lambda
function `enceladus-mcp-code` and reachable at `https://mcp.jreese.net`.

The server operates in one of two interface modes, selected by the
`ENCELADUS_MCP_INTERFACE_MODE` environment variable: `raw` (default) and `code`. This
document describes the `code` mode surface.

For the rationale behind the API boundary, see
[About the MCP API boundary](../explanation/about-the-mcp-api-boundary.md). For startup
and connection procedures, see
[Run and connect the MCP server](../how-to/run-and-connect-the-mcp-server.md). For hybrid
retrieval usage, see
[Exercise hybrid retrieval](../how-to/exercise-hybrid-retrieval.md). The agent operating
contract is [AGENTS.md](../../AGENTS.md).

## Tools

Code mode (`ENCELADUS_MCP_INTERFACE_MODE=code`) exposes four composite tools. Each
dispatches to a domain action identifier supplied as a parameter.

| Tool | Purpose | Parameters |
| --- | --- | --- |
| `search` | Read-only discovery over governed resources. | `action` (string, required), `arguments` (object) |
| `execute` | Governed runner for ordered mutation and lifecycle steps. | `dry_run` (boolean), `steps` (array, required) |
| `get_compact_context` | Budgeted composite context assembly with optional three-signal hybrid retrieval. | `mode`, `record_id`, `project_id`, `document_id`, `domain`, `domains`, `max_tokens`, `history_limit`, `query`, `anchor_record_id`, `top_n`, `include_below_threshold`, `record_type`, `include_code_map`, `include_governance`, `include_related_documents`, `include_hybrid_retrieval` |
| `coordination` | Orchestration surface for capabilities, request inspection, dispatch-plan generation, and managed-session auth. | `action` (string, required), `arguments` (object) |

The `connection_health` operation is reachable as the `system.connection_health` action
through `search`.

### `search`

`action` is a read action identifier. `arguments` is forwarded to the underlying governed
read tool. Only `action` is required.

### `execute`

`steps` is an ordered array of step objects. Each step object has:

| Field | Type | Notes |
| --- | --- | --- |
| `action` | string | Mutation or lifecycle action identifier. Required. |
| `arguments` | object | Forwarded to the underlying governed tool. |
| `on_error` | string | `abort` (default) or `continue`. |
| `dry_run` | boolean | Step-level dry-run override. |

A top-level `dry_run` boolean resolves and validates all steps without executing them.

### `get_compact_context`

`mode` selects the context shape: `record`, `issue`, `task`, `feature`, `project`,
`document`, or `topic`. When `query` or `anchor_record_id` is supplied, the response adds a
`hybrid_retrieval` section ranking records by Reciprocal Rank Fusion over three signals:
vector cosine (HNSW), graph Personalized PageRank (Cypher fallback), and keyword
title/intent/description match. Callers who pass neither `query` nor `anchor_record_id`
receive the legacy context shape. `top_n` defaults to 20 (maximum 50).

### `coordination`

`action` is a coordination action identifier. `arguments` is forwarded to the underlying
governed coordination helper. Only `action` is required.

## Actions

Action identifiers are grouped by domain. The **Hash** column marks actions that require a
`governance_hash` argument.

### `search` actions (read-only)

| Action | Domain | Hash |
| --- | --- | --- |
| `projects.list` | Projects | — |
| `projects.get` | Projects | — |
| `tracker.get` | Tracker | — |
| `tracker.list` | Tracker | — |
| `tracker.pending_updates` | Tracker | — |
| `tracker.validation_rules` | Tracker | — |
| `tracker.graphsearch` | Tracker | — |
| `tracker.sheaf_cohomology` | Tracker | ENC-FTR-095 |
| `tracker.manifest` | Tracker | — |
| `tracker.get_acs` | Tracker | — |
| `tracker.worklog_timeline` | Tracker | — |
| `tracker.worklogs` | Tracker | — |
| `tracker.manifest_bulk` | Tracker | — |
| `tracker.list_relationships` | Tracker | — |
| `tracker.list_lessons` | Tracker | — |
| `documents.search` | Documents | — |
| `documents.get` | Documents | — |
| `documents.list` | Documents | — |
| `deploy.state_get` | Deploy | — |
| `deploy.history` | Deploy | — |
| `deploy.history_list` | Deploy | — |
| `deploy.status` | Deploy | — |
| `deploy.status_get` | Deploy | — |
| `deploy.pending_requests` | Deploy | — |
| `changelog.history` | Changelog | — |
| `changelog.history_all` | Changelog | — |
| `changelog.version` | Changelog | — |
| `governance.hash` | Governance | — |
| `governance.get` | Governance | — |
| `governance.dictionary` | Governance | — |
| `reference.search` | Reference | — |
| `system.connection_health` | System | — |
| `github.projects_list` | GitHub | — |
| `plan.objectives_status` | Plan | — |

`tracker.list_relationships`, `tracker.list_lessons`, and several mutation actions are
registered conditionally behind server feature flags (`ENABLE_TYPED_RELATIONSHIPS`,
`ENABLE_LESSON_PRIMITIVE`, `ENABLE_HANDOFF_PRIMITIVE`).

### `execute` actions (mutation and lifecycle)

| Action | Domain | Hash |
| --- | --- | --- |
| `tracker.create` | Tracker | Yes |
| `tracker.set` | Tracker | Yes |
| `tracker.log` | Tracker | Yes |
| `tracker.set_acceptance_evidence` | Tracker | Yes |
| `tracker.create_relationship` | Tracker | Yes |
| `tracker.archive_relationship` | Tracker | Yes |
| `tracker.create_lesson` | Tracker | Yes |
| `tracker.extend_lesson` | Tracker | Yes |
| `documents.check_policy` | Documents | — |
| `documents.put` | Documents | Yes |
| `documents.patch` | Documents | Yes |
| `document.create_handoff` | Documents | Yes |
| `document.claim_handoff` | Documents | Yes |
| `document.complete_handoff` | Documents | Yes |
| `document.create_coe` | Documents | Yes |
| `document.create_wave` | Documents | Yes |
| `document.append_handoff_reply` | Documents | Yes |
| `document.append_wave_entry` | Documents | Yes |
| `document.create_note` | Documents | Yes |
| `deploy.submit` | Deploy | Yes |
| `deploy.state_set` | Deploy | Yes |
| `deploy.trigger` | Deploy | — |
| `checkout.task` | Checkout | Yes |
| `checkout.release` | Checkout | Yes |
| `checkout.advance` | Checkout | Yes |
| `checkout.append_worklog` | Checkout | Yes |
| `github.create_issue` | GitHub | — |
| `github.projects_sync` | GitHub | — |
| `plan.create` | Plan | Yes |
| `plan.checkout` | Plan | Yes |
| `plan.advance` | Plan | Yes |
| `plan.add_objective` | Plan | Yes |
| `plan.remove_objective` | Plan | Yes |
| `plan.reorder_objectives` | Plan | Yes |
| `plan.replace_objectives` | Plan | Yes |
| `component.propose` | Component | Yes |
| `component.advance` | Component | Yes |
| `component.revert` | Component | Yes |
| `component.deprecate` | Component | Yes |
| `component.restore` | Component | Yes |
| `component.add_edge` | Component | Yes |
| `component.remove_edge` | Component | Yes |

The document handoff/COE/wave actions and the component actions are registered
conditionally behind server feature flags. `plan.create` resolves to the `tracker_create`
underlying tool.

### `coordination` actions

| Action | Hash |
| --- | --- |
| `capabilities.get` | — |
| `request.get` | — |
| `dispatch_plan.generate` | — |
| `dispatch_plan.dry_run` | — |
| `auth.cognito_session` | — |

## Authentication

The HTTP transport authenticates callers with Cognito OAuth JWTs (access or id tokens).
Validation:

- Algorithm `RS256`; tokens with any other `alg` are rejected.
- Signing keys are fetched from
  `https://cognito-idp.{region}.amazonaws.com/{pool}/.well-known/jwks.json`.
- The JWKS set is cached for 3600 seconds.
- The issuer is verified against
  `https://cognito-idp.{region}.amazonaws.com/{pool}`.
- Expiry is verified.
- For `token_use=access`, the `client_id` claim is compared against the configured client
  id; for `token_use=id`, the `aud` claim is compared.

Inter-service calls authenticate with internal API keys sent in the
`X-Coordination-Internal-Key` header. Each service accepts a set of keys collected from
plural `*_KEYS` environment variables, supporting key rotation.

## Deployment

| Attribute | Value |
| --- | --- |
| Lambda function | `enceladus-mcp-code` |
| Hosted endpoint | `https://mcp.jreese.net` |
| Transport modes | `stdio` (default) and `streamable_http`, selected by `ENCELADUS_MCP_TRANSPORT` |
| Interface modes | `raw` (default) and `code`, selected by `ENCELADUS_MCP_INTERFACE_MODE` |

The Lambda handler requires `ENCELADUS_MCP_TRANSPORT=streamable_http`.

### Data backend

| DynamoDB table | Default name |
| --- | --- |
| Tracker | `devops-project-tracker` |
| Projects | `projects` |
| Documents | `documents` |
| Coordination requests | `coordination-requests` |
| Deployment manager | `devops-deployment-manager` |
| Governance policies | `governance-policies` |
| Compliance violations | `agent-compliance-violations` |

Object storage uses the S3 bucket `jreese-net`. Table and bucket names are overridable by
environment variable.
