# Governance Data Dictionary

## Purpose
The governance data dictionary defines authoritative field semantics, allowed values, validation constraints, and usage guidance for governed Enceladus APIs.

Primary dictionary artifact:
- `backend/lambda/coordination_api/governance_data_dictionary.json`

Runtime lookup endpoint:
- `GET /api/v1/governance/dictionary`
  - Query params:
    - `entity` (optional)
    - `field` (optional, requires `entity`)
    - `value` (optional, requires `entity` + `field`)
    - `include_all=true` (optional full payload)

Backends:
- Preferred source: DynamoDB table `governance-policies` item `policy_id=governance_data_dictionary`
- Fallback source: bundled JSON file above (fail-safe read path)

## Ownership
- Primary owner: Enceladus platform engineering
- Secondary owner: Coordination API maintainers

## Update Workflow
1. Update governed schema/enum behavior in code.
2. Update `governance_data_dictionary.json` in the same change.
3. Ensure `Governance Dictionary Guard` workflow passes.
4. Deploy coordination API (`api-mcp-backend-deploy.yml`).
5. Validate endpoint results for affected entities/fields.

## Merge/Deploy Enforcement
- CI fail-closed guard:
  - Workflow: `.github/workflows/governance-dictionary-guard.yml`
  - Script: `tools/check_governance_dictionary_sync.py`
- If schema-affecting files change without dictionary updates, CI fails and merge/deploy must not proceed.

## Backward Compatibility Policy
- Prefer additive changes.
- Do not remove enum values or tighten required constraints without a migration plan.
- When breaking changes are necessary:
  - record migration strategy in feature/task worklog,
  - update dictionary definitions and usage guidance,
  - coordinate deploy sequencing across dependent clients.
