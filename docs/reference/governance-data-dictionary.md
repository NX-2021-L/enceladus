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

## Merge/Deploy Enforcement
- CI fail-closed guard:
  - Workflow: `.github/workflows/governance-dictionary-guard.yml`
  - Script: `tools/check_governance_dictionary_sync.py`
- If schema-affecting files change without dictionary updates, CI fails and merge/deploy is blocked.
