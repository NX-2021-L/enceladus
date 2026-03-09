# Terminal MCP Bootstrap Validation Matrix

## Scope

Validation for:

- `ENC-TSK-476` terminal bootstrap contract
- `ENC-TSK-477` terminal session briefing template
- `ENC-TSK-478` host-v2 one-time MCP connector provisioning
- `ENC-TSK-479` host-v2 fleet bootstrap template
- `ENC-TSK-480` matrix execution and evidence capture
- `ENC-TSK-845` lifecycle primer bootstrap rollout
- `ENC-TSK-850` cross-provider validation for first-session lifecycle awareness

## Automated Test Evidence

- Coordination API unit tests:
  - Command: `python3 -m pytest -q backend/lambda/coordination_api/test_lambda_function.py`
  - Result: `154 passed`
  - Coverage includes host-v2 MCP bootstrap assertions plus lifecycle-primer prompt inclusion and priority ordering.
- Lifecycle-aware coordination prompt tests:
  - Command: `python3 -m pytest -q backend/lambda/coordination_api/test_lambda_function.py`
  - Result: recorded in `/tmp/enceladus-mcp-lifecycle-primer.28DTHd/coordination_pytest.log`
  - Coverage includes lifecycle-primer prompt inclusion and priority ordering for managed dispatch/bootstrap flows.

## Matrix Results

All scenarios passed in this session.

| Scenario | Method | Result | Evidence |
|---------|--------|--------|----------|
| Local terminal cold start | Run `install_profile.sh` with empty HOME | PASS | `/tmp/enceladus-mcp-matrix/local_cold.log` |
| Local terminal warm start | Re-run `install_profile.sh` with existing profile | PASS | `/tmp/enceladus-mcp-matrix/local_warm.log` |
| Codex cold start lifecycle bootstrap | Run `install_profile.sh` with empty HOME and inspect `.codex/config.toml` + `.codex/AGENTS.md` | PASS | `/tmp/enceladus-mcp-lifecycle-primer.28DTHd/install_cold.log`, `/tmp/enceladus-mcp-lifecycle-primer.28DTHd/home/.codex/config.toml`, `/tmp/enceladus-mcp-lifecycle-primer.28DTHd/home/.codex/AGENTS.md` |
| Claude cold start lifecycle bootstrap | Same cold-start install and inspect `.claude/CLAUDE.md` | PASS | `/tmp/enceladus-mcp-lifecycle-primer.28DTHd/install_cold.log`, `/tmp/enceladus-mcp-lifecycle-primer.28DTHd/home/.claude/CLAUDE.md` |
| Lifecycle warm start idempotence | Re-run installer against the same HOME and confirm lifecycle references remain | PASS | `/tmp/enceladus-mcp-lifecycle-primer.28DTHd/install_warm.log` |
| Bedrock/managed dispatch lifecycle preload | Run `python3 -m pytest -q backend/lambda/coordination_api/test_lambda_function.py` | PASS | `/tmp/enceladus-mcp-lifecycle-primer.28DTHd/coordination_pytest.log` |
| Host-v2 cold start | Run `host_v2_first_bootstrap.sh` against empty host home | PASS | `/tmp/enceladus-mcp-matrix/host_cold.log` |
| Host-v2 warm start | Re-run `host_v2_first_bootstrap.sh` and verify warm skip | PASS | `/tmp/enceladus-mcp-matrix/host_warm.log` |
| Fleet-provisioned host session | Run `host_v2_user_data_template.sh` first-boot path | PASS | `/tmp/enceladus-mcp-matrix/fleet_run.log`, `/tmp/enceladus-mcp-matrix/fleet_userdata.log` |

## Session Governance Check

- Terminal template enforces MCP bootstrap then governance initialization:
  - `SESSION_BRIEFING_TEMPLATE-TERMINAL.md`
- Both templates enforce MCP-only work mode (no direct tracker/docstore/aws/boto3 in normal task execution):
  - `SESSION_BRIEFING_TEMPLATE-UI.md`
  - `SESSION_BRIEFING_TEMPLATE-TERMINAL.md`

## Notes

- Host-v2 and fleet checks were executed as controlled local simulations using host-v2 scripts and isolated HOME paths.
- Runtime capability metadata for host-v2 bootstrap and fleet template is exposed by coordination API code changes and validated by unit tests.
