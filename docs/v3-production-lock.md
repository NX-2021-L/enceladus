# V3 Production Lock & Gamma-First Deployment Process

**Status:** Active  
**Effective:** 2026-04-11  
**Tag:** `v3.0.0-restored` (commit `cb34be7243d0f3566e3ecf2b8c8c3543a046705b`)  
**Plan:** ENC-PLN-019 (V3 Full Restoration & Production Lockdown)  
**COE:** DOC-2CACF0D1E7E6

---

## Production Architecture (Locked)

| Property | Value | Enforced By |
|----------|-------|-------------|
| Architecture | x86_64 | CFN `!If [IsGamma, arm64, x86_64]`, CI guard, deploy.sh env guards |
| Runtime | python3.11 | CFN `!If [IsGamma, python3.12, python3.11]`, CI guard |
| Lambda count | 20 (CFN-managed) + checkout-service (standalone) | Lambda workflow manifest |
| Shared layer | x86_64 | `backend/lambda/shared_layer/deploy.sh` hardcodes x86_64 |

### Production Rules

1. **No arm64 on production** until v4 cutover is explicitly approved.
2. **No python3.12 on production** until v4 cutover is explicitly approved.
3. All CFN Lambda declarations MUST use `!If [IsGamma, <gamma_val>, <prod_val>]` conditionals.
4. Deploy scripts with binary dependencies MUST use `ENVIRONMENT_SUFFIX` conditional gating.
5. The CI guard (`tools/verify_lambda_arch_parity.py`) blocks PRs that violate rules 3-4.

---

## Gamma Architecture (v4 Target)

| Property | Value |
|----------|-------|
| Architecture | arm64 (Graviton2) |
| Runtime | python3.12 |
| Lambda count | 22 (20 CFN-managed + 2 checkout-service) |
| Environment suffix | `-gamma` |

### Gamma Stack Status (2026-04-11)

All 22 gamma Lambdas deployed:
- 20 on arm64/py3.12 (target architecture)
- 2 checkout-service variants on x86_64/py3.12 (deploy.sh needs update)

All 20 prod Lambdas have corresponding gamma functions. Checkout-service (standalone, not CFN-managed) has 2 extra gamma functions.

---

## Gamma-First Deployment Process

### Current State

All 27 Lambda deploy workflows support `ENVIRONMENT_SUFFIX` for gamma targeting:
- Workflows use the reusable workflow at `.github/workflows/lambda-deploy-reusable.yml`
- `ENVIRONMENT_SUFFIX: "-gamma"` activates gamma deployment path
- Deploy scripts conditionally select arm64/py3.12 when `ENVIRONMENT_SUFFIX` is non-empty

### Recommended Gamma-First Process (v4)

1. **Code change** -> PR -> merge to main
2. **Gamma deploy first**: Dispatch workflow with `ENVIRONMENT_SUFFIX="-gamma"`
3. **Gamma validation**: Verify function health, test endpoints
4. **Production deploy**: Dispatch workflow with default (empty) `ENVIRONMENT_SUFFIX`
5. **Production validation**: Full health check

### GitHub Actions Feasibility Assessment

**Current capability:** All workflows support manual dispatch (`workflow_dispatch`) with `environment` input that maps to `ENVIRONMENT_SUFFIX`. Gamma-first is achievable today with manual workflow dispatch ordering.

**Not yet implemented:**
- Automated gamma-first sequencing (deploy gamma -> validate -> deploy prod)
- Gamma health gates blocking production deploy
- Gamma-specific test suites

These would require a new orchestration workflow or enhancement to the deploy pipeline.

---

## CFN Stack Policy (Pending)

A CFN stack policy to prevent accidental architecture changes via CloudFormation updates has been prepared but not yet applied. Requires product-lead IAM (`cloudformation:SetStackPolicy`).

Script: `workspace/v3-recovery/02-cfn-rollback-to-x86.sh`

---

## Related Documents

- **COE:** DOC-2CACF0D1E7E6 (Sev1 MCP/PWA Outage 2026-04-11)
- **Plan:** ENC-PLN-019 (DOC-191E709E43C5)
- **CI Guard:** `tools/verify_lambda_arch_parity.py`
- **Manifest:** `infrastructure/lambda_workflow_manifest.json`
