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
| Shared layer | `enceladus-shared:8` (python3.11 / x86_64) | `backend/lambda/shared_layer/deploy.sh` ENVIRONMENT_SUFFIX-conditional pip flags + CI guard |
| Layer ABI parity | cp311 .so wheels only on prod | `tools/verify_lambda_arch_parity.py` shared-layer guard (ENC-ISS-198) |

### Production Rules

1. **No arm64 on production** until v4 cutover is explicitly approved.
2. **No python3.12 on production** until v4 cutover is explicitly approved.
3. All CFN Lambda declarations MUST use `!If [IsGamma, <gamma_val>, <prod_val>]` conditionals.
4. Deploy scripts with binary dependencies MUST use `ENVIRONMENT_SUFFIX` conditional gating.
5. The CI guard (`tools/verify_lambda_arch_parity.py`) blocks PRs that violate rules 3-4.
6. **Shared layer build scripts MUST pass all three pip flags** — `--platform`, `--python-version`, and `--abi` — to override the consumer ABI on every dimension. Single-flag fixes are insufficient (ENC-ISS-198). Enforced by `_validate_shared_layer_deploy_script()` in the CI guard.
7. **Lifeboat layer versions MUST be preserved.** `enceladus-shared:6` (the last clean python3.11/x86_64 build before the ENC-ISS-198 regression) is retained as a documented rollback target. Do not delete published layer versions that are referenced as lifeboats.
8. **Recovery validation MUST include an authenticated probe.** Synthetic `aws lambda invoke` probes with no `Authorization` header land in the no-token path of `auth.py:_authenticate()` and return HTTP 401 *before* `_verify_token()` is ever called — this is structurally indistinguishable from the 401 a real Cognito request produces when JWT init has silently failed. Use `tools/probe_cognito_auth.sh` (or equivalent) to bootstrap a real Cognito IdToken and probe with `Authorization: Bearer`.

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

## Layer ABI Parity Invariant (ENC-ISS-198 / ENC-TSK-D22)

The original V3 production lock validated the CFN template's `Architectures` and `Runtime` declarations but did **not** validate that attached shared layers carry the matching ABI. ENC-ISS-198 was a 3-hour-latent bug caused by exactly that gap: `enceladus-shared:7` was published 2026-04-03 by ENC-TSK-B42 with a `cpython-312-x86_64-linux-gnu` cffi backend, the V3 lock recovery rolled prod Lambdas back to python3.11/x86_64 without rolling back the layer, and every Cognito-authenticated PWA write returned a misleading HTTP 401 *"JWT library not available in Lambda package"* — until the user surfaced it via a manual worklog write attempt against DVP-TSK-481 at `2026-04-11T09:17Z`.

### Three-flag rule

Lambda layer build scripts must override every dimension of the consumer ABI explicitly:

| Dimension | pip flag | Prod value | Gamma value |
|---|---|---|---|
| OS / arch | `--platform` | `manylinux2014_x86_64` | `manylinux2014_aarch64` |
| Python version | `--python-version` | `3.11` | `3.12` |
| Python ABI tag | `--abi` | `cp311` | `cp312` |

If any flag is omitted, pip falls back to the **builder's** Python ABI and produces wheels that may not load on the consumer runtime. The failure is always silent (`import jwt` raises ImportError, the surrounding `except` swallows it, `_JWT_AVAILABLE = False`, every Cognito request returns HTTP 401).

`backend/lambda/shared_layer/deploy.sh` is now ENVIRONMENT_SUFFIX-aware: prod targets `python3.11 / cp311 / x86_64`, gamma targets `python3.12 / cp312 / aarch64`. The publish call also passes `--compatible-architectures` so the published layer metadata is honest and auditable.

### CI guard extension

`tools/verify_lambda_arch_parity.py` now includes `_validate_shared_layer_deploy_script()` which enforces:

1. All three pip flags (`--platform`, `--python-version`, `--abi`) are present in the script.
2. The prod build target (`manylinux2014_x86_64` / `3.11` / `cp311`) is fully pinned.
3. `aws lambda publish-layer-version` is invoked with `--compatible-architectures` so the layer metadata is honest.
4. The script's documentation comment references `ENC-ISS-198` so the historical precedent chain (ENC-ISS-041, ENC-ISS-044, ENC-ISS-198) is preserved for the next maintainer.

Test fixtures in `tools/test_verify_lambda_arch_parity.py` cover both a known-bad case (the pre-fix script that produced ENC-ISS-198) and a known-good case (the post-fix script).

### Lifeboat layer policy

`enceladus-shared:6` (created `2026-02-24T19:09Z`, descriptor *"rebuilt for Linux x86_64 Python 3.11 (ENC-ISS-044)"*, `CompatibleRuntimes=[python3.11]`, `CompatibleArchitectures=[x86_64]`) is the documented rollback target for prod. **Do not delete it.** If a future layer publish breaks prod, re-attach v6 via `aws lambda update-function-configuration --layers arn:aws:lambda:us-west-2:356364570033:layer:enceladus-shared:6 …` per function. v6's contents have been validated against the V3 lock.

### Authenticated-probe requirement

DOC-2CACF0D1E7E6 §3 Phase R3 used `aws lambda invoke` with no `Authorization` header for empirical validation. That probe lands in the no-token path of `auth.py:_authenticate()` and returns HTTP 401 *before* `_verify_token()` is ever called — structurally indistinguishable from the 401 a real Cognito request produces when JWT init has silently failed. The COE Lesson 4 ("empirical validation beats inference") is correct in spirit but the specific implementation was structurally blind to ENC-ISS-198.

`tools/probe_cognito_auth.sh` is the new authenticated-probe primitive. It bootstraps a Cognito IdToken via the terminal-agent path (`devops/coordination/cognito/terminal-agent` Secrets Manager record → `cognito-idp:initiate-auth` → IdToken), then probes a configurable list of Cognito-protected routes with `Authorization: Bearer <IdToken>`. The probe FAILs on any response containing the canonical `"JWT library not available in Lambda package"` string, regardless of HTTP status.

**All future v3 lock validation runs MUST include an authenticated probe.** Add it to `workspace/v3-recovery/03-validate-prod-health.sh` (or its successor).

### Open follow-up

Adding a runtime check to `verify_lambda_arch_parity.py` that fetches each Lambda's attached layer artifacts via `aws lambda get-layer-version` and inspects `.so` ABI tags directly is left as a future enhancement. It would close the remaining gap between source-of-truth validation (current static check) and live-attachment validation. The static check catches the regression at PR time; the runtime check would catch it at deploy time. Both layers of defense are valuable but the static check is sufficient to prevent the ENC-ISS-198 class of bug from reoccurring.

---

## Split-Artifact Build Pipeline (ENC-TSK-E20)

### Overview

The split-artifact pipeline centralizes Lambda package building into a single GitHub Actions workflow (`build-lambda-artifacts.yml`) that produces architecture-tagged zip artifacts in S3. This replaces the previous model where each deploy workflow built its own package inline, eliminating architecture contamination risk at the source.

### S3 naming convention

All Lambda artifacts are stored in the `jreese-net` bucket under a deterministic key structure:

```
lambda-artifacts/{git_sha}/{arch_tag}/{function_name}.zip
```

Where `arch_tag` is one of:
- `x86_64-py311` — production (v3)
- `arm64-py312` — gamma (v4)

Example:
```
s3://jreese-net/lambda-artifacts/58a9128fc150.../x86_64-py311/devops-coordination-api.zip
s3://jreese-net/lambda-artifacts/58a9128fc150.../arm64-py312/devops-coordination-api.zip
```

### Build workflow

`.github/workflows/build-lambda-artifacts.yml` runs on every push to main:
1. Reads function list from `infrastructure/lambda_workflow_manifest.json`
2. Builds both `x86_64-py311` and `arm64-py312` variants for each function
3. Uploads zips to S3 under the commit SHA prefix
4. Outputs `artifact_prefix` for downstream consumption

Build logic is implemented in `tools/package_lambda_artifact.sh`. Deploy-side resolution is handled by `tools/lambda_artifact_helper.sh` (sourced by all 31 `deploy.sh` scripts).

### Arch-tag validation gate

`.github/workflows/lambda-deploy-reusable.yml` includes an arch-tag validation step that verifies the artifact S3 key's arch tag matches the target environment before proceeding with `aws lambda update-function-code`. This prevents a gamma artifact from being deployed to production (or vice versa).

### Deploy intake validation

`deploy_intake` `_handle_submit()` validates `source_artifact_s3_key` when present:
1. S3 key format must match `lambda-artifacts/{sha}/{arch_tag}/{fn}.zip`
2. Arch tag must be a recognized value (`x86_64-py311` or `arm64-py312`)
3. Arch tag must match the target environment derived from the project ID

The MCP server `deploy_submit` tool accepts and forwards this parameter.

### CI parity audit

`tools/verify_lambda_arch_parity.py` includes `_validate_artifact_s3_layout()` (activated via `--check-s3-artifacts GIT_SHA`):
- Reads the manifest to enumerate all functions
- Lists S3 objects under each environment's arch-tag prefix
- Reports any function missing its expected artifact zip

### Known limitation

**ENC-ISS-237 (P1):** The `enceladus-backend-deploy-github-role` IAM role currently lacks `s3:PutObject` permission on the `lambda-artifacts/` S3 prefix. The `build-lambda-artifacts.yml` upload step fails with AccessDenied until this IAM policy is updated. The pipeline architecture is complete and validated; only the IAM grant is missing.

### Phased delivery

| Phase | Task | PR | Summary |
|-------|------|----|---------|
| 1 | ENC-TSK-E26 | #339 | Build workflow + package script + manifest |
| 2 | ENC-TSK-E27 | #340 | Deploy-side artifact helper + 31 deploy.sh scripts |
| 3 | ENC-TSK-E28 | #341 | deploy-orchestration.yml wiring + arch-tag gate |
| 4 | ENC-TSK-E29 | #342 | Deploy intake validation + parity audit |
| 5 | ENC-TSK-E30 | — | Documentation + governance dictionary (this section) |

---

## Related Documents

- **COE (operational):** DOC-2CACF0D1E7E6 (Sev1 MCP/PWA Outage 2026-04-11)
- **COE (strategic):** DOC-E9B160563B1C v6 §Addendum (ENC-ISS-198 — Shared Layer Build ABI Drift)
- **Plan:** ENC-PLN-019 (DOC-191E709E43C5)
- **CI Guard:** `tools/verify_lambda_arch_parity.py`
- **CI Guard tests:** `tools/test_verify_lambda_arch_parity.py`
- **Authenticated probe:** `tools/probe_cognito_auth.sh`
- **Manifest:** `infrastructure/lambda_workflow_manifest.json`
- **Issue:** ENC-ISS-198 (P1 — PWA Cognito writes broken by layer ABI mismatch)
- **Fix task:** ENC-TSK-D22
- **Split-artifact pipeline:** ENC-TSK-E20 (parent), ENC-TSK-E26–E30 (phases 1–5)
- **Build workflow:** `.github/workflows/build-lambda-artifacts.yml`
- **Package script:** `tools/package_lambda_artifact.sh`
- **Artifact helper:** `tools/lambda_artifact_helper.sh`
- **IAM gap:** ENC-ISS-237 (S3 PutObject on `lambda-artifacts/` prefix)
