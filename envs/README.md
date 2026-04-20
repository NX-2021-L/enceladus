# envs/

Environment manifests for the Deployment Manager Gen2 pipeline
(ENC-FTR-090, ENC-PLN-041 Phase 8 / ENC-TSK-F66).

Each manifest captures the invariants for a single target environment (stack name,
deploy role ARN, architecture, runtime, artifact bucket prefix, required
approvers, CodeDeploy canary preference). The Gen2 `_deploy.yml` reusable workflow
(F60 Phase 2) reads the manifest to parameterize the deploy; no env-specific
logic lives in the workflow itself.

## Current manifests

- `v3-prod.yaml` \u2014 v3 production stack (x86_64, python3.11). **Authored in F65
  Phase 7 cutover (not yet present).** v3 is the current production target.
- `v4-gamma.yaml` \u2014 v4 pre-prod on the arm64/python3.12 matrix row. First
  consumer of the Gen2 pipeline end-to-end. Authored here in Phase 8 scaffold
  (this PR).
- `v4-prod.yaml` \u2014 v4 production on arm64/python3.12. Guards against accidental
  prod deploy until the environment is created on the AWS side. Authored here
  in Phase 8 scaffold (this PR).

## Shape validation

`tools/cfn-guard/manifest-shape.guard` (this PR) enforces the schema against
every YAML file in this directory. Required top-level keys:

```yaml
env_name: string       # v3-gamma | v3-prod | v4-gamma | v4-prod
architecture: x86_64|arm64
runtime: python3.11|python3.12
stack_name: string
deploy_role_arn: arn
artifact_bucket: string
artifact_prefix: string
required_reviewers: list[string]
canary_preference: Linear10PercentEvery1Minute | Linear10PercentEvery10Minutes | AllAtOnce
runner_label: string   # ubuntu-latest (x86_64) | ubuntu-24.04-arm (arm64)
environment: string    # GitHub environment name (v3-prod, v4-prod, etc.)
```

## Invariants

- `architecture == arm64` MUST pair with `runtime == python3.12` and
  `runner_label == ubuntu-24.04-arm`.
- `architecture == x86_64` MUST pair with `runtime == python3.11` and
  `runner_label == ubuntu-latest`.
- `deploy_role_arn` MUST match the OIDC trust policy scope for `environment`
  (see `infrastructure/iam/github-actions-*-prod-deploy-role-trust-policy.json`).

## Related

- ENC-TSK-F66 (this task) \u2014 Phase 8 v4 bring-up scaffold
- ENC-TSK-F58 \u2014 Phase 0 (cfn-guard framework + trust policies)
- ENC-TSK-F60 \u2014 Phase 2 reusable `_deploy.yml` (manifest consumer)
- ENC-TSK-F65 \u2014 Phase 7 v3 cutover (adds v3 manifests)
- ENC-FTR-090 AC-7 \u2014 v4-prod arm64/python3.12 matrix row
