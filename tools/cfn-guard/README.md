# tools/cfn-guard

CloudFormation Guard policy-as-code invariants for the Deployment Manager Gen2 pipeline
(ENC-FTR-090, ENC-PLN-041 Phase 0 / ENC-TSK-F58).

These rules are evaluated in CI against every changed CFN template. They fail CI red
when a Lambda resource omits or mismatches the architecture / runtime invariants the
Gen2 matrix build depends on. Rules are authored against both
`AWS::Serverless::Function` (SAM) and `AWS::Lambda::Function` (plain CFN) so the same
invariants apply regardless of template flavor.

## Rule files

- `lambda-architecture.guard` — every Lambda must declare `Architectures` and the value
  must be one of `x86_64` (v3 prod, py3.11) or `arm64` (v4 prod, py3.12). Missing
  `Architectures` blocks the build because the Gen2 matrix uses it to route the artifact
  to the correct build row.

- `runtime-whitelist.guard` — `Runtime` must be one of the two pinned values
  (`python3.11` for v3 x86_64, `python3.12` for v4 arm64). Any other runtime is a
  governance violation that would desync the prod/gamma/v4 invariants documented in
  ENC-ISS-202 / ENC-ISS-213.

## Invocation

```
cfn-guard validate \
  --data infrastructure/cloudformation/*.yaml \
  --rules tools/cfn-guard/lambda-architecture.guard \
  --rules tools/cfn-guard/runtime-whitelist.guard
```

CI wires this into the `build-lambda-artifacts.yml` workflow (added in a subsequent
Gen2 phase task \u2014 F59). For the Phase 0 PR these rules are committed but not yet
enforced; the CI gate activation is part of F59 Phase 1 so Phase 0 can land without
blocking any in-flight CFN work.

## Expected failure modes

- New Lambda added without `Architectures` \u2014 fails with a pointer to this rule file.
- Template hardcodes `python3.9` or `python3.10` \u2014 fails with the whitelist values.
- Template declares an architecture outside `[x86_64, arm64]` \u2014 fails.

## Related

- ENC-TSK-F58 (this task) \u2014 Phase 0 Foundation
- ENC-TSK-F59 \u2014 Phase 1 Artifact Pipeline (activates CI enforcement)
- ENC-FTR-090 AC-5 \u2014 CFN Architectures-required invariant
- ENC-ISS-202 / ENC-ISS-213 / ENC-ISS-233 \u2014 prior python-version drift incidents
