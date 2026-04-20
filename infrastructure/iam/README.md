# infrastructure/iam

IAM trust policies and role-shape definitions for the Deployment Manager Gen2
pipeline (ENC-FTR-090, ENC-PLN-041 Phase 0 / ENC-TSK-F58).

The Gen2 pipeline uses short-lived tokens via GitHub Actions OIDC federation. Each
deploy target has its own role with a trust policy scoped by environment. No
long-lived AWS access keys live in GitHub secrets under Gen2.

## Files

- `github-actions-v3-prod-deploy-role-trust-policy.json` \u2014 trust policy for
  `GitHubActions-V3Prod-DeployRole`. Allows `sts:AssumeRoleWithWebIdentity` from the
  GitHub OIDC provider ONLY for workflow runs that target the `v3-prod` environment.

- `github-actions-v4-prod-deploy-role-trust-policy.json` \u2014 trust policy for
  `GitHubActions-V4Prod-DeployRole`. Same pattern, scoped to `v4-prod`.

- `release-bot-installation-README.md` \u2014 AC-2 prerequisite runbook for installing
  the release-bot GitHub App. Installation is a GitHub UI action performed by the
  repo admin; this file captures the required scope, webhook events, and the
  distinct-identity invariant that prevents self-approval rejection.

## Trust policy invariant

Every trust policy MUST use `StringEquals` on `token.actions.githubusercontent.com:sub`.
`StringLike` would allow a workflow to impersonate a different environment by crafting
its `sub` claim against the wildcard. ENC-FTR-090 AC-3 explicitly requires `StringEquals`.

The `sub` claim format produced by GitHub OIDC is:
```
repo:<owner>/<repo>:environment:<environment-name>
```

For Gen2, environments `v3-prod` and `v4-prod` are GitHub-configured environments
with a required-reviewer rule. A workflow can only produce that `sub` if it is
already gated by the environment's required-reviewer approval. The OIDC trust
policy is the second gate \u2014 AWS side.

## How to apply

```
aws iam create-role \
  --role-name GitHubActions-V3Prod-DeployRole \
  --assume-role-policy-document \
    file://infrastructure/iam/github-actions-v3-prod-deploy-role-trust-policy.json
aws iam create-role \
  --role-name GitHubActions-V4Prod-DeployRole \
  --assume-role-policy-document \
    file://infrastructure/iam/github-actions-v4-prod-deploy-role-trust-policy.json
```

Permissions policies are attached in Phase 2 / F60 when the reusable deploy workflow
lands.

## Related

- ENC-TSK-F58 (this task) \u2014 Phase 0 Foundation
- ENC-TSK-F60 \u2014 Phase 2 Deploy Workflow (consumes these roles)
- ENC-FTR-090 AC-3 \u2014 OIDC env-scoped trust policy invariant
