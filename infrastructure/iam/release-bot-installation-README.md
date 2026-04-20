# Release-bot GitHub App \u2014 Installation Runbook

**Tracks**: ENC-TSK-F58 AC-2 (ENC-FTR-090 / ENC-PLN-041 Phase 0)
**Audience**: repo admin with GitHub App install authority for `NX-2021-L/enceladus`.
**Execution**: GitHub UI action (cannot be scripted through the PR). This file
records the exact configuration required so the install is auditable and repeatable.

## Why a GitHub App (not a PAT or the Actions default token)

The Gen2 required-reviewer gate uses GitHub Environments plus CODEOWNERS and the
branch-protection "require pull request" rule. The default `GITHUB_TOKEN` cannot
submit a PR review that satisfies required-reviewer rules when the PR author is
the same identity that opened the PR \u2014 GitHub blocks self-approval.

A dedicated release-bot App holds a distinct identity from any human or automated
PR author, so it can act as the automated "reviewer of last resort" for PRs that
have already passed all branch-protection checks and need a timing-deterministic
merge. It is also the identity that the Phase 2 reusable workflow uses to write
GitHub Deployments API entries.

## Required scope

```yaml
permissions:
  pull_requests: write   # submit review decisions; merge after checks pass
  contents: read         # read repo contents for deployment context
  deployments: write     # create/update GitHub Deployments API records
  actions: read          # fetch workflow run status for gate logic
  checks: read           # read required-check status
  metadata: read         # always required
events:
  - pull_request
  - pull_request_review
  - check_suite
  - workflow_run
  - deployment_status
```

The `deployments: write` scope is required for Phase 2 (F60) to land; listing it on
the App at install time means no re-install is needed when F60 ships.

## Distinct-identity invariant

**The App MUST NOT be installed under, or grant bypass permissions to, any user
who also authors deploy PRs.** If the App's effective identity ever matches the
PR author (e.g. because the App is run with the admin's user context), GitHub will
reject the review-submit with "pull request author cannot approve their own pull
request." This is a structural protection \u2014 we rely on it.

## Installation steps

1. Create the App at https://github.com/organizations/NX-2021-L/settings/apps/new
2. Name: `enceladus-release-bot`
3. Homepage URL: `https://jreese.net/enceladus`
4. Webhook URL: (deferred \u2014 F60 introduces the webhook target; skip for Phase 0)
5. Permissions: as the YAML block above
6. Events: as the YAML block above
7. Where to install: "Only on this account"
8. Install on: `NX-2021-L/enceladus` (single repo)
9. Save the App ID + private key to AWS Secrets Manager under
   `devops/release-bot-app/private-key` with companion metadata at
   `devops/release-bot-app/app-id`. F60 will consume these.
10. Add the installed App to the `.github/rulesets/automation-exempt.json` bypass
    list (already committed in this Phase 0 PR).

## Verification

After install, run from an admin shell:

```bash
curl -H "Accept: application/vnd.github+json" \
     -H "Authorization: Bearer $(gh auth token)" \
     https://api.github.com/repos/NX-2021-L/enceladus/installation
```

The response should include the App name `enceladus-release-bot` and the permissions
matching the scope above.

## Related

- ENC-TSK-F58 AC-2 (install \u2014 this runbook)
- ENC-TSK-F58 AC-4 (bypass list reference)
- ENC-TSK-F60 \u2014 Phase 2 Deploy Workflow (consumer)
- ENC-TSK-F61 \u2014 Phase 3 Approval Migration (consumer)
