# .github/rulesets

GitHub Repository Rulesets (JSON spec) for the Gen2 pipeline
(ENC-FTR-090, ENC-PLN-041 Phase 0 / ENC-TSK-F58).

Rulesets are a stricter replacement for classic branch-protection rules. They apply
to a pattern of refs and can be bypassed ONLY by members of an explicit bypass list.
Unlike branch protection, they are composable: you can layer a strict `main-quality`
rule set with a narrow `automation-exempt` bypass rule set so that the release-bot
App can merge PRs that satisfy the quality gate without the App owner also gaining
bypass elsewhere.

## Files

- `main-quality.json` \u2014 branch ruleset on `main` that enforces: PR required, at
  least one approving review, required status checks (build + cfn-guard + commit-
  gate + governance-dict-guard), linear history, no force-push, no deletion.

- `automation-exempt.json` \u2014 separate ruleset declaring the release-bot App
  (see `/infrastructure/iam/release-bot-installation-README.md`) as a bypass actor
  for the narrow case of "merge a PR that has already passed all checks." No other
  rule in this set is bypassed.

## How these land on GitHub

Rulesets cannot be applied from a PR merge alone \u2014 they require a `gh api` call
against `/repos/{owner}/{repo}/rulesets`. The JSON files in this directory are the
canonical source; the runbook to apply them lives in `main-quality.json` as a top-
of-file comment (which GitHub strips on POST; the runbook is for human reference).

```
gh api -X POST \
  /repos/NX-2021-L/enceladus/rulesets \
  --input .github/rulesets/main-quality.json
gh api -X POST \
  /repos/NX-2021-L/enceladus/rulesets \
  --input .github/rulesets/automation-exempt.json
```

Application is a Phase 0 prerequisite for Phase 2 (F60) but is an AWS/GitHub Ops
action, not a repo PR merge. The JSON files are committed in this Phase 0 PR so
the state is reproducible; the actual API application is a follow-up F60 step.

## Invariant protection

The `main-quality` ruleset protects itself via the CODEOWNERS entry on
`/.github/rulesets/` (owned by @io). A drift auditor under F64 (Phase 6) will
additionally compare live ruleset state against these JSON files and file an
ENC-ISS- if they diverge.

## Related

- ENC-TSK-F58 AC-4 (this task \u2014 commits ruleset JSON)
- ENC-TSK-F60 \u2014 Phase 2 applies rulesets via gh api
- ENC-TSK-F64 \u2014 Phase 6 drift auditor detects ruleset drift
