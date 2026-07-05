# ENC-TSK-J40: Blast-Radius-Scoped Gen2 Lambda Deploys

PLN-060 Pile B / LCD-8b. Design doc for narrowing the Gen2 deploy pipeline
(`.github/workflows/_deploy.yml`) from "push code to every Lambda on every
merge" to "push code only to the Lambdas a merge actually touched."

## Problem

Every push to `v4/main` (and every `workflow_dispatch`/`workflow_call` to
`v3-prod`) rebuilds and redeploys **all** ~30 Lambda functions, regardless of
how small the actual change was. A one-line fix in `tracker_mutation` still
triggers `update-function-code` + alias update (and CodeDeploy canary, where
configured) for every other function too. This is wasted deploy time, wasted
CodeDeploy canary windows, and unnecessary blast radius: a bug in the deploy
pipeline itself, or a bad artifact for an unrelated function, can block or
break a deploy that only needed to touch one Lambda.

## Design

### Phase 1 (this task) — Lambda-code push scoping only

Scope is deliberately narrow: **only** which Lambda functions get
`update-function-code` called in `_deploy.yml`'s `deploy` job. `_build.yml`
still builds every function's artifact on every run (build-side selectivity
has a different risk profile — stale/missing artifacts across partial
rebuilds — and is left as a follow-up). CFN stack-level scoping (separate
`cloudformation-*-stack-deploy.yml` workflows) is also out of scope; those
already deploy independently per-stack.

### AC-1 / AC-3 — Affected-set computation (`tools/compute_affected_targets.py`)

Given `--environment` (the GitHub Deployments environment name, e.g.
`v4-gamma`), the script:

1. Resolves the **last successful GitHub Deployment SHA** for that
   environment via `gh api /repos/{repo}/deployments?environment=X` +
   `/statuses` (the existing deploy-state store — see `_deploy.yml`'s own
   AC-2 comment: "GitHub Deployments API is the deploy-state store").
2. `git diff --name-only <base>..<head>`.
3. If any changed path matches a cross-cutting pattern — shared layer
   source (`backend/lambda/shared_layer/`), IAM (`04-github-roles.yaml`),
   CFN parameter files (`envs/*.yaml`), the deploy workflow files
   themselves (`_build.yml`/`_deploy.yml`), or the build manifest
   (`lambda_workflow_manifest.json`) — **or** the base SHA can't be
   resolved, **or** the diff itself fails — output `full_scope=true` and an
   empty affected list. The caller must treat `full_scope=true` as "deploy
   everything," the current (safe) behavior.
4. Otherwise, map every changed `backend/lambda/<dir>/...` path to its
   `<dir>` and return that set as `affected_functions`.

This is the "ambiguity widens, never narrows" contract (AC-3): any failure
mode, any doubt, any cross-cutting touch produces the *wider* answer.

### AC-2 — Component registry `deploy_targets` + fail-closed coverage (`tools/assert_deploy_target_coverage.py`)

`deploy_targets` is added to the existing capability-declaration field set
on `component_registry.component` (ENC-TSK-E68's `_COMPONENT_CAPABILITY_FIELDS`
extension point in `coordination_api/lambda_function.py`) — a list of
backend/lambda directory names (fnmatch globs supported) the component owns
for deploy purposes.

The assertion is **asymmetric by design**: for each function in the
affected-set, find its owning component by `source_paths.directory`. If that
component declared `deploy_targets` and the affected function is **not**
covered by it, the deploy CI run fails closed — this is a real
misconfiguration (the component's own maintainer said "I only touch X" and
the diff proves otherwise). If the component has **not** declared
`deploy_targets` at all, the function is not gated — it simply doesn't
benefit from narrowing at the registry layer (it still gets deployed,
because the plain diff-inferred set already includes it). This means
enabling the feature does not retroactively block the ~27 of ~30 functions
that don't yet have an owning component with `deploy_targets` declared;
adoption is incremental, and getting it wrong can only ever widen (fail
closed / block), never silently under-deploy.

### AC-4 — Per-function selective push

`_deploy.yml`'s `resolve` job's S3-artifact-probe step now takes the
affected-set and narrows the probed (and therefore deployed) function list
to the intersection of "what changed" and "what's built," unless
`full_scope=true`. The `deploy` job's existing per-function push loop
(`update-function-code` + `--s3-key`, already structured as one unit per
target function) is untouched — it already only acts on whatever
`version_ids_json` it's handed, so narrowing that input is sufficient.

### AC-6 — Both lanes

`main` and `v4/main` maintain **forked** copies of `_build.yml`/`_deploy.yml`
(confirmed divergent — v4/main's `_build.yml` inlines MCP-server packaging
differently). This change lands as two separate, hand-ported PRs: one to
`main`, one to `v4/main`, each verified independently against that branch's
actual workflow file.

## Verification (AC-5)

`tools/test_compute_affected_targets.py` exercises `compute()` directly
(mocking `git diff`/`gh api` at the `_run` seam, no live AWS/GitHub calls
needed) for the two scenarios the AC calls out by name:

- A single changed file under one `backend/lambda/<dir>/` → `full_scope=False`,
  `affected_functions == [<dir>]` only.
- A changed file under `backend/lambda/shared_layer/` → `full_scope=True`
  (fans out to everything).

Run: `python3 tools/test_compute_affected_targets.py`

## Guardrails

- Every failure path (missing `gh`/git, malformed API response, no prior
  deployment) resolves to `full_scope=true`, never to an empty/no-op deploy.
- `assert_deploy_target_coverage.py` fails **open** (skips the check
  entirely, doesn't block) if `COORDINATION_INTERNAL_API_KEY` isn't
  configured or the registry API call itself fails — the coverage gate is a
  defense-in-depth addition on top of the diff-based narrowing, not a hard
  dependency for the base feature to function.
- No existing behavior changes for components that haven't opted into
  `deploy_targets`.

## Follow-ups (explicitly out of scope here)

- Build-side selectivity (skip building artifacts for unaffected functions).
- CFN stack-level blast-radius scoping (separate deploy lane entirely).
- Backfilling `deploy_targets` across the remaining component registry
  entries (only the 3 pre-existing Enceladus Lambda components — checkout
  service, coordination API, tracker mutation — are seeded in this PR).
