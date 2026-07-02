#!/usr/bin/env python3
"""ENC-TSK-J65 / ENC-FTR-120: prod-gate coverage guard.

Enforces the FTR-120 invariant as a repo property: no agent-reachable git
operation mutates v3-prod without pausing on the v3-prod GitHub Environment
required-reviewer gate. Consumes tools/prod_gate_baseline.json (ENC-TSK-J64)
and statically verifies the actual workflow YAML matches its classification.

Fail-closed rules (any violation => exit 1, naming the file/job):
  1. Every .github/workflows/*.yml file MUST appear in the baseline. An
     unclassified workflow fails CI until someone classifies it.
  2. class=prod-mutating: every job in gated_jobs must carry
     environment: v3-prod verbatim in the workflow YAML.
  3. class=prod-mutating with EMPTY gated_jobs: allowed only as a recorded
     grace entry (notes mention ENC-TSK-J63). Grace entries must still exist
     and still be ungated -- if one gained an environment, the baseline is
     stale and must be updated (grace lists may not rot silently).
  4. class=conditional: every job in gated_jobs must have an environment
     expression whose text contains 'v3-prod' (the prod path must gate).
  5. class=already-gated: every job in gated_jobs must have SOME environment
     key (literal or expression).
  6. Baseline entries whose workflow file does not exist on THIS branch are
     skipped (main and v4/main carry branch-specific workflows) -- but a
     baseline entry is required for every file that DOES exist (rule 1).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    print("::error::PyYAML is required (pip install pyyaml)")
    sys.exit(2)

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
BASELINE_PATH = REPO_ROOT / "tools" / "prod_gate_baseline.json"

VALID_CLASSES = {"prod-mutating", "gamma-only", "conditional", "already-gated", "inert"}
GRACE_MARKER = "ENC-TSK-J63"


def load_workflow(path: Path) -> dict:
    with open(path) as fh:
        doc = yaml.safe_load(fh)
    if not isinstance(doc, dict):
        raise ValueError(f"{path.name}: not a mapping")
    return doc


def job_environment(job: dict):
    """Return the environment value for a job: str, dict ({name: ...}), or None."""
    env = job.get("environment")
    if isinstance(env, dict):
        return env.get("name")
    return env


def check(workflows_dir: Path = WORKFLOWS_DIR, baseline_path: Path = BASELINE_PATH) -> list[str]:
    """Return a list of violation strings (empty == pass)."""
    violations: list[str] = []

    baseline = json.loads(baseline_path.read_text())
    entries = baseline.get("workflows", {})

    files = sorted(p.name for p in workflows_dir.glob("*.yml")) + sorted(
        p.name for p in workflows_dir.glob("*.yaml")
    )

    # Rule 1: every present file must be classified.
    for fname in files:
        if fname not in entries:
            violations.append(
                f"{fname}: NOT in tools/prod_gate_baseline.json -- classify it "
                f"(prod-mutating/gamma-only/conditional/already-gated/inert) before merging."
            )

    for fname, entry in entries.items():
        wf_path = workflows_dir / fname
        if not wf_path.exists():
            continue  # rule 6: branch-specific workflow, entry applies where the file exists

        cls = entry.get("class")
        if cls not in VALID_CLASSES:
            violations.append(f"{fname}: invalid class {cls!r} in baseline.")
            continue

        try:
            doc = load_workflow(wf_path)
        except Exception as exc:
            violations.append(f"{fname}: unparseable workflow YAML ({exc}).")
            continue

        # PyYAML parses the bare `on:` trigger key as boolean True.
        jobs = doc.get("jobs") or {}
        gated_jobs = entry.get("gated_jobs") or []

        for job_id in gated_jobs:
            job = jobs.get(job_id)
            if job is None:
                violations.append(
                    f"{fname}: baseline names gated job {job_id!r} which does not exist -- "
                    f"update the baseline to match the workflow."
                )
                continue
            env = job_environment(job)
            if cls == "prod-mutating":
                if env != "v3-prod":
                    violations.append(
                        f"{fname} job {job_id!r}: class=prod-mutating requires "
                        f"environment: v3-prod, found {env!r}."
                    )
            elif cls == "conditional":
                if not (isinstance(env, str) and "v3-prod" in env):
                    violations.append(
                        f"{fname} job {job_id!r}: class=conditional requires an environment "
                        f"expression containing 'v3-prod', found {env!r}."
                    )
            elif cls == "already-gated":
                if not env:
                    violations.append(
                        f"{fname} job {job_id!r}: class=already-gated but the job has no "
                        f"environment key."
                    )

        if cls == "prod-mutating" and not gated_jobs:
            notes = entry.get("notes", "")
            if GRACE_MARKER not in notes:
                violations.append(
                    f"{fname}: class=prod-mutating with no gated_jobs and no {GRACE_MARKER} "
                    f"grace marker -- gate its mutating job with environment: v3-prod."
                )
            else:
                # Rule 3: grace entries may not rot -- if the workflow gained a gate,
                # the baseline must be promoted (grace list must shrink, not linger).
                any_env = any(job_environment(j) for j in jobs.values() if isinstance(j, dict))
                if any_env:
                    violations.append(
                        f"{fname}: recorded as an ungated {GRACE_MARKER} grace entry but now "
                        f"carries an environment -- promote its baseline entry (class/gated_jobs)."
                    )

    return violations


def main() -> int:
    violations = check()
    if violations:
        for v in violations:
            print(f"::error::{v}")
        print(f"[FAIL] prod-gate coverage guard: {len(violations)} violation(s).")
        return 1
    print("[SUCCESS] prod-gate coverage guard: every workflow classified; every prod lane gated or in recorded grace.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
