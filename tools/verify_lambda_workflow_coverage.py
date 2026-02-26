#!/usr/bin/env python3
"""Verify production Lambda workflow coverage.

This guard enforces that each production Lambda declared in
infrastructure/cloudformation/02-compute.yaml has a workflow entry in
infrastructure/lambda_workflow_manifest.json, and that each mapped workflow file
exists in the repository.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Dict, List, Set

REPO_ROOT = Path(__file__).resolve().parents[1]
COMPUTE_TEMPLATE = REPO_ROOT / "infrastructure/cloudformation/02-compute.yaml"
MANIFEST_PATH = REPO_ROOT / "infrastructure/lambda_workflow_manifest.json"


def _parse_production_lambdas(template_path: Path) -> List[str]:
    names: List[str] = []
    expect_function_name = False

    for raw in template_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()

        if line.startswith("Type:") and "AWS::Lambda::Function" in line:
            expect_function_name = True
            continue

        if expect_function_name and line.startswith("FunctionName:"):
            value = line.split("FunctionName:", 1)[1].strip().strip('"\'')
            if value and not value.startswith("!"):
                names.append(value)
            expect_function_name = False

    return names


def _load_manifest(manifest_path: Path) -> List[Dict[str, object]]:
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    functions = payload.get("functions")
    if not isinstance(functions, list):
        raise ValueError("Manifest must contain a top-level 'functions' list")
    return functions


def _validate(manifest: List[Dict[str, object]], production: List[str]) -> List[str]:
    errors: List[str] = []

    manifest_names: List[str] = []
    seen: Set[str] = set()

    for idx, entry in enumerate(manifest):
        if not isinstance(entry, dict):
            errors.append(f"functions[{idx}] must be an object")
            continue

        function_name = entry.get("function_name")
        lambda_dir = entry.get("lambda_dir")
        workflow_file = entry.get("workflow_file")
        deploy_script = entry.get("deploy_script")

        if not isinstance(function_name, str) or not function_name:
            errors.append(f"functions[{idx}].function_name must be a non-empty string")
            continue

        if function_name in seen:
            errors.append(f"Duplicate function_name in manifest: {function_name}")
        seen.add(function_name)
        manifest_names.append(function_name)

        if not isinstance(lambda_dir, str) or not lambda_dir:
            errors.append(f"{function_name}: lambda_dir must be a non-empty string")
        else:
            lambda_dir_path = REPO_ROOT / lambda_dir
            if not lambda_dir_path.is_dir():
                errors.append(f"{function_name}: lambda_dir does not exist: {lambda_dir}")

        if not isinstance(workflow_file, str) or not workflow_file:
            errors.append(f"{function_name}: workflow_file must be a non-empty string")
        else:
            workflow_path = REPO_ROOT / workflow_file
            if not workflow_path.is_file():
                errors.append(f"{function_name}: workflow file missing: {workflow_file}")
            else:
                text = workflow_path.read_text(encoding="utf-8")
                if function_name not in text:
                    errors.append(
                        f"{function_name}: workflow file does not reference function name: {workflow_file}"
                    )

        if isinstance(deploy_script, str) and deploy_script:
            deploy_script_path = REPO_ROOT / deploy_script
            if not deploy_script_path.is_file():
                errors.append(f"{function_name}: deploy_script missing: {deploy_script}")

    manifest_set = set(manifest_names)
    production_set = set(production)

    missing_manifest_entries = sorted(production_set - manifest_set)
    extra_manifest_entries = sorted(manifest_set - production_set)

    if missing_manifest_entries:
        errors.append(
            "Missing manifest entries for production Lambdas: "
            + ", ".join(missing_manifest_entries)
        )

    if extra_manifest_entries:
        errors.append(
            "Manifest has non-production Lambda entries: "
            + ", ".join(extra_manifest_entries)
        )

    return errors


def main() -> int:
    if not COMPUTE_TEMPLATE.is_file():
        print(f"[ERROR] Compute template missing: {COMPUTE_TEMPLATE}")
        return 1

    if not MANIFEST_PATH.is_file():
        print(f"[ERROR] Manifest missing: {MANIFEST_PATH}")
        return 1

    production = _parse_production_lambdas(COMPUTE_TEMPLATE)
    manifest = _load_manifest(MANIFEST_PATH)
    errors = _validate(manifest, production)

    if errors:
        print("[ERROR] Lambda workflow coverage validation failed:")
        for err in errors:
            print(f"  - {err}")
        return 1

    print(
        "[SUCCESS] Lambda workflow coverage valid: "
        f"{len(production)} production Lambdas mapped to workflows"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
