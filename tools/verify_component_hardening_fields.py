#!/usr/bin/env python3
"""ENC-TSK-L05 AC-1 — Pre-merge / spot-check guard for the five ENC-TSK-E68
hardening fields on active enceladus-project component_registry entries.

Runs two checks:

1. **Seed manifest audit (always on).** Imports ``KNOWN_COMPONENTS`` from
   ``tools/seed-component-registry.py`` and fails with exit code 1 if any
   active enceladus-project entry is missing one of the five fields:
   required_iam_actions, required_env_secrets, required_apigw_routes,
   required_cfn_resources, required_lambda_env_vars. Per ENC-TSK-E68, each
   field's *presence* (as a list, empty or not) is the bar — an empty list is
   a valid, deliberate value (see comments in the seed file for the
   per-component rationale on which fields are legitimately empty and why).
   Only non-enceladus-project components and non-active components are
   skipped, mirroring the AC-1 scope (this task never touched other
   projects' entries).

2. **Live registry probe (optional, gated by env var).** When
   ``VERIFY_COMPONENT_HARDENING_LIVE=1`` is set, also queries the
   coordination API and fails if any live enceladus-project component row is
   missing one of the five fields.

Usage:
    # Default — audits the seed manifest only (used in PR CI / spot checks).
    python3 tools/verify_component_hardening_fields.py

    # Include live registry probe (run with Cognito/assistant creds).
    VERIFY_COMPONENT_HARDENING_LIVE=1 \\
        ENCELADUS_COORDINATION_INTERNAL_API_KEY=<key> \\
        python3 tools/verify_component_hardening_fields.py

Exit codes:
    0 — all considered components pass
    1 — one or more components missing a required field
    2 — configuration error (e.g. seed import failed, API unreachable while
        live probe requested)

Related: ENC-TSK-L05 (B63 Ph2 H-BACKFILL AC-1), ENC-TSK-E68, ENC-PLN-031
Phase 3, ENC-TSK-E69 (deploy_capability_auditor, the downstream consumer).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

_HARDENING_FIELDS = (
    "required_iam_actions",
    "required_env_secrets",
    "required_apigw_routes",
    "required_cfn_resources",
    "required_lambda_env_vars",
)


def _load_seed_components() -> list[dict[str, Any]]:
    """Import KNOWN_COMPONENTS from the seed script without executing its CLI."""
    seed_path = Path(__file__).resolve().parent / "seed-component-registry.py"
    if not seed_path.exists():
        print(f"FAIL(config): seed script not found at {seed_path}", file=sys.stderr)
        sys.exit(2)
    namespace: dict[str, Any] = {"__name__": "__not_main__"}
    try:
        exec(compile(seed_path.read_text(), str(seed_path), "exec"), namespace)
    except Exception as exc:
        print(f"FAIL(config): could not import seed script: {exc}", file=sys.stderr)
        sys.exit(2)
    components = namespace.get("KNOWN_COMPONENTS")
    if not isinstance(components, list):
        print("FAIL(config): KNOWN_COMPONENTS not a list in seed script", file=sys.stderr)
        sys.exit(2)
    return components


def _in_scope(comp: dict[str, Any]) -> bool:
    """ENC-TSK-L05 AC-1 scope: active components in the enceladus project."""
    return comp.get("project_id") == "enceladus" and comp.get("status") == "active"


def _audit_seed(components: list[dict[str, Any]]) -> tuple[list[str], int]:
    """Return (failure reasons, count of in-scope components audited)."""
    failures: list[str] = []
    audited = 0
    for comp in components:
        if not _in_scope(comp):
            continue
        audited += 1
        cid = comp.get("component_id") or "<unknown>"
        missing_fields = [f for f in _HARDENING_FIELDS if f not in comp]
        if missing_fields:
            failures.append(
                f"  - {cid}: missing field(s) {missing_fields} "
                "(ENC-TSK-L05 AC-1 — every active enceladus component must "
                "declare all five ENC-TSK-E68 hardening fields, even if the "
                "considered value is an empty list)."
            )
            continue
        non_list = [f for f in _HARDENING_FIELDS if not isinstance(comp.get(f), list)]
        if non_list:
            failures.append(f"  - {cid}: field(s) {non_list} present but not a list.")
    return failures, audited


def _live_probe(base_url: str, api_key: str, timeout_s: float = 10.0) -> list[str]:
    url = f"{base_url.rstrip('/')}/components?project_id=enceladus"
    req = urllib.request.Request(
        url,
        method="GET",
        headers={
            "Content-Type": "application/json",
            "X-Coordination-Internal-Key": api_key,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            body = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return [f"CONFIG_ERROR: coordination API returned HTTP {exc.code}: {exc.reason}"]
    except Exception as exc:
        return [f"CONFIG_ERROR: live probe failed: {exc}"]

    items = body.get("components") or body.get("items") or []
    if not isinstance(items, list):
        return ["CONFIG_ERROR: API response missing 'components' array"]

    failures: list[str] = []
    for item in items:
        if not _in_scope(item):
            continue
        cid = item.get("component_id") or "<unknown>"
        missing_fields = [f for f in _HARDENING_FIELDS if f not in item]
        if missing_fields:
            failures.append(
                f"  - {cid}: live registry row missing field(s) {missing_fields} "
                "(run tools/backfill_component_hardening_fields.py)."
            )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Enceladus component registry hardening-fields guard "
            "(ENC-TSK-L05 AC-1 / ENC-TSK-E68)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--live-probe",
        action="store_true",
        help=(
            "Probe the live coordination API in addition to auditing the seed "
            "manifest. Overrides VERIFY_COMPONENT_HARDENING_LIVE. Requires "
            "COORDINATION_API_BASE and ENCELADUS_COORDINATION_INTERNAL_API_KEY."
        ),
    )
    args = parser.parse_args()

    components = _load_seed_components()
    failures, audited = _audit_seed(components)
    print(f"Auditing {audited} active enceladus-project seed manifest entries "
          "for the five ENC-TSK-E68 hardening fields…")
    if failures:
        print("\nFAIL: seed manifest audit", file=sys.stderr)
        for line in failures:
            print(line, file=sys.stderr)
        return 1

    print("PASS: every active enceladus-project seed manifest entry declares "
          "all five hardening fields (required_iam_actions, "
          "required_env_secrets, required_apigw_routes, "
          "required_cfn_resources, required_lambda_env_vars).")

    do_live = args.live_probe or os.environ.get("VERIFY_COMPONENT_HARDENING_LIVE") in {"1", "true", "yes"}
    if not do_live:
        print("(Live registry probe skipped. Set VERIFY_COMPONENT_HARDENING_LIVE=1 to enable.)")
        return 0

    base_url = os.environ.get("COORDINATION_API_BASE") or "https://jreese.net/api/v1/coordination"
    api_key = os.environ.get("ENCELADUS_COORDINATION_INTERNAL_API_KEY") or os.environ.get(
        "COORDINATION_INTERNAL_API_KEY"
    )
    if not api_key:
        print(
            "FAIL(config): live probe requested but no internal API key in env "
            "(ENCELADUS_COORDINATION_INTERNAL_API_KEY or COORDINATION_INTERNAL_API_KEY).",
            file=sys.stderr,
        )
        return 2

    print(f"Probing live registry at {base_url}…")
    live_failures = _live_probe(base_url, api_key)
    config_errors = [f for f in live_failures if f.startswith("CONFIG_ERROR")]
    if config_errors:
        for line in config_errors:
            print(f"FAIL(config): {line}", file=sys.stderr)
        return 2
    if live_failures:
        print("\nFAIL: live registry probe", file=sys.stderr)
        for line in live_failures:
            print(line, file=sys.stderr)
        return 1

    print("PASS: live registry rows all declare the five hardening fields.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
