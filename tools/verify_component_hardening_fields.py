#!/usr/bin/env python3
"""ENC-TSK-L05 AC-1/AC2-6 — Pre-merge / spot-check guard for the five
ENC-TSK-E68 hardening fields AND the four v3 identity fields on active
enceladus-project component_registry entries.

Runs three checks:

1. **Seed manifest E68 audit (always on).** Imports ``KNOWN_COMPONENTS`` from
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

2. **Seed manifest v3 identity audit (always on, ENC-TSK-L05 AC2-6).** For
   every active enceladus-project component, asserts the four v3 identity
   fields — component_address, component_repo_dir, component_address_class,
   component_class — are present and non-empty strings, that
   component_address_class is one of the allowed address classes, that
   component_class is one of {physical, external, meta}, and that
   required_transition_type is one of the v3 values {code, external_deploy,
   documentation}. Also runs a MECE check: no two active components may share
   the same component_address, and no component_repo_dir may be a path prefix
   of another (``meta:`` sentinels are exempt from the prefix check but must
   still be unique). Fails with exit code 1 listing offenders.

3. **Live registry probe (optional, gated by env var).** When
   ``VERIFY_COMPONENT_HARDENING_LIVE=1`` is set, also queries the
   coordination API and fails if any live enceladus-project component row is
   missing one of the five E68 fields.

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

# ENC-TSK-L05 AC2-6 — v3 component identity fields.
_V3_IDENTITY_FIELDS = (
    "component_address",
    "component_repo_dir",
    "component_address_class",
    "component_class",
)

_VALID_ADDRESS_CLASSES = {
    "aws_arn",
    "https_url",
    "cloudflare_resource",
    "neo4j_auradb",
    "external_manifest",
    "meta",
}

_VALID_COMPONENT_CLASSES = {"physical", "external", "meta"}

_VALID_REQUIRED_TRANSITION_TYPES = {"code", "external_deploy", "documentation"}

_META_SENTINEL_PREFIX = "meta:"


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


def _audit_v3_identity(components: list[dict[str, Any]]) -> tuple[list[str], int]:
    """ENC-TSK-L05 AC2-6 v3 identity audit.

    Returns (failure reasons, count of in-scope components audited). Checks
    per-component field validity plus the two MECE properties (unique
    component_address; component_repo_dir antichain / no-prefix-overlap among
    non-meta entries).
    """
    failures: list[str] = []
    in_scope = [c for c in components if _in_scope(c)]
    audited = len(in_scope)

    # Per-component field validity.
    for comp in in_scope:
        cid = comp.get("component_id") or "<unknown>"

        missing = [f for f in _V3_IDENTITY_FIELDS if f not in comp]
        if missing:
            failures.append(
                f"  - {cid}: missing v3 identity field(s) {missing} "
                "(ENC-TSK-L05 AC2-6 — every active enceladus component must "
                "declare component_address, component_repo_dir, "
                "component_address_class, and component_class)."
            )
            continue

        empty_or_nonstr = [
            f
            for f in _V3_IDENTITY_FIELDS
            if not isinstance(comp.get(f), str) or not comp.get(f).strip()
        ]
        if empty_or_nonstr:
            failures.append(
                f"  - {cid}: v3 identity field(s) {empty_or_nonstr} present but "
                "not a non-empty string."
            )
            continue

        addr_class = comp["component_address_class"]
        if addr_class not in _VALID_ADDRESS_CLASSES:
            failures.append(
                f"  - {cid}: component_address_class={addr_class!r} is not one of "
                f"{sorted(_VALID_ADDRESS_CLASSES)}."
            )

        comp_class = comp["component_class"]
        if comp_class not in _VALID_COMPONENT_CLASSES:
            failures.append(
                f"  - {cid}: component_class={comp_class!r} is not one of "
                f"{sorted(_VALID_COMPONENT_CLASSES)}."
            )

        rtt = comp.get("required_transition_type")
        if rtt not in _VALID_REQUIRED_TRANSITION_TYPES:
            failures.append(
                f"  - {cid}: required_transition_type={rtt!r} is not a v3 value "
                f"({sorted(_VALID_REQUIRED_TRANSITION_TYPES)})."
            )

    # MECE 1 — unique component_address across all active components.
    addr_owners: dict[str, list[str]] = {}
    for comp in in_scope:
        addr = comp.get("component_address")
        if not isinstance(addr, str) or not addr.strip():
            continue
        addr_owners.setdefault(addr, []).append(comp.get("component_id") or "<unknown>")
    for addr, owners in sorted(addr_owners.items()):
        if len(owners) > 1:
            failures.append(
                f"  - duplicate component_address {addr!r} shared by {owners} "
                "(ENC-TSK-L05 AC2-6 MECE — component_address must be unique)."
            )

    # MECE 2 — component_repo_dir antichain: no dir may be a path prefix of
    # another. meta: sentinels are exempt from the prefix check but must still
    # be unique.
    repo_owners: dict[str, list[str]] = {}
    for comp in in_scope:
        rd = comp.get("component_repo_dir")
        if not isinstance(rd, str) or not rd.strip():
            continue
        repo_owners.setdefault(rd, []).append(comp.get("component_id") or "<unknown>")
    for rd, owners in sorted(repo_owners.items()):
        if len(owners) > 1:
            failures.append(
                f"  - duplicate component_repo_dir {rd!r} shared by {owners} "
                "(ENC-TSK-L05 AC2-6 MECE — component_repo_dir must be unique)."
            )

    non_meta_dirs = [
        (comp.get("component_id") or "<unknown>", comp["component_repo_dir"])
        for comp in in_scope
        if isinstance(comp.get("component_repo_dir"), str)
        and comp["component_repo_dir"].strip()
        and not comp["component_repo_dir"].startswith(_META_SENTINEL_PREFIX)
    ]
    for cid_a, dir_a in non_meta_dirs:
        for cid_b, dir_b in non_meta_dirs:
            if dir_a == dir_b and cid_a == cid_b:
                continue
            if dir_a == dir_b:
                continue  # duplicate case handled above
            # dir_b is a proper path-prefix of dir_a.
            if (dir_a + "/").startswith(dir_b + "/"):
                failures.append(
                    f"  - component_repo_dir {dir_a!r} ({cid_a}) is nested under "
                    f"{dir_b!r} ({cid_b}) — repo dirs must form an antichain "
                    "(ENC-TSK-L05 AC2-6 MECE, no-prefix-overlap)."
                )

    # De-dup failure lines (the antichain double-loop can emit a pair twice
    # from opposite directions only if both are prefixes, which is impossible;
    # this is defensive).
    deduped: list[str] = []
    seen: set[str] = set()
    for line in failures:
        if line not in seen:
            seen.add(line)
            deduped.append(line)
    return deduped, audited


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

    v3_failures, v3_audited = _audit_v3_identity(components)
    print(f"Auditing {v3_audited} active enceladus-project seed manifest entries "
          "for the four v3 identity fields + MECE properties "
          "(ENC-TSK-L05 AC2-6)…")
    if v3_failures:
        print("\nFAIL: seed manifest v3 identity audit", file=sys.stderr)
        for line in v3_failures:
            print(line, file=sys.stderr)
        return 1

    print("PASS: every active enceladus-project seed manifest entry declares "
          "valid v3 identity fields (component_address, component_repo_dir, "
          "component_address_class, component_class) with a v3 "
          "required_transition_type, and the MECE properties hold "
          "(unique component_address; component_repo_dir antichain).")

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
