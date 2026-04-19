#!/usr/bin/env python3
"""F50/AC-10 — Pre-merge guard for required_transition_type on component entries.

Runs two checks:

1. **Seed manifest audit (always on).** Imports ``KNOWN_COMPONENTS`` from
   ``tools/seed-component-registry.py`` and fails the process with exit code
   1 if any entry is missing ``required_transition_type`` or carries an
   invalid enum value.

2. **Live registry probe (optional, gated by env var).** When
   ``VERIFY_COMPONENT_REGISTRY_LIVE=1`` is set, the script also queries the
   coordination API (``COORDINATION_API_BASE`` + internal API key) and fails
   if any live component row is missing ``required_transition_type``.

Usage:
    # Default — audits the seed manifest only (used in PR CI).
    python3 tools/verify_component_required_transition_type.py

    # Include live registry probe (run with Cognito/assistant creds).
    VERIFY_COMPONENT_REGISTRY_LIVE=1 \\
        ENCELADUS_COORDINATION_INTERNAL_API_KEY=<key> \\
        python3 tools/verify_component_required_transition_type.py

Exit codes:
    0 — all components pass
    1 — one or more components missing or invalid (details on stderr)
    2 — configuration error (e.g. seed import failed, API unreachable
        while live probe requested)

Related: ENC-TSK-F50, ENC-ISS-270, DOC-240A67973B13 (governance review).
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

_VALID_ENUM_VALUES = {
    "github_pr_deploy",
    "lambda_deploy",
    "web_deploy",
    "code_only",
    "no_code",
}


def _load_seed_components() -> list[dict[str, Any]]:
    """Import KNOWN_COMPONENTS from the seed script without executing its CLI."""
    seed_path = Path(__file__).resolve().parent / "seed-component-registry.py"
    if not seed_path.exists():
        print(
            f"FAIL(config): seed script not found at {seed_path}", file=sys.stderr
        )
        sys.exit(2)
    namespace: dict[str, Any] = {"__name__": "__not_main__"}
    try:
        exec(compile(seed_path.read_text(), str(seed_path), "exec"), namespace)
    except Exception as exc:
        print(
            f"FAIL(config): could not import seed script: {exc}", file=sys.stderr
        )
        sys.exit(2)
    components = namespace.get("KNOWN_COMPONENTS")
    if not isinstance(components, list):
        print(
            "FAIL(config): KNOWN_COMPONENTS not a list in seed script",
            file=sys.stderr,
        )
        sys.exit(2)
    return components


def _audit_seed(components: list[dict[str, Any]]) -> list[str]:
    """Return a list of human-readable failure reasons for the seed manifest."""
    failures: list[str] = []
    for comp in components:
        cid = comp.get("component_id") or "<unknown>"
        value = comp.get("required_transition_type")
        if not value:
            failures.append(
                f"  - {cid}: missing 'required_transition_type' "
                "(F50/AC-9 — add the field to this entry, matched to its "
                "governance intent per DOC-240A67973B13)."
            )
            continue
        if value not in _VALID_ENUM_VALUES:
            failures.append(
                f"  - {cid}: invalid 'required_transition_type'={value!r} "
                f"(must be one of {sorted(_VALID_ENUM_VALUES)})."
            )
    return failures


def _live_probe(
    base_url: str, api_key: str, timeout_s: float = 10.0
) -> list[str]:
    """Optional live registry probe.

    Returns a list of failure reasons; empty list == pass. Returns a
    ``[CONFIG_ERROR …]`` single-element list when the API is unreachable so
    the caller can distinguish transport errors from missing-field errors.
    """
    url = f"{base_url.rstrip('/')}/components"
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
        return [
            f"CONFIG_ERROR: coordination API returned HTTP {exc.code} while "
            f"probing live component registry: {exc.reason}"
        ]
    except Exception as exc:  # network, DNS, timeout, JSON
        return [f"CONFIG_ERROR: live probe failed: {exc}"]

    items = body.get("components") or []
    if not isinstance(items, list):
        return ["CONFIG_ERROR: API response missing 'components' array"]

    failures: list[str] = []
    for item in items:
        cid = item.get("component_id") or "<unknown>"
        value = item.get("required_transition_type")
        if not value:
            failures.append(
                f"  - {cid}: live registry row missing 'required_transition_type' "
                "(run the AC-2 backfill handoff under io-dev-admin)."
            )
            continue
        if value not in _VALID_ENUM_VALUES:
            failures.append(
                f"  - {cid}: live registry row has invalid "
                f"'required_transition_type'={value!r}."
            )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Enceladus component registry required_transition_type pre-merge guard "
            "(ENC-TSK-F50 / ENC-ISS-270)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--live-probe",
        action="store_true",
        help=(
            "Probe the live coordination API in addition to auditing the seed "
            "manifest. Overrides VERIFY_COMPONENT_REGISTRY_LIVE. Requires "
            "COORDINATION_API_BASE and ENCELADUS_COORDINATION_INTERNAL_API_KEY."
        ),
    )
    args = parser.parse_args()

    components = _load_seed_components()
    print(f"Auditing {len(components)} seed manifest entries for "
          "required_transition_type…")
    failures = _audit_seed(components)
    if failures:
        print("\nFAIL: seed manifest audit", file=sys.stderr)
        for line in failures:
            print(line, file=sys.stderr)
        print(
            "\nRemediation: add 'required_transition_type' to each entry with "
            "the deliberate governance value per DOC-240A67973B13. See "
            "ENC-TSK-F50 for the full remediation plan.",
            file=sys.stderr,
        )
        return 1

    print("PASS: every seed manifest entry declares required_transition_type.")

    do_live = args.live_probe or os.environ.get(
        "VERIFY_COMPONENT_REGISTRY_LIVE"
    ) in {"1", "true", "yes"}
    if not do_live:
        print(
            "(Live registry probe skipped. Set VERIFY_COMPONENT_REGISTRY_LIVE=1 "
            "to enable.)"
        )
        return 0

    base_url = (
        os.environ.get("COORDINATION_API_BASE")
        or "https://jreese.net/api/v1/coordination"
    )
    api_key = os.environ.get(
        "ENCELADUS_COORDINATION_INTERNAL_API_KEY"
    ) or os.environ.get("COORDINATION_INTERNAL_API_KEY")
    if not api_key:
        print(
            "FAIL(config): live probe requested but no internal API key in env "
            "(ENCELADUS_COORDINATION_INTERNAL_API_KEY or "
            "COORDINATION_INTERNAL_API_KEY).",
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
        print("\nFAIL: live registry audit", file=sys.stderr)
        for line in live_failures:
            print(line, file=sys.stderr)
        print(
            "\nRemediation: run the F50 AC-2 backfill handoff under io-dev-admin "
            "to populate required_transition_type on every live row.",
            file=sys.stderr,
        )
        return 1
    print("PASS: every live registry row has required_transition_type.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
