#!/usr/bin/env python3
"""Backfill the five ENC-TSK-E68 hardening fields onto active enceladus-project
component_registry records.

ENC-TSK-L05 AC-1 (B63 Ph2 H-BACKFILL). Reads the researched values from
``tools/seed-component-registry.py``'s ``KNOWN_COMPONENTS`` (the single source
of truth this backfill keeps in sync with) and PATCHes each active
enceladus-project component's live registry row via the coordination API's
``PATCH /api/v1/coordination/components/{componentId}`` route, which already
recognizes required_iam_actions / required_env_secrets / required_apigw_routes
/ required_cfn_resources / required_lambda_env_vars as
``_COMPONENT_CAPABILITY_FIELDS`` (backend/lambda/coordination_api/
lambda_function.py:8751-8756) — no Cognito/assistant-key gate applies to these
fields (unlike transition_type/required_transition_type), so a plain internal
API key is sufficient auth.

This mirrors tools/backfill_component_lifecycle.py's CLI shape (--env {prod|
gamma}, --dry-run, before/after classification + summary logging) but writes
via the governed HTTP API (coordination_api Lambda's own IAM role) rather than
direct boto3 DynamoDB UpdateItem, because the calling agent identity
(enceladus-agent-cli) carries an explicit IAM deny on dynamodb:UpdateItem /
PutItem against component-registry* tables (ENC-TSK-564) — confirmed live via
a real UpdateItem attempt during ENC-TSK-L05 AC-1 research, which returned
AccessDeniedException. The HTTP path goes through the coordination_api
Lambda's own execution role instead, which is why seed-component-registry.py
itself already uses this same HTTP-based approach rather than boto3.

Usage:
    # Dry run — prints planned PATCH bodies, makes no network calls.
    python3 tools/backfill_component_hardening_fields.py --env gamma --dry-run

    # Real run against gamma (requires COORDINATION_INTERNAL_API_KEY or
    # ENCELADUS_COORDINATION_INTERNAL_API_KEY in the environment — this key is
    # NOT available to standard enceladus-agent-cli sessions; it must be
    # supplied by a session with access to it, e.g. via the coordination_api
    # Lambda's own config or an authorized CI context).
    ENCELADUS_COORDINATION_INTERNAL_API_KEY=<key> \\
        python3 tools/backfill_component_hardening_fields.py --env gamma

Scope: gamma only. This script intentionally has no prod code path — prod
component-registry metadata is out of scope for ENC-TSK-L05 (per the task's
standing gamma-lane directive); running against prod would require adding
--env prod deliberately and is NOT wired up here on purpose.

Related: ENC-TSK-L05, ENC-TSK-E68, ENC-PLN-031 Phase 3, ENC-TSK-E69
(deploy_capability_auditor, the downstream consumer of these fields).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Tuple

logger = logging.getLogger("backfill_component_hardening_fields")

_HARDENING_FIELDS = (
    "required_iam_actions",
    "required_env_secrets",
    "required_apigw_routes",
    "required_cfn_resources",
    "required_lambda_env_vars",
)

# gamma-only by design (see module docstring). No prod entry — do not add one
# without a deliberate, separately-reviewed decision; ENC-TSK-L05 scope is gamma.
_ENV_TO_BASE_URL = {
    "gamma": "https://jreese.net/api/v1/coordination",
}


def _load_seed_components() -> List[Dict[str, Any]]:
    seed_path = Path(__file__).resolve().parent / "seed-component-registry.py"
    namespace: Dict[str, Any] = {"__name__": "__not_main__"}
    exec(compile(seed_path.read_text(), str(seed_path), "exec"), namespace)
    components = namespace.get("KNOWN_COMPONENTS")
    if not isinstance(components, list):
        raise RuntimeError("KNOWN_COMPONENTS not found or not a list in seed script")
    return components


def _in_scope(comp: Dict[str, Any]) -> bool:
    """ENC-TSK-L05 AC-1 scope: active components in the enceladus project."""
    return comp.get("project_id") == "enceladus" and comp.get("status") == "active"


def _api_request(
    base_url: str, api_key: str, method: str, path: str, payload: Dict[str, Any] | None = None
) -> Tuple[int, Dict[str, Any]]:
    url = f"{base_url.rstrip('/')}{path}"
    body = json.dumps(payload).encode() if payload is not None else None
    headers = {
        "Content-Type": "application/json",
        "X-Coordination-Internal-Key": api_key,
    }
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            err_body = json.loads(raw)
        except Exception:
            err_body = {"raw": raw.decode(errors="replace")}
        return exc.code, err_body


def _get_live_component(base_url: str, api_key: str, component_id: str) -> Tuple[int, Dict[str, Any]]:
    return _api_request(base_url, api_key, "GET", f"/components/{component_id}")


def _needs_backfill(live_row: Dict[str, Any]) -> List[str]:
    """Return the subset of the five hardening fields missing on the live row."""
    return [f for f in _HARDENING_FIELDS if f not in live_row]


def _patch_component(
    base_url: str, api_key: str, component_id: str, seed_comp: Dict[str, Any]
) -> Tuple[int, Dict[str, Any]]:
    payload = {f: seed_comp.get(f, []) for f in _HARDENING_FIELDS}
    return _api_request(base_url, api_key, "PATCH", f"/components/{component_id}", payload)


def run(env: str, dry_run: bool, api_key: str) -> int:
    base_url = _ENV_TO_BASE_URL[env]
    components = [c for c in _load_seed_components() if _in_scope(c)]
    logger.info("env=%s base_url=%s dry_run=%s in_scope_components=%d", env, base_url, dry_run, len(components))

    # Pre-state: classify against live registry.
    needs: List[str] = []
    already: List[str] = []
    unreachable: List[str] = []
    for comp in components:
        cid = comp["component_id"]
        status, live = _get_live_component(base_url, api_key, cid)
        if status == 404:
            unreachable.append(cid)
            logger.warning("[BEFORE] %s not found live (404) -- skipping", cid)
            continue
        if status != 200:
            unreachable.append(cid)
            logger.warning("[BEFORE] %s GET failed (%s) -- skipping", cid, status)
            continue
        live_row = live.get("component", live)
        missing = _needs_backfill(live_row)
        if missing:
            needs.append(cid)
        else:
            already.append(cid)

    logger.info(
        "[BEFORE] in_scope=%d needs_backfill=%d already_set=%d unreachable=%d",
        len(components), len(needs), len(already), len(unreachable),
    )

    if dry_run:
        for comp in components:
            cid = comp["component_id"]
            action = "PATCH" if cid in needs else ("SKIP (already set)" if cid in already else "SKIP (unreachable)")
            logger.info("[DRY-RUN] %s -> %s", cid, action)
            if cid in needs:
                payload = {f: comp.get(f, []) for f in _HARDENING_FIELDS}
                logger.info("[DRY-RUN]   payload=%s", json.dumps(payload, sort_keys=True))
        logger.info("[DRY-RUN] no writes performed")
        return 0

    # Apply.
    written = 0
    skipped = 0
    failed = 0
    for comp in components:
        cid = comp["component_id"]
        if cid not in needs:
            skipped += 1
            logger.info("[SKIP] %s already has all five hardening fields", cid)
            continue
        status, result = _patch_component(base_url, api_key, cid, comp)
        if status == 200:
            written += 1
            logger.info("[WRITE] %s hardening fields backfilled", cid)
        else:
            failed += 1
            logger.error("[FAIL] %s PATCH returned %s: %s", cid, status, result)

    # Post-state verification.
    after_needs: List[str] = []
    for comp in components:
        cid = comp["component_id"]
        status, live = _get_live_component(base_url, api_key, cid)
        if status != 200:
            continue
        live_row = live.get("component", live)
        if _needs_backfill(live_row):
            after_needs.append(cid)

    logger.info(
        "[SUMMARY] written=%d skipped=%d failed=%d expected_remaining=0 actual_remaining=%d",
        written, skipped, failed, len(after_needs),
    )
    if after_needs:
        logger.error("[SUMMARY] still missing hardening fields after backfill: %s", after_needs)

    return 0 if not after_needs and failed == 0 else 1


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Backfill ENC-TSK-E68 hardening fields onto live component-registry records (ENC-TSK-L05 AC-1)."
    )
    p.add_argument("--env", required=True, choices=sorted(_ENV_TO_BASE_URL.keys()),
                   help="Target environment. gamma only -- prod is intentionally not wired up (see module docstring).")
    p.add_argument("--dry-run", action="store_true", help="Classify + print planned PATCHes; no writes.")
    p.add_argument("--api-key", default=None, help="Coordination API internal key (overrides env var).")
    return p


def main(argv: List[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    args = _build_parser().parse_args(argv)

    api_key = (
        args.api_key
        or os.environ.get("ENCELADUS_COORDINATION_INTERNAL_API_KEY")
        or os.environ.get("COORDINATION_INTERNAL_API_KEY")
        or ""
    )
    if not api_key and not args.dry_run:
        print(
            "ERROR: --api-key or ENCELADUS_COORDINATION_INTERNAL_API_KEY/"
            "COORDINATION_INTERNAL_API_KEY env var is required for a real run. "
            "(This key is not provisioned to standard enceladus-agent-cli "
            "sessions -- see module docstring.)",
            file=sys.stderr,
        )
        return 2

    return run(args.env, args.dry_run, api_key)


if __name__ == "__main__":
    sys.exit(main())
