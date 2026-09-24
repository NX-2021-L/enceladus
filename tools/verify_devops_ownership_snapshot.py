#!/usr/bin/env python3
"""ENC-TSK-P15 / ENC-ISS-669: verify the devops Lambda ownership snapshot.

infrastructure/devops_lambda_ownership_snapshot.json is a committed,
pinned-commit + per-source-sha256 snapshot of NX-2021-L/devops's own
declared Lambda estate -- the reverse-direction analogue of how devops
already pins and hash-verifies the enceladus shared library (see
NX-2021-L/devops scripts/fetch_shared_library.py: pinned commit + per-module
sha256, stale digest = hard build failure, never a warning).

WHY THIS CANNOT JUST BE fetch_shared_library.py AGAIN. That script fetches
NX-2021-L/enceladus over HTTPS at build time because enceladus is public at
the pinned SHA. NX-2021-L/devops is NOT public, and enceladus CI carries no
token for it -- so this tool cannot re-fetch devops at check time. What it
CAN do, and does, is two independent things every run:

  1. STRUCTURAL SELF-CONSISTENCY (always runs, needs no network and no
     credentials): the snapshot's own schema is sound -- every required key
     present, every sha256 the right shape, no duplicate function names,
     and critically devops-io-devops-mcp (the function ENC-ISS-669 found
     missing from functions.yaml) is actually present. A malformed or
     hand-edited-into-inconsistency snapshot fails here, loudly.

  2. LOCAL-SOURCE DIGEST VERIFICATION (best-effort, opt-in): when the
     environment variable DEVOPS_OWNERSHIP_LOCAL_SOURCE points at a local
     checkout of NX-2021-L/devops (mirroring fetch_shared_library.py's own
     SHARED_LIBRARY_LOCAL_SOURCE escape hatch for offline/air-gapped
     builds), every declared source file is re-hashed and compared against
     the pinned digest. A mismatch is a hard failure -- the pin no longer
     describes what devops actually contains, and that must never pass
     silently. When the variable is unset (the normal CI case today, since
     no devops checkout and no token are available there), this step is
     SKIPPED -- and the skip is printed, every run, as its own labelled
     line, never folded into a bare [SUCCESS]. A skip and a verified pass
     are different states; ENC-TSK-P15 AC-5 is exactly the rule that a
     skipped check must never look like a passed one.

Exit 0 = structural check passed, AND (local-source check passed OR was
          skipped because no local source was declared).
Exit 1 = a structural violation, or a local-source digest mismatch.
Exit 2 = the guard could not run (missing/malformed snapshot file).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT_PATH = REPO_ROOT / "infrastructure" / "devops_lambda_ownership_snapshot.json"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")

REQUIRED_TOP_KEYS = (
    "owning_repo",
    "pinned_commit",
    "pinned_at",
    "sources",
    "functions",
    "ownership_predicate",
)
REQUIRED_FUNCTION_KEYS = (
    "function_name",
    "declared_in",
    "runtime",
    "architecture",
    "deploy_channel",
)
REQUIRED_SOURCE_KEYS = ("sha256", "declares_functions", "reason")

# ENC-ISS-669's own acceptance test, restated as data: a snapshot that does
# NOT carry this name has reproduced the exact functions.yaml-only gap this
# file exists to close, no matter how clean everything else about it looks.
REQUIRED_FUNCTION_NAME = "devops-io-devops-mcp"


def log(message: str) -> None:
    print(f"[devops-ownership-snapshot] {message}")


def load_snapshot(path: Path = SNAPSHOT_PATH) -> dict:
    if not path.is_file():
        print(f"::error::missing devops ownership snapshot: {path}")
        sys.exit(2)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"::error::{path} is not valid JSON: {exc}")
        sys.exit(2)


def validate_structure(snapshot: dict) -> list[str]:
    """Schema and internal-consistency checks -- no network, no credentials.

    Runs every time this tool runs, in every environment, including plain
    CI with no AWS access and no devops checkout.
    """
    errors: list[str] = []

    for key in REQUIRED_TOP_KEYS:
        if not snapshot.get(key):
            errors.append(f"missing or empty required top-level key: {key!r}")

    if errors:
        return errors  # can't usefully check deeper without the basics

    if not _COMMIT_RE.match(str(snapshot["pinned_commit"])):
        errors.append(
            f"pinned_commit {snapshot['pinned_commit']!r} is not a 40-hex-char "
            f"immutable commit SHA -- a branch name or short SHA is not pinned."
        )

    if snapshot.get("owning_repo") != "NX-2021-L/devops":
        errors.append(
            f"owning_repo {snapshot.get('owning_repo')!r} != 'NX-2021-L/devops' "
            f"-- this snapshot's entire purpose is to record devops ownership."
        )

    sources = snapshot.get("sources") or {}
    if not isinstance(sources, dict) or not sources:
        errors.append("sources must be a non-empty object")
    else:
        for rel_path, entry in sources.items():
            if not isinstance(entry, dict):
                errors.append(f"sources[{rel_path!r}] must be an object")
                continue
            for key in REQUIRED_SOURCE_KEYS:
                if key not in entry:
                    errors.append(f"sources[{rel_path!r}] missing required key {key!r}")
            digest = entry.get("sha256")
            if digest is not None and not _SHA256_RE.match(str(digest)):
                errors.append(
                    f"sources[{rel_path!r}].sha256 {digest!r} is not a 64-hex-char "
                    f"sha256 digest."
                )

    functions = snapshot.get("functions") or []
    if not isinstance(functions, list) or not functions:
        errors.append("functions must be a non-empty array")
    else:
        seen_names: set[str] = set()
        for entry in functions:
            if not isinstance(entry, dict):
                errors.append(f"functions[] entry is not an object: {entry!r}")
                continue
            for key in REQUIRED_FUNCTION_KEYS:
                if not entry.get(key):
                    errors.append(
                        f"functions[] entry {entry.get('function_name', '?')!r} "
                        f"missing required key {key!r}"
                    )
            name = entry.get("function_name")
            if name in seen_names:
                errors.append(f"functions[] lists {name!r} more than once")
            if name:
                seen_names.add(name)

        # ENC-ISS-669's own acceptance test: the exact gap that made a
        # functions.yaml-only predicate fail must be represented here, or
        # this snapshot has quietly regressed to the thing it replaced.
        if REQUIRED_FUNCTION_NAME not in seen_names:
            errors.append(
                f"functions[] does not list {REQUIRED_FUNCTION_NAME!r} -- this is "
                f"the exact live devops function that appears nowhere in "
                f"functions.yaml (ENC-ISS-669). A snapshot missing it has "
                f"regressed to the functions.yaml-only predicate this file "
                f"exists to replace."
            )

        # Every declared function must trace to at least one source entry's
        # declares_functions list -- otherwise "declared_in" prose is the
        # only provenance, which is exactly the un-provenanced hand-copy
        # ENC-TSK-P15's brief forbids.
        declared_anywhere: set[str] = set()
        for entry in sources.values():
            if isinstance(entry, dict):
                declared_anywhere.update(entry.get("declares_functions") or [])
        for entry in functions:
            name = entry.get("function_name") if isinstance(entry, dict) else None
            if name and name not in declared_anywhere:
                errors.append(
                    f"{name!r} is listed in functions[] but no entry under "
                    f"sources{{}}.declares_functions names it -- every function "
                    f"here must trace to a hashed source file, not just prose."
                )

    return errors


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def verify_local_source(snapshot: dict, local_root: str) -> tuple[list[str], list[str]]:
    """Re-hash every declared source file against a local devops checkout.

    Returns (errors, verified_paths). Mirrors fetch_shared_library.py's own
    digest-mismatch-is-a-refusal discipline: this is the ONLY path in this
    tool that can prove the pin still matches devops's actual content, so a
    mismatch here is never downgraded to a warning.
    """
    errors: list[str] = []
    verified: list[str] = []
    root = Path(local_root)
    for rel_path, entry in (snapshot.get("sources") or {}).items():
        if not isinstance(entry, dict):
            continue
        expected = entry.get("sha256")
        local_file = root / rel_path
        if not local_file.is_file():
            errors.append(
                f"DEVOPS_OWNERSHIP_LOCAL_SOURCE is set but {local_file} does not "
                f"exist -- cannot verify the pin for {rel_path!r}."
            )
            continue
        actual = _sha256(local_file.read_bytes())
        if actual != expected:
            errors.append(
                f"DIGEST MISMATCH for {rel_path}\n"
                f"  expected {expected}\n"
                f"  actual   {actual}\n"
                f"The pinned snapshot no longer matches the local devops checkout's "
                f"content. Either the pin was edited without updating the digest, "
                f"the local checkout is not at the pinned commit "
                f"({snapshot.get('pinned_commit')}), or the devops-side content "
                f"changed since the pin was recorded. All three are refusals, not "
                f"warnings."
            )
            continue
        verified.append(rel_path)
        log(f"verified sha256 {actual}  {rel_path}")
    return errors, verified


def main() -> int:
    snapshot = load_snapshot()

    errors = validate_structure(snapshot)
    if errors:
        print("[ERROR] devops ownership snapshot structural validation FAILED:")
        for err in errors:
            print(f"  {err}")
        return 1

    function_names = sorted(f["function_name"] for f in snapshot["functions"])
    print(
        f"[INFO] Structural validation passed: {len(function_names)} devops-owned "
        f"function(s) declared, pinned at commit {snapshot['pinned_commit']} "
        f"({snapshot['pinned_at']}): {', '.join(function_names)}"
    )

    local_root = os.environ.get("DEVOPS_OWNERSHIP_LOCAL_SOURCE")
    if not local_root:
        # ENC-TSK-P15 AC-5: a skipped check must be VISIBLE as a skip, never
        # folded silently into an unqualified [SUCCESS]. This is the
        # expected state in CI today -- no devops checkout, no token -- and
        # saying so every run is the point, not a defect to hide.
        print(
            "[SKIPPED] Local-source digest verification: DEVOPS_OWNERSHIP_LOCAL_SOURCE "
            "is not set -- no local NX-2021-L/devops checkout to re-hash against. "
            "Structural validation above is the only check that ran. This is the "
            "expected state in ordinary CI (devops is a private repo and no fetch "
            "token is wired in); it is not evidence the pin is still fresh."
        )
        print(
            "[SUCCESS] devops ownership snapshot: structurally valid "
            "(local-source digest verification SKIPPED, not performed)."
        )
        return 0

    local_errors, verified = verify_local_source(snapshot, local_root)
    if local_errors:
        print("[ERROR] devops ownership snapshot local-source verification FAILED:")
        for err in local_errors:
            print(f"  {err}")
        return 1

    print(
        f"[SUCCESS] devops ownership snapshot: structurally valid AND "
        f"{len(verified)} source file(s) digest-verified against "
        f"DEVOPS_OWNERSHIP_LOCAL_SOURCE={local_root}."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
