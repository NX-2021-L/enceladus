#!/usr/bin/env python3
"""elr_list.py -- ELR tracker list (ENC-TSK-Q16, plan ENC-PLN-093 objective
O4, U2). Base route (--project/--type/--status/--page-size) plus the
bounded server-side census walk (--census, U1, mode=census): the full
census payload is written verbatim to a local side file under
--lists-dir; only a compact digest ({count, exhausted, count_truncated,
pages, as_of, by_type}) is ever printed.

The explicit single-page read (--page), the bounded N-page loop
(--pages), and the tracker_capabilities.census preflight land in later
commits on this same file.

Usage:
    python3 tools/elr/elr_list.py --project enceladus
    python3 tools/elr/elr_list.py --project enceladus --type task --status open --census
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional

# Allow running this file directly (python3 tools/elr/elr_list.py) without
# requiring tools/elr to already be on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from elr_lib import profiles as elr_profiles  # noqa: E402
from elr_lib.config import get_profile  # noqa: E402
from elr_lib.digest import build_digest  # noqa: E402
from elr_lib.transport import InternalClient, classify_internal_posture  # noqa: E402

# The reserved tracker-sentinel project segment (mirrors
# elr_batch_get.PROJECT_SENTINEL). --project is always a real, single
# project id here -- "_" as a project value would collide with the
# sentinel route's own reserved meaning, so it is rejected at the
# argparse layer, before any network call is attempted.
RESERVED_PROJECT_SENTINEL = "_"

MIN_PAGE_SIZE = 1
MAX_PAGE_SIZE = 200
DEFAULT_PAGE_SIZE = 100

DEFAULT_LISTS_DIR = "~/.enceladus/lists"


# --- argparse value types ----------------------------------------------------


def _project_arg(value: str) -> str:
    if value == RESERVED_PROJECT_SENTINEL:
        raise argparse.ArgumentTypeError(
            f"--project {RESERVED_PROJECT_SENTINEL!r} is not a valid project id "
            "(it is the reserved tracker sentinel route segment, ENC-TSK-Q10)"
        )
    return value


def _page_size_arg(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"--page-size must be an integer, got {value!r}") from exc
    if not (MIN_PAGE_SIZE <= parsed <= MAX_PAGE_SIZE):
        raise argparse.ArgumentTypeError(
            f"--page-size must be between {MIN_PAGE_SIZE} and {MAX_PAGE_SIZE}, got {parsed}"
        )
    return parsed


def build_parser() -> argparse.ArgumentParser:
    # ALL ELR CLIs must set allow_abbrev=False so partial/ambiguous flags
    # are never silently accepted.
    parser = argparse.ArgumentParser(
        prog="elr_list",
        description="ELR tracker list: base route over --project/--type/--status/--page-size.",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--project",
        required=True,
        type=_project_arg,
        help="Tracker project id, e.g. 'enceladus'. The sentinel value '_' is rejected.",
    )
    parser.add_argument(
        "--type",
        default=None,
        help="Optional record_type filter (task/issue/feature/plan/lesson/escalation).",
    )
    parser.add_argument(
        "--status",
        default=None,
        help="Optional status filter.",
    )
    parser.add_argument(
        "--page-size",
        type=_page_size_arg,
        default=DEFAULT_PAGE_SIZE,
        help=f"Rows per raw/census page (default: {DEFAULT_PAGE_SIZE}, max: {MAX_PAGE_SIZE}).",
    )
    parser.add_argument(
        "--census",
        action="store_true",
        default=False,
        help="Run one bounded server-side census walk (mode=census) and write its payload to disk.",
    )
    parser.add_argument(
        "--lists-dir",
        default=DEFAULT_LISTS_DIR,
        help=f"Directory for census/page side files (default: {DEFAULT_LISTS_DIR}).",
    )
    parser.add_argument(
        "--profile",
        default=elr_profiles.PROFILE_PROD,
        choices=list(elr_profiles.VALID_ENVIRONMENT_PROFILES),
        help=(
            "ELR ENVIRONMENT profile (ENC-TSK-P77) -- which deployed Enceladus "
            "environment to read from (default: prod; ENCELADUS_PROFILE env var "
            "also selects this). Always uses the 'internal' transport."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=15,
        help="Per-request timeout in seconds (default: 15).",
    )
    return parser


# --- side-file naming (--census) ------------------------------------------


def _slug_or_all(value: Optional[str]) -> str:
    return value if value else "all"


def census_file_path(
    lists_dir: str, project: str, type_: Optional[str], status: Optional[str], started_at: str
) -> Path:
    name = f"{project}_{_slug_or_all(type_)}_{_slug_or_all(status)}_{started_at}.census.json"
    return Path(lists_dir).expanduser() / name


def census_glob(lists_dir: str, project: str, type_: Optional[str], status: Optional[str]) -> List[Path]:
    pattern = f"{project}_{_slug_or_all(type_)}_{_slug_or_all(status)}_*.census.json"
    return sorted(Path(lists_dir).expanduser().glob(pattern))


def _write_json_file(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


# --- --census ------------------------------------------------------------------


def run_census(client: InternalClient, key_sent: bool, args: argparse.Namespace) -> Dict[str, Any]:
    query: Dict[str, Any] = {
        "mode": "census",
        "type": args.type,
        "status": args.status,
        "page_size": args.page_size,
    }
    encoded_project = urllib.parse.quote(str(args.project), safe="")
    status, body = client.request("GET", "tracker", f"/{encoded_project}", query=query)

    posture, anomalies = classify_internal_posture(key_sent=key_sent, status_code=status)
    anomalies = list(anomalies)
    ok = 200 <= status < 300 and isinstance(body, dict)
    if isinstance(body, dict) and body.get("error"):
        anomalies.append(f"response_error: {body['error']}")
        ok = False

    count = exhausted = count_truncated = pages = as_of = by_type = None
    if ok:
        count = body.get("count")
        exhausted = body.get("exhausted")
        count_truncated = body.get("count_truncated")
        pages = body.get("pages")
        as_of = body.get("as_of")
        by_type = body.get("by_type")

        started_at = None
        if isinstance(as_of, dict):
            started_at = as_of.get("started_at")
        out_path = census_file_path(
            args.lists_dir, args.project, args.type, args.status, started_at or "unknown-start"
        )
        _write_json_file(out_path, body)

    return build_digest(
        "elr_list.census",
        ok,
        status,
        identity_posture=posture,
        anomalies=anomalies,
        count=count,
        exhausted=exhausted,
        count_truncated=count_truncated,
        pages=pages,
        as_of=as_of,
        by_type=by_type,
    )


# --- base route ----------------------------------------------------------------


def run_plain_list(client: InternalClient, key_sent: bool, args: argparse.Namespace) -> Dict[str, Any]:
    """One plain GET {tracker_base}/{project} -- query params only, no
    mode=census, no cursor. Used when no mode flag is given; --page/
    --pages (ENC-TSK-Q16-0C) add the remaining entry points.
    """
    query: Dict[str, Any] = {"type": args.type, "status": args.status, "page_size": args.page_size}
    encoded_project = urllib.parse.quote(str(args.project), safe="")
    status, body = client.request("GET", "tracker", f"/{encoded_project}", query=query)

    posture, anomalies = classify_internal_posture(key_sent=key_sent, status_code=status)
    anomalies = list(anomalies)
    ok = 200 <= status < 300 and isinstance(body, dict)
    if isinstance(body, dict) and body.get("error"):
        anomalies.append(f"response_error: {body['error']}")
        ok = False

    counts: Optional[Dict[str, Any]] = None
    if ok:
        records = body.get("records")
        counts = {"records": len(records) if isinstance(records, list) else 0}

    return build_digest(
        "elr_list.plain",
        ok,
        status,
        identity_posture=posture,
        anomalies=anomalies,
        counts=counts,
    )


# --- CLI -----------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    config = get_profile("internal", environment_profile_name=args.profile)
    client = InternalClient(config, timeout=args.timeout)
    key_sent = bool(config.key_for("tracker"))

    if args.census:
        digest = run_census(client, key_sent, args)
    else:
        digest = run_plain_list(client, key_sent, args)

    print(json.dumps(digest, sort_keys=True))
    return 0 if digest.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
