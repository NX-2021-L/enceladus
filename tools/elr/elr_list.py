#!/usr/bin/env python3
"""elr_list.py -- ELR tracker list (ENC-TSK-Q16, plan ENC-PLN-093 objective
O4, U2). Base route (--project/--type/--status/--page-size), the bounded
server-side census walk (--census, U1, mode=census; full payload written
verbatim to a local side file, only a compact digest printed), an
explicit single raw-page read (--page CURSOR; writes one record id per
line in elr_batch_get.py's --ids-file format -- deliberately no --all),
and a bounded N-page loop over a prior census's page-boundary cursors
(--pages N, max 10).

Before ANY --census/--page/--pages request, this script reads
``tracker_capabilities.census`` off GET /api/v1/health (the same
payload the MCP ``connection_health`` tool reports, ENC-TSK-Q14-0E /
D9). A server that does not advertise census support gets zero list
requests -- ELR never falls back to client-side paging on a plane that
predates U1. See EXIT_CENSUS_UNSUPPORTED below.

Usage:
    python3 tools/elr/elr_list.py --project enceladus
    python3 tools/elr/elr_list.py --project enceladus --type task --status open --census
    python3 tools/elr/elr_list.py --project enceladus --page <cursor>
    python3 tools/elr/elr_list.py --project enceladus --type task --status open --pages 3
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Allow running this file directly (python3 tools/elr/elr_list.py) without
# requiring tools/elr to already be on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from elr_lib import profiles as elr_profiles  # noqa: E402
from elr_lib import tls as elr_tls  # noqa: E402
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

MIN_PAGES = 1
MAX_PAGES = 10

_CURSOR_HASH_LEN = 12

EXIT_CENSUS_UNSUPPORTED = 6
CENSUS_UNSUPPORTED_MESSAGE = "CENSUS_UNSUPPORTED: server lacks census mode; ELR never walks pages"


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


def _pages_arg(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"--pages must be an integer, got {value!r}") from exc
    if not (MIN_PAGES <= parsed <= MAX_PAGES):
        raise argparse.ArgumentTypeError(f"--pages must be between {MIN_PAGES} and {MAX_PAGES}, got {parsed}")
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
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--census",
        action="store_true",
        default=False,
        help="Run one bounded server-side census walk (mode=census) and write its payload to disk.",
    )
    mode.add_argument(
        "--page",
        default=None,
        metavar="CURSOR",
        help="Fetch exactly one raw page for this cursor (e.g. a cursor from a prior --census run).",
    )
    mode.add_argument(
        "--pages",
        type=_pages_arg,
        default=None,
        metavar="N",
        help=(
            f"Fetch the first N (max {MAX_PAGES}) page-boundary cursors from the most recent "
            "matching --census side file (same --project/--type/--status)."
        ),
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


# --- side-file naming (--page / --pages) ---------------------------------


def cursor_hash(cursor: Optional[str]) -> str:
    """Short, filesystem-safe id for a cursor value (empty/None cursor -- the
    start of the walk, e.g. census pages[0] -- hashes the empty string)."""
    return hashlib.sha256((cursor or "").encode("utf-8")).hexdigest()[:_CURSOR_HASH_LEN]


def page_ids_file_path(lists_dir: str, project: str, cursor: Optional[str]) -> Path:
    return Path(lists_dir).expanduser() / f"{project}_{cursor_hash(cursor)}.ids"


def pages_ids_file_path(lists_dir: str, project: str, type_: Optional[str], status: Optional[str], n: int) -> Path:
    return Path(lists_dir).expanduser() / f"{project}_{_slug_or_all(type_)}_{_slug_or_all(status)}_pages{n}.ids"


def find_latest_census_file(
    lists_dir: str, project: str, type_: Optional[str], status: Optional[str]
) -> Optional[Path]:
    """Most recent matching --census side file for the same filters, per
    O4.3's "same filters" requirement. Census side-file names embed the
    server-reported ``as_of.started_at`` timestamp, which is ISO8601 and
    therefore sorts lexicographically in chronological order -- the last
    glob match (sorted ascending) is the most recent run.
    """
    matches = census_glob(lists_dir, project, type_, status)
    return matches[-1] if matches else None


# --- record id extraction / ids-file writing ---------------------------------


def _extract_ids(records: Any) -> List[str]:
    """Per record, prefer the caller-facing item id (``item_id``, else
    ``id``). Otherwise fall back to ``record_id`` -- on the real server
    this is the raw DynamoDB sort key, e.g. ``"task#ENC-TSK-B95"``, so
    strip the leading ``"<type>#"`` prefix (split on the first ``"#"``)
    to recover the plain item id that elr_batch_get --ids-file expects
    (ENC-TSK-Q28). Order is preserved; an id that comes out empty is
    never emitted.
    """
    ids: List[str] = []
    if not isinstance(records, list):
        return ids
    for rec in records:
        if not isinstance(rec, dict):
            continue
        item_id = rec.get("item_id") or rec.get("id")
        if item_id:
            candidate = str(item_id)
        else:
            record_id = rec.get("record_id")
            if not record_id:
                continue
            candidate = str(record_id).split("#", 1)[-1]
        if candidate:
            ids.append(candidate)
    return ids


def _write_ids_file(path: Path, ids: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{i}\n" for i in ids), encoding="utf-8")


# --- raw page fetch (shared by --page and --pages) ----------------------------


def _fetch_raw_page(
    client: InternalClient,
    project: str,
    type_: Optional[str],
    status_filter: Optional[str],
    page_size: int,
    cursor: Optional[str],
) -> Tuple[int, Any]:
    query: Dict[str, Any] = {
        "type": type_,
        "status": status_filter,
        "page_size": page_size,
        "next_cursor": cursor,
    }
    encoded_project = urllib.parse.quote(str(project), safe="")
    return client.request("GET", "tracker", f"/{encoded_project}", query=query)


# --- --page ----------------------------------------------------------------


def run_single_page(client: InternalClient, key_sent: bool, args: argparse.Namespace) -> Dict[str, Any]:
    status, body = _fetch_raw_page(client, args.project, args.type, args.status, args.page_size, args.page)

    posture, anomalies = classify_internal_posture(key_sent=key_sent, status_code=status)
    anomalies = list(anomalies)
    ok = 200 <= status < 300 and isinstance(body, dict)
    if isinstance(body, dict) and body.get("error"):
        anomalies.append(f"response_error: {body['error']}")
        ok = False

    n = next_cursor = page_truncated = None
    if ok:
        ids = _extract_ids(body.get("records"))
        n = len(ids)
        next_cursor = body.get("next_cursor") or None
        # Prefer the server's own page_truncated field (raw list route
        # contract, U1) -- it is the authoritative signal and can diverge
        # from next_cursor presence (e.g. a final page that still echoes a
        # cursor for idempotent-retry purposes, or a truncation reason not
        # tied to a next_cursor). Only fall back to the next_cursor
        # heuristic when the server omits the field (pre-U1 servers).
        # "present only when True" convention preserved either way.
        server_page_truncated = body.get("page_truncated")
        if server_page_truncated is not None:
            page_truncated = True if server_page_truncated else None
        else:
            page_truncated = True if next_cursor else None
        out_path = page_ids_file_path(args.lists_dir, args.project, args.page)
        _write_ids_file(out_path, ids)

    return build_digest(
        "elr_list.page",
        ok,
        status,
        identity_posture=posture,
        anomalies=anomalies,
        n=n,
        next_cursor=next_cursor,
        page_truncated=page_truncated,
    )


# --- --pages N -----------------------------------------------------------------


def run_pages_loop(client: InternalClient, key_sent: bool, args: argparse.Namespace) -> Dict[str, Any]:
    census_path = find_latest_census_file(args.lists_dir, args.project, args.type, args.status)
    if census_path is None:
        return build_digest(
            "elr_list.pages",
            False,
            0,
            identity_posture="unknown",
            anomalies=["no_matching_census_file"],
        )

    try:
        census_body = json.loads(census_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return build_digest(
            "elr_list.pages",
            False,
            0,
            identity_posture="unknown",
            anomalies=["census_side_file_unreadable"],
        )

    all_pages = census_body.get("pages")
    if not isinstance(all_pages, list) or not all_pages:
        return build_digest(
            "elr_list.pages",
            False,
            0,
            identity_posture="unknown",
            anomalies=["census_side_file_has_no_pages"],
        )

    census_page_size = census_body.get("page_size") or args.page_size
    to_fetch = all_pages[: args.pages]

    all_ids: List[str] = []
    last_status = 0
    last_next_cursor: Optional[str] = None
    last_server_page_truncated: Any = None
    aggregate_ok = True
    anomalies: List[str] = []
    posture = "unknown"

    for entry in to_fetch:
        cursor = entry.get("cursor") if isinstance(entry, dict) else None
        status, body = _fetch_raw_page(client, args.project, args.type, args.status, census_page_size, cursor)
        page_posture, page_anomalies = classify_internal_posture(key_sent=key_sent, status_code=status)
        posture = page_posture
        anomalies.extend(page_anomalies)
        last_status = status
        page_ok = 200 <= status < 300 and isinstance(body, dict)
        if isinstance(body, dict) and body.get("error"):
            anomalies.append(f"response_error: {body['error']}")
            page_ok = False
        if not page_ok:
            aggregate_ok = False
            break
        all_ids.extend(_extract_ids(body.get("records")))
        last_next_cursor = body.get("next_cursor") or None
        last_server_page_truncated = body.get("page_truncated")

    lower_bound = True if (aggregate_ok and len(to_fetch) < len(all_pages)) else None
    # Prefer the last fetched page's own server-reported page_truncated
    # field over the next_cursor heuristic -- see run_single_page.
    if last_server_page_truncated is not None:
        page_truncated = True if last_server_page_truncated else None
    else:
        page_truncated = True if last_next_cursor else None

    if aggregate_ok:
        out_path = pages_ids_file_path(args.lists_dir, args.project, args.type, args.status, args.pages)
        _write_ids_file(out_path, all_ids)

    return build_digest(
        "elr_list.pages",
        aggregate_ok,
        last_status,
        identity_posture=posture,
        anomalies=anomalies,
        n=len(all_ids) if aggregate_ok else None,
        next_cursor=last_next_cursor,
        page_truncated=page_truncated,
        lower_bound=lower_bound,
    )


# --- capability preflight (O4.4) ----------------------------------------------


def check_census_capability(client: InternalClient) -> Tuple[bool, Any, Any, str, List[str]]:
    """Reads tracker_capabilities.census off GET /api/v1/health (D9: the
    coordination_api Lambda serving that route). Returns
    (supported, status, body, identity_posture, anomalies). Never issues
    any other request -- callers must not fetch a census/page until this
    returns supported=True.
    """
    status, body = client.health()
    if status == elr_tls.TLS_UNRESOLVED_STATUS:
        return False, status, body, "unknown", ["tls_ca_bundle_missing"]

    posture, anomalies = classify_internal_posture(key_sent=False, status_code=status)
    anomalies = list(anomalies)
    if not (200 <= status < 300):
        return False, status, body, posture, anomalies

    supported = False
    if isinstance(body, dict):
        caps = body.get("tracker_capabilities")
        if isinstance(caps, dict):
            supported = bool(caps.get("census"))
    return supported, status, body, posture, anomalies


# --- CLI -----------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not (args.census or args.page is not None or args.pages is not None):
        parser.error("choose one of --census, --page CURSOR, --pages N")

    config = get_profile("internal", environment_profile_name=args.profile)
    client = InternalClient(config, timeout=args.timeout)
    key_sent = bool(config.key_for("tracker"))

    supported, health_status, _health_body, posture, anomalies = check_census_capability(client)

    if health_status == elr_tls.TLS_UNRESOLVED_STATUS:
        digest = build_digest(
            "elr_list.preflight",
            False,
            health_status,
            identity_posture="unknown",
            anomalies=anomalies,
            **client.ca_bundle_digest_fields(),
        )
        print(json.dumps(digest, sort_keys=True))
        return elr_tls.EXIT_CODE_TLS_UNRESOLVED

    if not (200 <= health_status < 300):
        digest = build_digest(
            "elr_list.preflight",
            False,
            health_status,
            identity_posture=posture,
            anomalies=anomalies + ["health_check_failed"],
        )
        print(json.dumps(digest, sort_keys=True))
        return 1

    if not supported:
        print(CENSUS_UNSUPPORTED_MESSAGE, file=sys.stderr)
        digest = build_digest(
            "elr_list.preflight",
            False,
            health_status,
            identity_posture=posture,
            anomalies=list(anomalies) + [CENSUS_UNSUPPORTED_MESSAGE],
        )
        print(json.dumps(digest, sort_keys=True))
        return EXIT_CENSUS_UNSUPPORTED

    if args.census:
        digest = run_census(client, key_sent, args)
    elif args.page is not None:
        digest = run_single_page(client, key_sent, args)
    else:
        digest = run_pages_loop(client, key_sent, args)

    print(json.dumps(digest, sort_keys=True))
    return 0 if digest.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
