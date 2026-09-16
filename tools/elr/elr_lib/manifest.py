"""ELR digest side-file management (ENC-TSK-P78, T-B5, FR-B4-11).

NAMING NOTE, same spirit as elr_lib.profiles' module docstring: two
DISTINCT "digest" concepts exist in ELR -- do not conflate them.

  * elr_lib.digest owns the STDOUT digest schema (build_digest()) --
    every ELR CLI's small, stable JSON summary of what a run did.

  * THIS module owns the ON-DISK "digest side file" --
    ~/.enceladus/docs/{document_id}.digest.json -- a local cache of the
    document_api manifest endpoint's response (document_id, version,
    content_hash, size_bytes, outline, ...) plus a `fetched_at`
    timestamp. elr_doc_digest.py writes it explicitly; elr_doc_get.py
    writes the same shape as a side effect of every fetch (AC-1); it is
    the SOLE source of `if_match` (the content_hash a write must be
    conditioned on) for elr_doc_patch.py's optimistic-concurrency writes
    -- elr_doc_patch.py never re-derives if_match any other way, and
    refuses to run (exit 2) when the side file is absent or stale beyond
    STALE_AFTER_HOURS.

Nothing here ever prints a document body -- this module only ever
touches the small manifest-shaped JSON envelope, never `content`.
"""

from __future__ import annotations

import json
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from . import transport as elr_transport

DEFAULT_DOCS_DIR = "~/.enceladus/docs"
STALE_AFTER_HOURS = 24

# The canonical document_api manifest response shape (ground truth per
# the ENC-TSK-P78 brief): {document_id, version, content_hash,
# size_bytes, outline}. write_side_file() persists the FULL manifest
# response (whatever keys it actually carries), not just this subset --
# this tuple is documentation of the expected/typical shape only.
MANIFEST_FIELDS = ("document_id", "version", "content_hash", "size_bytes", "outline")

_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def now_iso() -> str:
    """UTC timestamp in the exact format this module reads back."""
    return datetime.now(timezone.utc).strftime(_TIMESTAMP_FORMAT)


def fetch_manifest(
    client: "elr_transport.InternalClient", document_id: str, *, timeout: int = 20
) -> Tuple[int, Any]:
    """GET /{document_id}/manifest through the same InternalClient/
    "document" API surface every other ELR document call uses. Returns
    (status, parsed_body) exactly like InternalClient.request()."""
    encoded = urllib.parse.quote(str(document_id), safe="")
    return client.request("GET", "document", f"/{encoded}/manifest")


def side_file_path(document_id: str, docs_dir: str = DEFAULT_DOCS_DIR) -> Path:
    return Path(docs_dir).expanduser() / f"{document_id}.digest.json"


def body_cache_path(document_id: str, docs_dir: str = DEFAULT_DOCS_DIR) -> Path:
    """The local body-copy path elr_doc_patch.py's re-apply-and-verify
    step reads from (when present) and refreshes on a hash mismatch --
    same directory as the digest side file, `{document_id}.md`."""
    return Path(docs_dir).expanduser() / f"{document_id}.md"


def write_side_file(
    document_id: str,
    manifest_body: Dict[str, Any],
    *,
    docs_dir: str = DEFAULT_DOCS_DIR,
    fetched_at: Optional[str] = None,
) -> Tuple[str, Dict[str, Any]]:
    """AC-1: writes ~/.enceladus/docs/{document_id}.digest.json = the
    FULL manifest response (every key it carries) plus `fetched_at`.
    Overwrites any existing side file wholesale (this is the "just
    fetched a fresh manifest" path -- elr_doc_digest.py and
    elr_doc_get.py both call this, never update_side_file()). Returns
    (path_str, written_dict).
    """
    out_dir = Path(docs_dir).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)
    payload: Dict[str, Any] = dict(manifest_body)
    payload["fetched_at"] = fetched_at or now_iso()
    path = side_file_path(document_id, docs_dir)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return str(path), payload


def update_side_file(
    document_id: str,
    updates: Dict[str, Any],
    *,
    docs_dir: str = DEFAULT_DOCS_DIR,
    fetched_at: Optional[str] = None,
) -> Tuple[str, Dict[str, Any]]:
    """Merge `updates` into whatever side file already exists (or start
    fresh from `updates` alone if none does), always refreshing
    `fetched_at`. Used by elr_doc_patch.py to refresh the cached
    version/content_hash/outline after a successful write or a 412 --
    a full manifest re-fetch is not required just to record what the
    write/412 response itself already told us.
    """
    existing = read_side_file(document_id, docs_dir=docs_dir) or {}
    merged = dict(existing)
    merged.update(updates)
    return write_side_file(document_id, merged, docs_dir=docs_dir, fetched_at=fetched_at)


def read_side_file(document_id: str, docs_dir: str = DEFAULT_DOCS_DIR) -> Optional[Dict[str, Any]]:
    path = side_file_path(document_id, docs_dir)
    if not path.is_file():
        return None
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return loaded if isinstance(loaded, dict) else None


def is_stale(fetched_at: Optional[str], *, max_age_hours: int = STALE_AFTER_HOURS, now: Optional[datetime] = None) -> bool:
    """True when `fetched_at` is missing, unparsable, or older than
    `max_age_hours`. `now` is a test-only override hook."""
    if not fetched_at:
        return True
    try:
        parsed = datetime.strptime(fetched_at, _TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        return True
    reference = now or datetime.now(timezone.utc)
    age_seconds = (reference - parsed).total_seconds()
    return age_seconds > max_age_hours * 3600
