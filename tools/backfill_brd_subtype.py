#!/usr/bin/env python3
"""Census and backfill for the brd subtypepattern graduation (ENC-FTR-152 / ENC-TSK-S25).

ENC-FTR-152 graduates ``brd`` from a ``subtypepattern`` on ``document_subtype='doc'``
to a first-class ``document_subtype='brd'`` (the first ENC-FTR-078 AC-18 graduation).
This tool takes the census on either plane and migrates every legacy
``doc + subtypepattern=brd`` document to ``document_subtype='brd'`` with the
subtypepattern cleared. The migration is metadata-only: every PATCH carries an
If-Match on the document's current content_hash, and the document is re-read
afterwards to prove the content_hash did not move.

Writes go through the governed document API (the document_api Lambda's own IAM
role) with the internal key, because the agent identity (enceladus-agent-cli)
carries an explicit IAM deny on DynamoDB/S3 writes (ENC-TSK-564).

Usage:
    # Census only (read-only), both shapes, all statuses.
    python3 tools/backfill_brd_subtype.py census --env gamma

    # Dry run: list what would be migrated. No writes.
    python3 tools/backfill_brd_subtype.py migrate --env gamma

    # Apply on gamma.
    python3 tools/backfill_brd_subtype.py migrate --env gamma --apply

    # Apply on prod (io-gated: the run refuses without --approved-by io).
    python3 tools/backfill_brd_subtype.py migrate --env prod --apply --approved-by io

    # Flag io-approved untagged BRDs from the sweep (AC-6) by explicit id.
    python3 tools/backfill_brd_subtype.py migrate --env prod --ids DOC-A,DOC-B --apply --approved-by io

Every run is idempotent: an already-migrated document is skipped, so a second
run reports zero changes. The internal key is read from
ENCELADUS_COORDINATION_INTERNAL_API_KEY / COORDINATION_INTERNAL_API_KEY or the
ELR key file ~/.enceladus/internal_key; it is never printed.

Related: ENC-FTR-152, ENC-TSK-S25, ENC-FTR-078 (AC-17/AC-18), DOC-259EB9D7200E.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent / "elr"))
from elr_lib import profiles as elr_profiles  # noqa: E402  (pure module, stdlib only)

logger = logging.getLogger("backfill_brd_subtype")

GRADUATED_PATTERN = "brd"
TARGET_SUBTYPE = "brd"
CAUSED_BY = "ENC-TSK-S25"

# Subtypes an io-approved sweep candidate may be flagged from, including the
# legacy-readable values older documents still carry. handoff, skill and
# context-node carry their own required fields and semantics, so they are never
# re-typed by this tool.
_IDS_MODE_SOURCE_SUBTYPES = {"doc", "idea", "wave", "coe", "general", "blueprint", "narrative", ""}

_ENV_TO_PROFILE = {"prod": elr_profiles.PROFILE_PROD, "gamma": elr_profiles.PROFILE_V4_GAMMA}
_OTHER_ENV = {"prod": "gamma", "gamma": "prod"}

_KEY_ENV_VARS = ("ENCELADUS_COORDINATION_INTERNAL_API_KEY", "COORDINATION_INTERNAL_API_KEY")
_KEY_FILE = Path.home() / ".enceladus" / "internal_key"

MAX_PASSES = 10


def _now_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _resolve_api_key() -> str:
    for name in _KEY_ENV_VARS:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    if _KEY_FILE.is_file():
        value = _KEY_FILE.read_text().strip()
        if value:
            return value
    raise SystemExit(
        "No internal key found (set ENCELADUS_COORDINATION_INTERNAL_API_KEY or provision "
        "~/.enceladus/internal_key via tools/elr/elr_provision_key.py)."
    )


def _ssl_context() -> ssl.SSLContext:
    cafile = os.environ.get("SSL_CERT_FILE", "").strip()
    if not cafile:
        try:
            import certifi  # type: ignore

            cafile = certifi.where()
        except ImportError:
            cafile = ""
    return ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()


def document_base_url(env: str) -> str:
    """The document API base for a plane: the direct host, per ELR's profile table."""
    profile = elr_profiles.get_environment_profile(_ENV_TO_PROFILE[env])
    return profile.api_base_overrides["document_direct"].rstrip("/")


def projects_base_url(env: str) -> str:
    profile = elr_profiles.get_environment_profile(_ENV_TO_PROFILE[env])
    return profile.api_base_overrides["projects"].rstrip("/")


def sentinel_document_id(env: str) -> str:
    return elr_profiles.get_environment_profile(_ENV_TO_PROFILE[env]).sentinel_document_id


class DocumentClient:
    """Minimal governed document API client (internal-key auth, urllib)."""

    def __init__(self, env: str, api_key: str, timeout: int = 30) -> None:
        self.env = env
        self.base = document_base_url(env)
        self.projects_base = projects_base_url(env)
        self._key = api_key
        self._timeout = timeout
        self._ctx = _ssl_context()

    def _request(
        self,
        method: str,
        url: str,
        payload: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, Dict[str, Any]]:
        body = json.dumps(payload).encode() if payload is not None else None
        all_headers = {
            "Content-Type": "application/json",
            "X-Coordination-Internal-Key": self._key,
            "X-Write-Source": "backfill_brd_subtype",
        }
        all_headers.update(headers or {})
        req = urllib.request.Request(url, data=body, method=method, headers=all_headers)
        try:
            with urllib.request.urlopen(req, timeout=self._timeout, context=self._ctx) as resp:
                raw = resp.read()
                return resp.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                return exc.code, json.loads(raw)
            except Exception:
                return exc.code, {"raw": raw.decode(errors="replace")[:500]}

    def get(self, document_id: str) -> Tuple[int, Dict[str, Any]]:
        status, body = self._request("GET", f"{self.base}/{urllib.parse.quote(document_id)}")
        return status, (body.get("document", body) if isinstance(body, dict) else {})

    def search(self, **params: str) -> Tuple[int, Dict[str, Any]]:
        query = urllib.parse.urlencode(params)
        return self._request("GET", f"{self.base}/search?{query}")

    def patch(self, document_id: str, payload: Dict[str, Any], if_match: str) -> Tuple[int, Dict[str, Any]]:
        return self._request(
            "PATCH",
            f"{self.base}/{urllib.parse.quote(document_id)}",
            payload,
            headers={"If-Match": f'"{if_match}"'},
        )

    def list_project_ids(self) -> List[str]:
        status, body = self._request("GET", self.projects_base)
        if status != 200:
            raise RuntimeError(f"projects list failed on {self.env}: HTTP {status}")
        rows = body.get("projects", body.get("items", [])) if isinstance(body, dict) else []
        return sorted({str(r.get("project_id") or r.get("name") or "").strip() for r in rows} - {""})


# ---------------------------------------------------------------------------
# Plane gate
# ---------------------------------------------------------------------------


def plane_check(client: DocumentClient) -> Dict[str, Any]:
    """Prove the base URL is the intended plane before any write.

    Each plane keeps a sentinel document that exists only there (ENC-TSK-P79). The
    target plane must return its own sentinel and must NOT return the other
    plane's sentinel; a twin-environment mix-up fails one of the two.
    """
    own_id = sentinel_document_id(client.env)
    other_id = sentinel_document_id(_OTHER_ENV[client.env])
    own_status, own_doc = client.get(own_id)
    other_status, _ = client.get(other_id)
    ok = own_status == 200 and own_doc.get("document_id") == own_id and other_status == 404
    return {
        "ok": ok,
        "env": client.env,
        "base_url": client.base,
        "own_sentinel": {"document_id": own_id, "status": own_status},
        "other_sentinel": {"document_id": other_id, "status": other_status},
    }


# ---------------------------------------------------------------------------
# Census
# ---------------------------------------------------------------------------


def _search_all(client: DocumentClient, **params: str) -> List[Dict[str, Any]]:
    """Every match across all statuses, partitioning by project past the page cap."""
    base_params = {"status": "", **params}
    status, body = client.search(**base_params)
    if status != 200:
        raise RuntimeError(f"search {params} failed on {client.env}: HTTP {status} {body}")
    docs = list(body.get("documents", []))
    total = int(body.get("total_matches", len(docs)))
    if total <= len(docs):
        return docs
    # The search route caps at PAGE_SIZE rows with no cursor; split per project.
    docs = []
    for project_id in client.list_project_ids():
        status, body = client.search(project=project_id, **base_params)
        if status != 200:
            raise RuntimeError(f"search {params} project={project_id} failed: HTTP {status}")
        page = list(body.get("documents", []))
        if int(body.get("total_matches", len(page))) > len(page):
            raise RuntimeError(
                f"project {project_id} alone exceeds the search page cap for {params}; "
                "narrow the census before migrating"
            )
        docs.extend(page)
    return docs


def _legacy_docs(client: DocumentClient) -> List[Dict[str, Any]]:
    # document_subtype=doc + subtypepattern=brd is the raw legacy probe; it is not
    # aliased by the graduated search path (ENC-FTR-152 AC-7).
    return _search_all(client, document_subtype="doc", subtypepattern=GRADUATED_PATTERN)


def _legacy_page(client: DocumentClient) -> Tuple[List[Dict[str, Any]], int]:
    """One page of legacy rows plus the exact total. Migrated rows drop out of this
    query, so repeated pages converge without a cursor."""
    status, body = client.search(status="", document_subtype="doc", subtypepattern=GRADUATED_PATTERN)
    if status != 200:
        raise RuntimeError(f"legacy search failed on {client.env}: HTTP {status} {body}")
    docs = list(body.get("documents", []))
    return docs, int(body.get("total_matches", len(docs)))


def _graduated_docs(client: DocumentClient) -> List[Dict[str, Any]]:
    return _search_all(client, document_subtype=TARGET_SUBTYPE)


def _summarize(docs: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    rows = sorted(docs, key=lambda d: (d.get("created_at", ""), d.get("document_id", "")))
    by_project: Dict[str, int] = {}
    for d in rows:
        by_project[d.get("project_id", "")] = by_project.get(d.get("project_id", ""), 0) + 1
    by_status: Dict[str, int] = {}
    for d in rows:
        by_status[d.get("status", "")] = by_status.get(d.get("status", ""), 0) + 1
    return {
        "count": len(rows),
        "projects": len(by_project),
        "by_project": dict(sorted(by_project.items())),
        "by_status": dict(sorted(by_status.items())),
        "first_created_at": rows[0].get("created_at", "") if rows else "",
        "last_created_at": rows[-1].get("created_at", "") if rows else "",
        "ids": [d.get("document_id", "") for d in rows],
    }


def census(client: DocumentClient) -> Dict[str, Any]:
    return {
        "env": client.env,
        "at": _now_z(),
        "plane_check": plane_check(client),
        "legacy_doc_subtypepattern_brd": _summarize(_legacy_docs(client)),
        "document_subtype_brd": _summarize(_graduated_docs(client)),
    }


# ---------------------------------------------------------------------------
# Migrate
# ---------------------------------------------------------------------------


def classify(doc: Dict[str, Any], ids_mode: bool) -> str:
    """'already' | 'eligible' | 'ineligible:<reason>' for one live document."""
    subtype = str(doc.get("document_subtype", "")).strip().lower()
    pattern = str(doc.get("subtypepattern", "") or "").strip().lower()
    if subtype == TARGET_SUBTYPE and not pattern:
        return "already"
    if subtype == TARGET_SUBTYPE:
        return "eligible"  # graduated but still carrying a stale subtypepattern
    if subtype == "doc" and pattern == GRADUATED_PATTERN:
        return "eligible"
    if ids_mode and subtype in _IDS_MODE_SOURCE_SUBTYPES:
        return "eligible"
    return f"ineligible:subtype={subtype or '-'},subtypepattern={pattern or '-'}"


def _patch_body(doc_id: str) -> Dict[str, Any]:
    return {
        "document_subtype": TARGET_SUBTYPE,
        "subtypepattern": "",
        "caused_by": CAUSED_BY,
        "idempotency_key": f"enc-tsk-s25-brd-graduation-{doc_id}",
    }


def migrate_one(client: DocumentClient, doc_id: str, apply: bool, ids_mode: bool) -> Dict[str, Any]:
    status, doc = client.get(doc_id)
    row: Dict[str, Any] = {"document_id": doc_id, "env": client.env, "at": _now_z()}
    if status != 200:
        row.update(outcome="failed", reason=f"GET HTTP {status}")
        return row
    before = {
        "document_subtype": doc.get("document_subtype", ""),
        "subtypepattern": doc.get("subtypepattern", "") or "",
        "content_hash": doc.get("content_hash", ""),
        "version": doc.get("version"),
    }
    row.update(project_id=doc.get("project_id", ""), title=doc.get("title", ""), before=before)
    verdict = classify(doc, ids_mode)
    if verdict == "already":
        row["outcome"] = "already"
        return row
    if verdict.startswith("ineligible"):
        row.update(outcome="skipped", reason=verdict)
        return row
    if not before["content_hash"]:
        row.update(outcome="failed", reason="document has no content_hash; refusing an unguarded patch")
        return row
    if not apply:
        row["outcome"] = "would_migrate"
        return row

    p_status, p_body = client.patch(doc_id, _patch_body(doc_id), if_match=before["content_hash"])
    if p_status != 200:
        row.update(outcome="failed", reason=f"PATCH HTTP {p_status}", error=p_body)
        return row
    a_status, after_doc = client.get(doc_id)
    after = {
        "document_subtype": after_doc.get("document_subtype", ""),
        "subtypepattern": after_doc.get("subtypepattern", "") or "",
        "content_hash": after_doc.get("content_hash", ""),
        "version": after_doc.get("version"),
    }
    row["after"] = after
    if a_status != 200:
        row.update(outcome="failed", reason=f"post-patch GET HTTP {a_status}")
    elif after["content_hash"] != before["content_hash"]:
        row.update(outcome="failed", reason="content_hash changed on a metadata-only patch")
    elif after["document_subtype"] != TARGET_SUBTYPE or after["subtypepattern"]:
        row.update(outcome="failed", reason="post-patch shape is not document_subtype=brd with no subtypepattern")
    else:
        row["outcome"] = "migrated"
    return row


def migrate(client: DocumentClient, apply: bool, ids: Optional[List[str]] = None) -> Dict[str, Any]:
    gate = plane_check(client)
    rows: List[Dict[str, Any]] = []
    summary: Dict[str, Any] = {"env": client.env, "at": _now_z(), "apply": apply, "plane_check": gate}
    if not gate["ok"]:
        summary.update(ok=False, reason="plane check failed; refusing to run", rows=rows)
        return summary

    if ids:
        for doc_id in ids:
            rows.append(migrate_one(client, doc_id, apply, ids_mode=True))
    elif not apply:
        # A dry run changes nothing, so it lists the complete legacy set once.
        for doc in _legacy_docs(client):
            rows.append(migrate_one(client, doc.get("document_id", ""), apply, ids_mode=False))
    else:
        seen: set = set()
        for _ in range(MAX_PASSES):
            page, _total = _legacy_page(client)
            pending = [d.get("document_id", "") for d in page]
            pending = [d for d in pending if d and d not in seen]
            if not pending:
                break
            for doc_id in pending:
                seen.add(doc_id)
                rows.append(migrate_one(client, doc_id, apply, ids_mode=False))

    counts: Dict[str, int] = {}
    for r in rows:
        counts[r["outcome"]] = counts.get(r["outcome"], 0) + 1
    summary.update(ok=counts.get("failed", 0) == 0, counts=counts, rows=rows)
    if apply and not ids:
        summary["remaining_legacy"] = _legacy_page(client)[1]
        summary["ok"] = summary["ok"] and summary["remaining_legacy"] == 0
    return summary


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _write_report(path: Optional[str], payload: Dict[str, Any]) -> None:
    if not path:
        return
    out = Path(path).expanduser()
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("a", encoding="utf-8") as fh:
        for row in payload.get("rows", []):
            fh.write(json.dumps(row, sort_keys=True) + "\n")
        fh.write(json.dumps({k: v for k, v in payload.items() if k != "rows"}, sort_keys=True) + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("census", "migrate"):
        p = sub.add_parser(name)
        p.add_argument("--env", choices=sorted(_ENV_TO_PROFILE), required=True)
        p.add_argument("--report-out", help="Append JSONL rows plus a summary line to this file.")
        p.add_argument("--timeout", type=int, default=30)
        if name == "migrate":
            p.add_argument("--apply", action="store_true", help="Write. Without it the run is a dry run.")
            p.add_argument("--approved-by", default="", help="Required as 'io' for a prod --apply.")
            p.add_argument("--ids", default="", help="Comma-separated io-approved document ids (sweep mode).")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = build_parser().parse_args(argv)
    if args.command == "migrate" and args.apply and args.env == "prod" and args.approved_by != "io":
        logger.error("prod --apply requires --approved-by io (ENC-TSK-S25: io-gated prod backfill)")
        return 2

    client = DocumentClient(args.env, _resolve_api_key(), timeout=args.timeout)
    if args.command == "census":
        result = census(client)
        print(json.dumps(result, indent=2, sort_keys=True))
        _write_report(args.report_out, result)
        return 0 if result["plane_check"]["ok"] else 2

    ids = [i.strip() for i in args.ids.split(",") if i.strip()] or None
    result = migrate(client, apply=args.apply, ids=ids)
    for row in result.get("rows", []):
        logger.info(
            "[%s] %s %s %s -> %s",
            row.get("outcome", "").upper(),
            row.get("document_id"),
            row.get("project_id", ""),
            (row.get("before") or {}).get("document_subtype", ""),
            TARGET_SUBTYPE if row.get("outcome") in ("migrated", "would_migrate") else "-",
        )
    print(json.dumps({k: v for k, v in result.items() if k != "rows"}, indent=2, sort_keys=True))
    _write_report(args.report_out, result)
    if not result["plane_check"]["ok"]:
        return 2
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
