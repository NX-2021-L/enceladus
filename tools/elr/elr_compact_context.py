#!/usr/bin/env python3
"""elr_compact_context.py -- ELR compact context (ENC-TSK-Q50, ENC-FTR-147,
DOC-412AB7081565 FR-1..FR-9, M-3, M-4).

The MCP ``get_compact_context`` tool returns 27-145 KB per call, of which the
ranking is 11-17 KB, and it spills past the harness tool-result cap. This
verb performs the SAME governed HTTP reads the MCP composer performs --

  record      GET tracker/_/{type}/{id}              (ENC-TSK-Q10 sentinel route)
  components  GET coordination/components            (filtered to the record's)
  governance  GET governance/dictionary?entity=tracker.{type}
  related     GET documents/search?related={id}
  project     GET coordination/projects/{project}
  reference   GET documents/search?keyword=reference + GET documents/{id}
              (topic mode; grepped client-side exactly as the MCP tool does)
  hybrid      GET tracker/graphsearch?search_type=hybrid  (query AND anchor)

-- lands every section under ``~/.enceladus/context/<run_id>/`` and prints ONE
small digest: the ranked top-N inline (a compact array row per node), the
signal posture, and the on-disk section index. Digest bytes are bounded by
``1024 + 192 * top_n`` (M-3).

TRANSPORT (ENC-TSK-Q54): ``--transport auto`` (default) reads
tracker_capabilities.compact_context from /api/v1/health; when true ONE GET to
coordination/context/compact (fields=full) replaces the composition above and
is mapped into the same digest (retrieval.composer "route"; "elr-1" otherwise).
A route failure (non-200 / shape drift) falls back to composition with a
``route_fallback:*`` warning. In composition, hybrid requests fields=compact
only when graphsearch/health advertises hybrid_fields_compact (ENC-TSK-Q49).

HARD RULES
  * GET only. There is no code path that constructs another HTTP method
    (tests/test_compact_context.py proves it statically).
  * No retrieval logic client-side. ``nodes[*]`` ordering and every score are
    copied from the server verbatim. The only derived inputs are the
    SENDING-side ones the BRD mandates (FR-2): in record modes without
    ``--query`` the query is ``normalize(title + ' ' + intent)[:300]`` of the
    record just read and the anchor is the record id. An anchor is never
    selected from a retrieval result.
  * ``--order fused`` re-presents the same returned rows by the server-supplied
    ``_fused_rank`` (no re-scoring); the default ``final`` is the server order.
  * Stdlib only. Credential and CA-bundle resolution reuse elr_lib: exit 7
    (no credential, before any request) and exit 4 (TLS unresolved).

Exit codes
  0  digest emitted (a partial composition still exits 0 with partial=true)
  1  unusable ranking: hybrid call failed / record unreadable / unreachable
  4  TLS CA bundle unresolved                       (elr_lib.tls)
  6  hybrid_unsupported_by_server: the plane answered 400/404 for hybrid;
     or (--transport route) context_route_unavailable
  7  no_credential_configured                       (elr_lib.config)
  8  response_shape_drift: a contract key is missing from the hybrid response

The hybrid response's contract keys are those the live route returns today
(required set below). Keys the BRD lists but the live route omits when unset
(retrieval_records, energy_lambda_weights, corroboration_weber_k) are optional;
additive unknown keys never fail a run, they surface as a warning.

Digest schema (``elr.compact_context_digest``): stable keys + ``profile``,
``key_source``, ``governance_hash`` (existing fields) + ``header``,
``retrieval``, ``ranking`` (array rows: [record_id, record_type, final_rank,
fused_rank, fused_score, final_score, {v,g,k}, k_corr, b_corr, below_t3,
title<=64]), ``sections`` ({name: [bytes, sha256[:32]]} -- a 128-bit prefix, because seven
full 64-hex hashes alone would consume 45% of the M-3 fixed budget; the file is
``<header.root>/<header.run_id>/<name>.json``), ``ids_file`` (the file NAME
inside that run directory -- absolute paths are kept out of the byte budget;
pass ``<root>/<run_id>/<ids_file>`` to ``elr_batch_get --ids-file``) and
``warnings``. To fit M-3, ``header.partial`` / ``header.truncated`` are present
only when true, ``governance_hash`` and ``retrieval.intent_signature`` are
16-hex prefixes (the full intent_signature is in hybrid.json),
``embedding_coverage_sample`` is [covered, total_ranked], and ``retrieval``
omits null/default members (rrf_k when 60);
``candidates`` is {v, g, k}.
The CA-bundle report appears only on TLS failures (exit 4).
``retrieval.signals_absent`` follows M-5; a graph signal served by the Cypher
fallback is present AND listed absent with reason ``gds_unavailable``.

Usage:
    python3 tools/elr/elr_compact_context.py --mode task --record-id ENC-TSK-Q33 --top-n 10
    python3 tools/elr/elr_compact_context.py --query "token efficient reads" --project-id enceladus
    python3 tools/elr/elr_batch_get.py --ids-file ~/.enceladus/context/<run_id>/<run_id>.ids
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# Allow running this file directly without tools/elr on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from elr_lib import context_store  # noqa: E402
from elr_lib import identity as elr_identity  # noqa: E402
from elr_lib import profiles as elr_profiles  # noqa: E402
from elr_lib import tls as elr_tls  # noqa: E402
from elr_lib.config import EXIT_CODE_NO_CREDENTIAL, get_profile  # noqa: E402
from elr_lib.digest import build_digest  # noqa: E402
from elr_lib.transport import InternalClient, classify_internal_posture  # noqa: E402

import elr_batch_get  # noqa: E402  (id classification + sentinel path only)

OPERATION = "elr_compact_context.run"
COMPOSER_VERSION = "elr-1"
COMPOSER_ROUTE = "route"  # ENC-TSK-Q54: server-side context.compact assembler
TRANSPORT_AUTO = "auto"
TRANSPORT_ROUTE = "route"
TRANSPORT_COMPOSE = "compose"
ROUTE_PATH = "/context/compact"
ROUTE_SECTION_NAMES = {"record_context": "record", "hybrid_retrieval": "hybrid"}
ROUTE_WARNING_MAX_CHARS = 96

EXIT_UNUSABLE = 1
EXIT_HYBRID_UNSUPPORTED = 6
EXIT_RESPONSE_SHAPE_DRIFT = 8
ANOMALY_HYBRID_UNSUPPORTED = "hybrid_unsupported_by_server"
ANOMALY_SHAPE_DRIFT = "response_shape_drift"

RECORD_MODES = ("record", "issue", "task", "feature")
ALL_MODES = RECORD_MODES + ("project", "document", "topic")
SIGNALS = ("vector", "graph", "keyword")
_SIGNAL_SHORT = {"vector": "v", "graph": "g", "keyword": "k"}

TOP_N_DEFAULT = 20
TOP_N_MIN = 1
TOP_N_MAX = 50
QUERY_MAX_CHARS = 300
TITLE_MAX_CHARS = 64
QUERY_HEAD_CHARS = 32
GOVERNANCE_HASH_CHARS = 16
DEFAULT_RRF_K = 60  # reported only when the server differs
INTENT_SIGNATURE_CHARS = 16
SECTION_SHA_CHARS = 32  # sha256 prefix in the digest; the full hash is `shasum -a 256 <file>`
DIGEST_BASE_BYTES = 1024
DIGEST_ROW_BYTES = 192
DEFAULT_PROJECT_PAGE_SIZE = 10
REFERENCE_CONTEXT_LINES = 2
REFERENCE_MAX_RESULTS = 10
DEFAULT_TIMEOUT = 30

# Keys the live hybrid route returns on every 200 (verified 2026-10-08 on
# prod and gamma). A missing key is response_shape_drift (exit 8).
REQUIRED_HYBRID_KEYS: Tuple[str, ...] = (
    "success",
    "nodes",
    "summary",
    "signal_availability",
    "graph_algorithm",
    "rrf_k",
    "embedding_coverage_sample",
    "per_node_fusion",
    "fsrs_t3_threshold",
    "include_below_threshold",
    "pathway",
)
OPTIONAL_HYBRID_KEYS: Tuple[str, ...] = (
    "edges",
    "paths",
    "edge_participation",
    "query_cypher",
    "duration_ms",
    "facets",
    "facets_source",
    "keyword_source",
    "retrieval_records",
    "energy_lambda_weights",
    "corroboration_weber_k",  # pre-ENC-TSK-Q46 planes
    "corroboration_alpha",  # ENC-TSK-Q46
    "s_top",  # ENC-TSK-Q46
)
REQUIRED_NODE_KEYS: Tuple[str, ...] = (
    "record_id",
    "_fused_rank",
    "_fused_score",
    "_final_rank",
    "_final_score",
    "_per_signal_ranks",
    "_corroboration_count",
    "_b_corr",
)

_SUMMARY_COUNTS_RE = re.compile(r"vector=(\d+),\s*graph=(\d+),\s*keyword=(\d+)")
_WS_RE = re.compile(r"\s+")


class ShapeDrift(Exception):
    """The hybrid response violates the contract; ``key`` names the culprit."""

    def __init__(self, key: str):
        super().__init__(key)
        self.key = key


# --- pure helpers -----------------------------------------------------------


def clamp_top_n(value: Any) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        n = TOP_N_DEFAULT
    return max(TOP_N_MIN, min(TOP_N_MAX, n))


def normalize_text(value: Any) -> str:
    return _WS_RE.sub(" ", str(value or "")).strip()


def derive_query(record: Dict[str, Any]) -> str:
    """FR-2: normalize(title + ' ' + intent)[:300]; falls back to the title
    alone when the record carries no intent (and to '' when neither)."""
    title = normalize_text(record.get("title"))
    intent = normalize_text(record.get("intent"))
    combined = normalize_text(f"{title} {intent}")[:QUERY_MAX_CHARS].strip()
    return combined or title[:QUERY_MAX_CHARS]


def infer_mode(
    mode: Optional[str],
    record_id: Optional[str],
    document_id: Optional[str],
    query: Optional[str],
    project_id: Optional[str],
) -> Optional[str]:
    """Mirror of the server composer: an explicit mode wins; otherwise
    record_id -> record, document_id -> document, query -> topic,
    project_id -> project."""
    explicit = (mode or "").strip().lower()
    if explicit:
        return explicit
    if (record_id or "").strip():
        return "record"
    if (document_id or "").strip():
        return "document"
    if (query or "").strip():
        return "topic"
    if (project_id or "").strip():
        return "project"
    return None


def digest_budget_bytes(top_n: int) -> int:
    """M-3: digest_bytes <= 1024 + 192 * top_n."""
    return DIGEST_BASE_BYTES + DIGEST_ROW_BYTES * top_n


def parse_summary_counts(summary: Any) -> Optional[Dict[str, int]]:
    """Candidate counts per signal from the server's summary string, e.g.
    'Hybrid: 5 nodes (vector=116, graph=25, keyword=25; ...)'."""
    match = _SUMMARY_COUNTS_RE.search(str(summary or ""))
    if not match:
        return None
    return {"v": int(match.group(1)), "g": int(match.group(2)), "k": int(match.group(3))}


def validate_hybrid_shape(body: Any) -> None:
    """FR-7: raise ShapeDrift naming the first missing contract key."""
    if not isinstance(body, dict):
        raise ShapeDrift("<body:not-an-object>")
    for key in REQUIRED_HYBRID_KEYS:
        if key not in body:
            raise ShapeDrift(key)
    if not isinstance(body["nodes"], list):
        raise ShapeDrift("nodes:not-a-list")
    if not isinstance(body["signal_availability"], dict):
        raise ShapeDrift("signal_availability:not-an-object")
    if not isinstance(body["pathway"], dict):
        raise ShapeDrift("pathway:not-an-object")
    for index, node in enumerate(body["nodes"]):
        if not isinstance(node, dict):
            raise ShapeDrift(f"nodes[{index}]:not-an-object")
        for key in REQUIRED_NODE_KEYS:
            if key not in node:
                raise ShapeDrift(f"nodes[{index}].{key}")


def unexpected_hybrid_keys(body: Dict[str, Any]) -> List[str]:
    known = set(REQUIRED_HYBRID_KEYS) | set(OPTIONAL_HYBRID_KEYS)
    return sorted(k for k in body if k not in known)


def _type_from_node(node: Dict[str, Any]) -> str:
    labels = node.get("_labels")
    if isinstance(labels, list) and labels and isinstance(labels[0], str):
        return labels[0].lower()
    classified = elr_batch_get.classify_id(str(node.get("record_id", "")))
    return classified.record_type or ("document" if str(node.get("record_id", "")).startswith("DOC-") else "")


def _round(value: Any, places: int) -> Any:
    try:
        return round(float(value), places)
    except (TypeError, ValueError):
        return None


def ranking_row(node: Dict[str, Any]) -> List[Any]:
    """One array row per node, every value copied from the server node
    (M-1: never recomputed)."""
    per_signal = node.get("_per_signal_ranks") or {}
    ranks = {_SIGNAL_SHORT[s]: per_signal[s] for s in SIGNALS if s in per_signal}
    return [
        str(node.get("record_id", ""))[:16],
        _type_from_node(node),
        node.get("_final_rank"),
        node.get("_fused_rank"),
        _round(node.get("_fused_score"), 6),
        _round(node.get("_final_score"), 6),
        ranks,
        node.get("_corroboration_count"),
        _round(node.get("_b_corr"), 3),
        bool(node.get("_below_t3", False)),
        normalize_text(node.get("title"))[:TITLE_MAX_CHARS],
    ]


def signal_posture(
    body: Dict[str, Any], query_sent: bool, anchor_sent: bool
) -> Tuple[List[str], Dict[str, str]]:
    """signals_present and signals_absent{signal: reason} per M-5, derived
    only from our inputs and server fields."""
    availability = body.get("signal_availability") or {}
    present = [s for s in SIGNALS if availability.get(s)]
    absent: Dict[str, str] = {}
    if not query_sent:
        absent["vector"] = "no_query"
        absent["keyword"] = "no_query"
    else:
        if not availability.get("vector"):
            absent["vector"] = "embedding_unavailable"
        if not availability.get("keyword"):
            absent["keyword"] = "keyword_unavailable"
    if not anchor_sent:
        absent["graph"] = "no_anchor"
    elif not availability.get("graph"):
        absent["graph"] = "graph_unavailable"
    elif body.get("graph_algorithm") == "cypher_fallback":
        absent["graph"] = "gds_unavailable"
    return present, absent


# --- transport wrappers -----------------------------------------------------


def _get(client: Any, api: str, path: str = "", query: Optional[Dict[str, Any]] = None) -> Tuple[int, Any]:
    """The ONLY request primitive in this module: always GET."""
    return client.request("GET", api, path, query=query)


def _quote(value: str) -> str:
    return urllib.parse.quote(str(value), safe="")


class Section:
    """Outcome of one section fetch."""

    def __init__(self, name: str, status: int, body: Any, ms: int, optional_warning: str = ""):
        self.name = name
        self.status = status
        self.body = body
        self.ms = ms
        self.optional_warning = optional_warning

    @property
    def ok(self) -> bool:
        return isinstance(self.status, int) and 200 <= self.status < 300 and isinstance(self.body, (dict, list))


def _timed(name: str, fn: Callable[[], Tuple[int, Any]]) -> Section:
    started = time.monotonic()
    try:
        status, body = fn()
    except Exception as exc:  # noqa: BLE001 -- a section failure must not abort siblings
        status, body = 0, {"error": f"{exc.__class__.__name__}"}
    return Section(name, status, body, int((time.monotonic() - started) * 1000))


def filter_components(all_components: Any, wanted: List[str]) -> Dict[str, Any]:
    """components.json: the active components restricted to the record's own
    component ids, with the resolution it was computed under."""
    rows = []
    if isinstance(all_components, dict):
        rows = all_components.get("components") or []
    by_id = {str(c.get("component_id")): c for c in rows if isinstance(c, dict)}
    matched = [by_id[w] for w in wanted if w in by_id]
    return {
        "components": matched,
        "count": len(matched),
        "component_resolution": {
            "requested": list(wanted),
            "matched": [c.get("component_id") for c in matched],
            "unmatched": [w for w in wanted if w not in by_id],
            "source": "elr-client-filter",
        },
    }


def grep_reference(content: str, query: str, document_id: str) -> Dict[str, Any]:
    """The MCP reference_search tool's plain-text grep (context 2, max 10)."""
    lines = content.splitlines()
    needle = query.lower()
    snippets: List[Dict[str, Any]] = []
    heading = ""
    for idx, line in enumerate(lines):
        if re.match(r"^#{1,6}\s+", line):
            heading = line.rstrip()
        if needle and needle in line.lower():
            snippets.append(
                {
                    "line_number": idx + 1,
                    "section": heading,
                    "context_before": lines[max(0, idx - REFERENCE_CONTEXT_LINES) : idx],
                    "matched_line": line,
                    "context_after": lines[idx + 1 : idx + 1 + REFERENCE_CONTEXT_LINES],
                }
            )
            if len(snippets) >= REFERENCE_MAX_RESULTS:
                break
    return {"source_document_id": document_id, "query": query, "total_lines": len(lines), "matches": snippets}


def fetch_project_documents(client: Any, project_id: str) -> Section:
    """Project mode: the MCP composer lists the project's documents and keeps
    the first page (page_size 10). The document API has no server-side page,
    so the first page is taken from the full list, as the server tool does."""
    started = time.monotonic()
    status, body = _get(client, "document_direct", "", {"project": project_id})
    ms = int((time.monotonic() - started) * 1000)
    docs = body.get("documents") if isinstance(body, dict) else body if isinstance(body, list) else None
    if not (200 <= status < 300) or not isinstance(docs, list):
        return Section("documents", status, body, ms)
    page = docs[:DEFAULT_PROJECT_PAGE_SIZE]
    return Section("documents", status, {"documents": page, "count": len(page), "total": len(docs)}, ms)


def fetch_reference(client: Any, project_id: str, query: str) -> Section:
    started = time.monotonic()
    status, found = _get(client, "document_direct", "/search", {"project": project_id, "keyword": "reference"})
    docs = found.get("documents") if isinstance(found, dict) else None
    if not (200 <= status < 300) or not docs:
        return Section("reference", status if not (200 <= status < 300) else 404, found, int((time.monotonic() - started) * 1000))
    doc_id = str(docs[0].get("document_id") or "")
    status, doc = _get(client, "document_direct", f"/{_quote(doc_id)}", {"include_content": "true"})
    content = doc.get("content", "") if isinstance(doc, dict) else ""
    if not (200 <= status < 300) or not content:
        return Section("reference", status if not (200 <= status < 300) else 404, doc, int((time.monotonic() - started) * 1000))
    return Section("reference", 200, grep_reference(content, query, doc_id), int((time.monotonic() - started) * 1000))


def _hybrid_get(client: Any, hybrid_query: Dict[str, Any], warnings: List[str]) -> Tuple[int, Any]:
    """The hybrid GET. When fields=compact was requested and the plane rejects
    it (400) or answers a body that breaks the contract, retry once without it."""
    status, body = _get(client, "graph_query", "", hybrid_query)
    if hybrid_query.get("fields"):
        drifted = False
        if status == 200:
            try:
                validate_hybrid_shape(body)
            except ShapeDrift:
                drifted = True
        if status in (400, 404) or drifted:
            warnings.append("hybrid_fields_compact_retry_full")
            plain = {k: v for k, v in hybrid_query.items() if k != "fields"}
            return _get(client, "graph_query", "", plain)
    return status, body


def _route_query(args: Any, mode: str, top_n: int) -> Dict[str, Any]:
    def off(flag: str) -> Optional[str]:
        return "false" if getattr(args, flag, False) else None

    query: Dict[str, Any] = {
        "mode": mode,
        "record_id": (args.record_id or None),
        "project_id": (args.project_id or None),
        "document_id": (args.document_id or None),
        "query": (args.query or None),
        "anchor_record_id": (args.anchor_record_id or None),
        "record_type": (args.record_type or None),
        "top_n": top_n,
        "include_below_threshold": "true" if args.include_below_threshold else None,
        "history_limit": args.history_limit,
        "domain": (args.domain or None),
        "domains": (args.domains or None),
        "include_code_map": off("no_code_map"),
        "include_governance": off("no_governance"),
        "include_related_documents": off("no_related_documents"),
        "include_hybrid_retrieval": off("no_hybrid"),
        "include_components": off("no_components"),
        "include_architecture": off("no_architecture"),
        "include_recent_history": off("no_recent_history"),
        "fields": "full",
    }
    return {k: v for k, v in query.items() if v is not None}


def _try_route(client: Any, args: Any, mode: str, top_n: int) -> Tuple[Optional[Dict[str, Any]], str]:
    """ONE GET to context.compact (fields=full). Returns (state, "") on success
    or (None, reason) on any non-200 / shape drift so the caller can fall back."""
    sec = _timed("route", lambda: _get(client, "coordination", ROUTE_PATH, _route_query(args, mode, top_n)))
    if sec.status != 200:
        return None, f"http_{sec.status}"
    body = sec.body
    if not isinstance(body, dict) or body.get("success") is not True:
        return None, "shape_drift:success"
    raw_sections, retrieval = body.get("sections"), body.get("retrieval")
    if not isinstance(raw_sections, dict) or not raw_sections:
        return None, "shape_drift:sections"
    if not isinstance(retrieval, dict):
        return None, "shape_drift:retrieval"
    header = body.get("header") if isinstance(body.get("header"), dict) else {}
    hybrid = raw_sections.get("hybrid_retrieval")
    hybrid_body: Optional[Dict[str, Any]] = None
    if isinstance(hybrid, dict):
        try:
            nodes = hybrid.get("nodes")
            if not isinstance(nodes, list):
                raise ShapeDrift("nodes")
            for index, node in enumerate(nodes):
                if not isinstance(node, dict):
                    raise ShapeDrift(f"nodes[{index}]")
                for key in REQUIRED_NODE_KEYS:
                    if key not in node:
                        raise ShapeDrift(f"nodes[{index}].{key}")
        except ShapeDrift as drift:
            return None, f"shape_drift:hybrid_retrieval.{drift.key}"
        hybrid_body = dict(hybrid)
        hybrid_body["pathway"] = {
            "intent_signature": retrieval.get("intent_signature"),
            "wave_id": retrieval.get("wave_id"),
            "edge_count": retrieval.get("pathway_edge_count"),
        }
        for src, dst in (("alpha", "corroboration_alpha"), ("s_top", "s_top"), ("weber_k", "corroboration_weber_k")):
            if retrieval.get(src) is not None and hybrid_body.get(dst) is None:
                hybrid_body[dst] = retrieval[src]
    elif not getattr(args, "no_hybrid", False) and mode in RECORD_MODES + ("topic",):
        return None, "shape_drift:hybrid_retrieval"
    landed: Dict[str, Section] = {}
    for name, value in raw_sections.items():
        landed[ROUTE_SECTION_NAMES.get(name, name)] = Section(ROUTE_SECTION_NAMES.get(name, name), 200, value, 0)
    present = [s for s in SIGNALS if s in (retrieval.get("signals_present") or [])]
    absent = {str(k): str(v) for k, v in (retrieval.get("signals_absent") or {}).items()}
    warnings = [
        f"server:{str(w)[:ROUTE_WARNING_MAX_CHARS]}" for w in (body.get("warnings") or []) if isinstance(w, (str, int, float))
    ]
    return {
        "sections": landed,
        "hybrid_body": hybrid_body,
        "signals": (present, absent),
        "query": str(header.get("query_head") or ""),
        "anchor": str(header.get("anchor") or ""),
        "partial": bool(header.get("partial")),
        "warnings": warnings,
    }, ""


# --- the run ------------------------------------------------------------------


def _fail_digest(
    exit_code: int, status: Any, anomalies: List[str], args: Any, profile: str, key_source: str, posture: str = "unknown", **extra: Any
) -> Tuple[Dict[str, Any], int]:
    digest = build_digest(
        OPERATION,
        False,
        status,
        identity_posture=posture,
        anomalies=anomalies,
        profile=profile,
        key_source=key_source,
        **extra,
    )
    return digest, exit_code


def _record_section_name(mode: str) -> str:
    return "document" if mode == "document" else "record"


def run_compact_context(args: Any, client: Any, *, profile: str, key_source: str) -> Tuple[Dict[str, Any], int]:
    """Compose one compact context. ``client`` is anything with an
    InternalClient-compatible ``request`` (tests pass a fake)."""
    started = time.monotonic()
    top_n = clamp_top_n(args.top_n)
    mode = infer_mode(args.mode, args.record_id, args.document_id, args.query, args.project_id)
    root = context_store.context_root(args.out_dir)
    run_id = context_store.new_ulid()
    directory = context_store.run_dir(root, run_id)
    warnings: List[str] = []
    ca_fields = client.ca_bundle_digest_fields() if hasattr(client, "ca_bundle_digest_fields") else {}

    def tls_failed(status: Any) -> bool:
        return status == elr_tls.TLS_UNRESOLVED_STATUS

    sections: Dict[str, Section] = {}
    record: Dict[str, Any] = {}
    record_id = (args.record_id or "").strip()
    project_id = (args.project_id or "").strip()
    query = (args.query or "").strip()
    anchor = (args.anchor_record_id or "").strip()
    record_type = ""

    # Step 0 -- health first (governance_hash + the transport capability switch).
    health = _timed("health", lambda: _get(client, "health"))
    governance_hash = None
    health_body = health.body if health.ok and isinstance(health.body, dict) else {}
    if health_body:
        governance_hash = health_body.get("governance_hash") or None
    transport = (getattr(args, "transport", None) or TRANSPORT_AUTO).strip().lower()
    route_state: Optional[Dict[str, Any]] = None
    if transport != TRANSPORT_COMPOSE:
        advertised = (health_body.get("tracker_capabilities") or {}).get("compact_context") is True if isinstance(health_body.get("tracker_capabilities"), dict) else False
        if transport == TRANSPORT_ROUTE or advertised:
            if (args.wave_id or "").strip():
                route_reason = "route_does_not_support_wave_id"
            else:
                route_state, route_reason = _try_route(client, args, mode, top_n)
            if route_state is None:
                warnings.append(f"route_fallback:{route_reason}")
                if transport == TRANSPORT_ROUTE:
                    return _fail_digest(
                        EXIT_HYBRID_UNSUPPORTED, 0, ["context_route_unavailable", f"context_route_unavailable:{route_reason}"], args, profile, key_source
                    )
        elif transport == TRANSPORT_AUTO:
            pass  # plane does not advertise the route: Phase 1 composition (composer elr-1)
    results: Dict[str, Section] = {}
    hybrid_body: Optional[Dict[str, Any]] = None
    posture = "internal-key"
    query_sent = False
    anchor_sent = False
    route_signals: Optional[Tuple[List[str], Dict[str, str]]] = None
    composer = COMPOSER_VERSION
    partial_from_route = False
    if route_state is not None:
        composer = COMPOSER_ROUTE
        sections.update(route_state["sections"])
        hybrid_body = route_state["hybrid_body"]
        route_signals = route_state["signals"]
        query = route_state["query"]
        anchor = route_state["anchor"]
        query_sent = bool(query)
        anchor_sent = bool(anchor) and mode != "document"
        partial_from_route = route_state["partial"]
        warnings.extend(route_state["warnings"])
        record_type = ""
    else:
        # Step 1 -- the record (serial: project, type and the derived query come from it).
        if mode in RECORD_MODES:
            classified = elr_batch_get.classify_id(record_id)
            if classified.kind != elr_batch_get.KIND_TRACKER:
                return _fail_digest(EXIT_UNUSABLE, 400, ["unsupported_record_id"], args, profile, key_source)
            record_type = classified.record_type or "task"
            sec = _timed(
                "record",
                lambda: _get(client, "tracker", elr_batch_get.tracker_path(record_type, classified.normalized)),
            )
            if tls_failed(sec.status):
                return _fail_digest(elr_tls.EXIT_CODE_TLS_UNRESOLVED, sec.status, ["tls_ca_bundle_missing"], args, profile, key_source, **ca_fields)
            if not sec.ok:
                posture, anomalies = classify_internal_posture(key_sent=True, status_code=sec.status if isinstance(sec.status, int) else 0)
                return _fail_digest(
                    EXIT_UNUSABLE, sec.status, list(anomalies) + [f"record_fetch_failed_http_{sec.status}"], args, profile, key_source, posture=posture
                )
            sections["record"] = sec
            record = sec.body.get("record") if isinstance(sec.body.get("record"), dict) else sec.body
            project_id = project_id or str(record.get("project_id") or "")
            if not query:
                query = derive_query(record)  # FR-2
            if not anchor:
                anchor = classified.normalized  # FR-2: the record itself anchors the graph signal

        # Step 2 -- independent reads, in parallel.
        tasks: Dict[str, Callable[[], Section]] = {}
        include = lambda flag: not getattr(args, flag, False)  # noqa: E731

        def add(name: str, fn: Callable[[], Tuple[int, Any]]) -> None:
            tasks[name] = lambda: _timed(name, fn)

        if mode in RECORD_MODES:
            if include("no_components") and project_id:
                add("components", lambda: _get(client, "coordination", "/components", {"project_id": project_id, "status": "active"}))
            if include("no_governance"):
                entity = (args.governance_entity or "").strip() or f"tracker.{record_type}"
                add("governance", lambda: _get(client, "governance", "/dictionary", {"entity": entity}))
            if include("no_related_documents"):
                rel_query = {"project_id": project_id, "related": record_id} if project_id else {"related": record_id}
                add("related_documents", lambda: _get(client, "document_direct", "/search", rel_query))
            if project_id:
                add("project", lambda: _get(client, "coordination", f"/projects/{_quote(project_id)}"))
        elif mode == "project":
            if not project_id:
                return _fail_digest(EXIT_UNUSABLE, 400, ["project_id_required"], args, profile, key_source)
            add("project", lambda: _get(client, "coordination", f"/projects/{_quote(project_id)}"))
            if include("no_related_documents"):
                tasks["documents"] = lambda: fetch_project_documents(client, project_id)
            if (args.governance_entity or "").strip() and include("no_governance"):
                add("governance", lambda: _get(client, "governance", "/dictionary", {"entity": args.governance_entity.strip()}))
        elif mode == "document":
            document_id = (args.document_id or "").strip()
            if not document_id:
                return _fail_digest(EXIT_UNUSABLE, 400, ["document_id_required"], args, profile, key_source)
            add("document", lambda: _get(client, "document_direct", f"/{_quote(document_id)}", {"include_content": "true"}))
        elif mode == "topic":
            if not query and not project_id:
                return _fail_digest(EXIT_UNUSABLE, 400, ["topic_requires_query_or_project_id"], args, profile, key_source)
            if project_id:
                add("project", lambda: _get(client, "coordination", f"/projects/{_quote(project_id)}"))
            if include("no_related_documents"):
                doc_query: Dict[str, Any] = {"title": query} if query else {}
                if project_id:
                    doc_query["project_id"] = project_id
                add("documents", lambda: _get(client, "document_direct", "/search", doc_query))
            if project_id and query:
                tasks["reference"] = lambda: fetch_reference(client, project_id, query)
            if (args.governance_entity or "").strip() and include("no_governance"):
                add("governance", lambda: _get(client, "governance", "/dictionary", {"entity": args.governance_entity.strip()}))
        else:
            return _fail_digest(EXIT_UNUSABLE, 400, [f"unknown_mode:{mode}"], args, profile, key_source)

        anchor_sent = bool(anchor) and mode != "document"
        query_sent = bool(query)
        run_hybrid = include("no_hybrid") and (query_sent or anchor_sent) and bool(project_id)
        if run_hybrid:
            hybrid_query: Dict[str, Any] = {
                "search_type": "hybrid",
                "project_id": project_id,
                "query": query or None,
                "anchor_record_id": anchor or None,
                "top_n": top_n,
                "record_type": (args.record_type or None),
                "include_below_threshold": "true" if args.include_below_threshold else None,
                "wave_id": (args.wave_id or None),
            }
            gs_health = _timed("graph_health", lambda: _get(client, "graph_query", "/health"))
            hybrid_compact = bool(gs_health.ok and isinstance(gs_health.body, dict) and gs_health.body.get("hybrid_fields_compact") is True)
            if hybrid_compact:
                hybrid_query["fields"] = "compact"  # ENC-TSK-Q49 projection; hybrid.json keeps what the server returned
            add("hybrid", lambda: _hybrid_get(client, hybrid_query, warnings))

        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(tasks))) as pool:
            futures = {name: pool.submit(fn) for name, fn in tasks.items()}
            results = {name: fut.result() for name, fut in futures.items()}

        # Step 3 -- the hybrid verdict decides the exit code before anything lands.
        if run_hybrid:
            hyb = results.pop("hybrid")
            if tls_failed(hyb.status):
                return _fail_digest(elr_tls.EXIT_CODE_TLS_UNRESOLVED, hyb.status, ["tls_ca_bundle_missing"], args, profile, key_source, **ca_fields)
            if hyb.status in (400, 404):
                return _fail_digest(EXIT_HYBRID_UNSUPPORTED, hyb.status, [ANOMALY_HYBRID_UNSUPPORTED], args, profile, key_source)
            if not hyb.ok:
                posture, anomalies = classify_internal_posture(key_sent=True, status_code=hyb.status if isinstance(hyb.status, int) else 0)
                return _fail_digest(
                    EXIT_UNUSABLE, hyb.status, list(anomalies) + [f"hybrid_call_failed_http_{hyb.status}"], args, profile, key_source, posture=posture
                )
            try:
                validate_hybrid_shape(hyb.body)
            except ShapeDrift as drift:
                return _fail_digest(
                    EXIT_RESPONSE_SHAPE_DRIFT, hyb.status, [ANOMALY_SHAPE_DRIFT, f"{ANOMALY_SHAPE_DRIFT}:{drift.key}"], args, profile, key_source
                )
            hybrid_body = hyb.body
            sections["hybrid"] = hyb
            for key in unexpected_hybrid_keys(hybrid_body):
                warnings.append(f"unexpected_hybrid_key:{key}")
            if hybrid_body.get("success") is False:
                return _fail_digest(EXIT_UNUSABLE, hyb.status, ["hybrid_reported_failure"], args, profile, key_source)

    # Step 4 -- land sections; failed reads become warnings, never an abort.
    partial = partial_from_route
    for name, sec in results.items():
        if not sec.ok:
            partial = True
            warnings.append(f"{name}_unavailable_http_{sec.status}")
            continue
        body = sec.body
        if name == "components" and mode in RECORD_MODES:
            body = filter_components(sec.body, [str(c) for c in (record.get("components") or [])])
        sections[name] = Section(name, sec.status, body, sec.ms)
    if (mode == "project" or (mode == "topic" and (args.domains or ""))) and (args.domains or ""):
        warnings.append("architecture_requires_server_route")

    landed: Dict[str, List[Any]] = {}
    for name, sec in sections.items():
        body = sec.body
        if name == "record" and isinstance(body, dict):
            body = _shape_record_history(body, args)
        size, sha = context_store.write_section(directory, name, body)
        landed[name] = [size, sha[:SECTION_SHA_CHARS]]

    # Step 5 -- ranking rows, ids file, digest.
    nodes: List[Dict[str, Any]] = list(hybrid_body["nodes"]) if hybrid_body else []
    returned = len(nodes)
    ordered = nodes
    if args.order == "fused":
        ordered = sorted(nodes, key=lambda n: n["_fused_rank"])  # server-supplied ranks, not re-scored
    ids_file = None
    ids = [str(n["record_id"]) for n in ordered[:top_n]]
    if hybrid_body is not None:
        ids_file = context_store.write_ids_file(directory, run_id, ids).name  # relative to header.run_dir

    if route_signals is not None:
        present, absent = route_signals
    elif hybrid_body:
        present, absent = signal_posture(hybrid_body, query_sent, anchor_sent)
    else:
        present, absent = [], _no_hybrid_absent(query_sent, anchor_sent)
    pathway = (hybrid_body or {}).get("pathway") or {}
    retrieval: Dict[str, Any] = {
        "composer": composer,
        "signals_present": present,
        "signals_absent": absent,
    }
    if hybrid_body is not None:
        retrieval.update(
            {
                "graph_algorithm": hybrid_body.get("graph_algorithm"),
                "rrf_k": hybrid_body.get("rrf_k") if hybrid_body.get("rrf_k") != DEFAULT_RRF_K else None,
                "below_t3_included": True if hybrid_body.get("include_below_threshold") else None,
                "alpha": hybrid_body.get("corroboration_alpha"),
                "s_top": hybrid_body.get("s_top"),
                "weber_k": hybrid_body.get("corroboration_weber_k"),  # pre-ENC-TSK-Q46 planes only
                "candidates": parse_summary_counts(hybrid_body.get("summary")),
                "embedding_coverage_sample": _coverage_pair(hybrid_body.get("embedding_coverage_sample")),
                "intent_signature": str(pathway.get("intent_signature") or "").replace("sha256:", "")[:INTENT_SIGNATURE_CHARS] or None,
                "wave_id": pathway.get("wave_id") if pathway.get("wave_id") not in (None, "unassigned") else None,
                "pathway_edges": pathway.get("edge_count") or None,
            }
        )
        if retrieval["candidates"] is None:
            warnings.append("summary_candidate_counts_unparsed")
        retrieval = {k: v for k, v in retrieval.items() if v is not None}
    wall_ms = int((time.monotonic() - started) * 1000)
    server_ms = (hybrid_body or {}).get("duration_ms")

    rows = [ranking_row(n) for n in ordered[:top_n]]
    budget = digest_budget_bytes(top_n)

    def assemble(emitted: List[List[Any]]) -> Dict[str, Any]:
        header = {
            "run_id": run_id,
            "mode": mode,
            "anchor": anchor or None,
            "query_head": query[:QUERY_HEAD_CHARS] or None,
            "root": str(root),
            "partial": True if partial else None,
            "truncated": True if len(emitted) < returned else None,
            "wall_ms": wall_ms,
            "server_ms": server_ms,
        }
        header = {k: v for k, v in header.items() if v is not None}
        return build_digest(
            OPERATION,
            True,
            200,
            identity_posture=posture,
            anomalies=[],
            profile=profile,
            key_source=key_source,
            governance_hash=(governance_hash or "")[:GOVERNANCE_HASH_CHARS] or None,
            header=header,
            retrieval=retrieval,
            ranking=emitted if hybrid_body is not None else None,
            sections=landed,
            ids_file=ids_file,
            warnings=warnings or None,
        )

    if args.max_tokens:
        # Explicit inline budget: drop rows from the tail until it fits.
        budget = int(args.max_tokens) * 4
        digest, size = fit_digest(assemble, rows, budget)
        if size > budget:
            warnings.append("digest_over_budget_with_zero_rows")
            digest, size = fit_digest(assemble, [], budget)
    else:
        # Default: every requested row is emitted; the M-3 bound is checked, not enforced by dropping.
        digest = assemble(rows)
        if _stamp_size(digest) > budget:
            warnings.append("digest_over_m3_budget")
            digest = assemble(rows)
            _stamp_size(digest)

    # Step 6 -- measurement and retention (FR-10, FR-11). Neither may fail the run.
    if hybrid_body is not None:
        entry = ledger_entry(
            run_id=run_id,
            mode=mode,
            anchor=anchor,
            profile=profile,
            retrieval=retrieval,
            pathway=pathway,
            ordered=ordered[:top_n],
            digest_bytes=digest["header"]["digest_bytes"],
            wall_ms=wall_ms,
        )
        try:
            context_store.append_ledger(root, entry)
        except (OSError, ValueError) as exc:
            warnings.append(f"ledger_append_failed:{exc.__class__.__name__}")
            digest = assemble(rows)
            _stamp_size(digest)
    try:
        context_store.prune_runs(root, protect=(run_id,))
    except OSError:
        pass
    return digest, 0


def _coverage_pair(sample: Any) -> Optional[List[int]]:
    """embedding_coverage_sample {covered, total_ranked} as [covered, total_ranked]."""
    if isinstance(sample, dict) and "covered" in sample and "total_ranked" in sample:
        return [sample["covered"], sample["total_ranked"]]
    return None


def ledger_entry(
    *,
    run_id: str,
    mode: str,
    anchor: str,
    profile: str,
    retrieval: Dict[str, Any],
    pathway: Dict[str, Any],
    ordered: List[Dict[str, Any]],
    digest_bytes: int,
    wall_ms: int,
) -> Dict[str, Any]:
    """One FR-10 ledger line. Only ids, ranks and counts -- never a key, a
    body or a title. ``ordered`` is the full top_n the server returned (not
    the possibly row-truncated inline digest)."""
    per_signal = []
    for node in ordered:
        ranks = node.get("_per_signal_ranks") or {}
        per_signal.append({_SIGNAL_SHORT[s]: ranks[s] for s in SIGNALS if s in ranks})
    return {
        "ts": context_store.utc_now_iso(),
        "run_id": run_id,
        "mode": mode,
        "anchor": anchor or None,
        "intent_signature": pathway.get("intent_signature"),
        "wave_id": pathway.get("wave_id"),
        "profile": profile,
        "signals_present": retrieval.get("signals_present"),
        "graph_algorithm": retrieval.get("graph_algorithm"),
        "ranked_ids": [str(n["record_id"]) for n in ordered],
        "per_signal_ranks": per_signal,
        "fused_ranks": [n["_fused_rank"] for n in ordered],
        "final_ranks": [n["_final_rank"] for n in ordered],
        "k_corr": [n["_corroboration_count"] for n in ordered],
        "digest_bytes": digest_bytes,
        "wall_ms": wall_ms,
    }


def _no_hybrid_absent(query_sent: bool, anchor_sent: bool) -> Dict[str, str]:
    absent: Dict[str, str] = {}
    if not query_sent:
        absent["vector"] = "no_query"
        absent["keyword"] = "no_query"
    if not anchor_sent:
        absent["graph"] = "no_anchor"
    return absent


def _shape_record_history(record_body: Dict[str, Any], args: Any) -> Dict[str, Any]:
    """--no-recent-history / --history-limit are explicit opt-ins that shape
    the LANDED record's embedded history; without them the body is verbatim."""
    inner = record_body.get("record") if isinstance(record_body.get("record"), dict) else None
    target = inner if inner is not None else record_body
    history = target.get("history")
    if not isinstance(history, list):
        return record_body
    if getattr(args, "no_recent_history", False):
        target = dict(target)
        target.pop("history", None)
    elif getattr(args, "history_limit", None) is not None:
        target = dict(target)
        target["history"] = history[-max(0, int(args.history_limit)) :]
    else:
        return record_body
    if inner is not None:
        shaped = dict(record_body)
        shaped["record"] = target
        return shaped
    return target


def serialize_digest(digest: Dict[str, Any]) -> str:
    return json.dumps(digest, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def fit_digest(
    assemble: Callable[[List[List[Any]]], Dict[str, Any]], rows: List[List[Any]], budget: int
) -> Tuple[Dict[str, Any], int]:
    """Drop rows from the TAIL until the serialized digest fits ``budget``,
    stamping header.digest_bytes with the exact size of what is printed
    (a fixed point: the digit count of the size is part of the size)."""
    emitted = list(rows)
    while True:
        digest = assemble(emitted)
        size = _stamp_size(digest)
        if size <= budget or not emitted:
            return digest, size
        emitted.pop()


def _stamp_size(digest: Dict[str, Any]) -> int:
    header = digest["header"]
    header["digest_bytes"] = 0
    size = len(serialize_digest(digest).encode("utf-8"))
    for _ in range(4):
        header["digest_bytes"] = size
        new_size = len(serialize_digest(digest).encode("utf-8"))
        if new_size == size:
            break
        size = new_size
    return size


# --- CLI ----------------------------------------------------------------------


def _top_n_arg(value: str) -> int:
    try:
        return clamp_top_n(int(value))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"--top-n must be an integer, got {value!r}") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="elr_compact_context",
        description=(
            "ELR compact context: the MCP get_compact_context reads over governed HTTP, "
            "ranked top-N inline, every section landed on disk (GET only)."
        ),
        allow_abbrev=False,
    )
    parser.add_argument("--mode", choices=list(ALL_MODES), default=None, help="Context mode (inferred when omitted).")
    parser.add_argument("--record-id", default=None, help="Tracker record id (record modes).")
    parser.add_argument("--project-id", default=None, help="Project id (required for project/topic; else from the record).")
    parser.add_argument("--document-id", default=None, help="Document id (document mode).")
    parser.add_argument("--query", default=None, help="Retrieval query (derived from title+intent in record modes).")
    parser.add_argument("--anchor-record-id", default=None, help="Graph anchor (defaults to --record-id in record modes).")
    parser.add_argument("--record-type", default=None, help="Restrict hybrid results to one record type.")
    parser.add_argument("--top-n", type=_top_n_arg, default=TOP_N_DEFAULT, help="Ranked rows (default 20, clamped to 1..50).")
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=None,
        help="Inline digest budget in tokens (~4 bytes each); default 256+48*top_n. Tail rows drop first.",
    )
    parser.add_argument("--include-below-threshold", action="store_true", help="Include nodes below the FSRS T3 threshold.")
    parser.add_argument("--history-limit", type=int, default=None, help="Keep only the last N history entries in the landed record.")
    parser.add_argument("--domain", default=None, help="Accepted for MCP parity (code map has no HTTP route).")
    parser.add_argument("--domains", default=None, help="Architecture domains (reported unavailable client-side).")
    parser.add_argument("--governance-entity", default=None, help="Governance dictionary entity (default tracker.<type>).")
    parser.add_argument("--no-code-map", action="store_true", help="Accepted for MCP parity (the code map is never fetched).")
    parser.add_argument("--no-related-documents", action="store_true")
    parser.add_argument("--no-governance", action="store_true")
    parser.add_argument("--no-components", action="store_true")
    parser.add_argument("--no-architecture", action="store_true", help="Accepted for MCP parity.")
    parser.add_argument("--no-recent-history", action="store_true", help="Drop the history array from the landed record.")
    parser.add_argument("--no-hybrid", action="store_true", help="Skip the hybrid retrieval call (no ranking).")
    parser.add_argument("--order", choices=["final", "fused"], default="final", help="Ranking order for rows and the ids file.")
    parser.add_argument(
        "--profile",
        default=elr_profiles.PROFILE_PROD,
        choices=list(elr_profiles.VALID_ENVIRONMENT_PROFILES),
        help="ELR ENVIRONMENT profile (default prod).",
    )
    parser.add_argument("--out-dir", default=None, help="Context root (default ~/.enceladus/context; env ELR_CONTEXT_DIR).")
    parser.add_argument("--wave-id", default=None, help="Wave id forwarded to the intent signature.")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Per-request timeout in seconds.")
    parser.add_argument(
        "--transport",
        choices=[TRANSPORT_AUTO, TRANSPORT_ROUTE, TRANSPORT_COMPOSE],
        default=TRANSPORT_AUTO,
        help="auto: one GET to the context.compact route when /health advertises it, else client composition "
        "(default); route: route only (exit 6 if unavailable); compose: always client composition.",
    )
    parser.add_argument("--json", action="store_true", help="Accepted for CLI parity; output is always one compact JSON line.")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    mode = infer_mode(args.mode, args.record_id, args.document_id, args.query, args.project_id)
    if mode is None:
        parser.error("provide --mode or one of --record-id, --document-id, --query, --project-id")
    if mode in RECORD_MODES and not (args.record_id or "").strip():
        parser.error("--record-id is required for record-oriented modes")

    # FR-9: no credential -> refuse locally, no request (exit 7).
    refusal = elr_identity.credential_refusal(OPERATION, "tracker", args.profile)
    if refusal is not None:
        print(json.dumps(refusal, sort_keys=True))
        return EXIT_CODE_NO_CREDENTIAL

    config = get_profile("internal", environment_profile_name=args.profile)
    client = InternalClient(config, timeout=args.timeout)
    digest, code = run_compact_context(
        args, client, profile=config.environment_profile.name, key_source=elr_identity.internal_key_source()
    )
    print(serialize_digest(digest))
    return code


if __name__ == "__main__":
    sys.exit(main())
