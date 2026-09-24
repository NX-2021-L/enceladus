"""OpenSearch keyword signal + within-search facets for hybrid graphsearch (ENC-TSK-L43).

Reads exclusively via the records_read alias. When OpenSearch is unreachable the
caller should fall back to Neo4j keyword ranks and feed/corpus facets.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

READ_ALIAS = os.environ.get("OPENSEARCH_READ_ALIAS", "records_read")
OPENSEARCH_ENDPOINT = os.environ.get("OPENSEARCH_ENDPOINT", "").strip()
OPENSEARCH_SECRET_NAME = os.environ.get("OPENSEARCH_SECRET_NAME", "").strip()
OPENSEARCH_USERNAME = os.environ.get("OPENSEARCH_USERNAME", "query").strip() or "query"
OPENSEARCH_PASSWORD = os.environ.get("OPENSEARCH_PASSWORD", "").strip()
FEED_API_BASE = os.environ.get("FEED_API_BASE", "https://enceladus-gamma.jreese.net/api/v1/feed").rstrip("/")
COORDINATION_INTERNAL_API_KEY = os.environ.get("COORDINATION_INTERNAL_API_KEY", "").strip()

SSL_CONTEXT = ssl.create_default_context()
SSL_CONTEXT.check_hostname = False
SSL_CONTEXT.verify_mode = ssl.CERT_NONE

_secrets_client = None
_cached_password: Optional[str] = None
_cached_username: Optional[str] = None

_FACET_FIELDS = ("project_id", "record_type", "status", "priority")

_TEXT_FIELDS = [
    "title",
    "title._2gram",
    "title._3gram",
    "description",
    "description._2gram",
    "description._3gram",
    "body",
    "body._2gram",
    "body._3gram",
]

_PREFIX_FIELDS = [
    "title",
    "title._2gram",
    "title._3gram",
    "description",
    "description._2gram",
    "description._3gram",
]


def opensearch_configured() -> bool:
    return bool(OPENSEARCH_ENDPOINT)


def _get_secrets_client():
    global _secrets_client
    if _secrets_client is None:
        import boto3

        _secrets_client = boto3.client("secretsmanager", region_name=os.environ.get("SECRETS_REGION", "us-west-2"))
    return _secrets_client


def _get_credentials() -> Tuple[str, str]:
    global _cached_password, _cached_username
    if _cached_password is not None:
        return _cached_username or OPENSEARCH_USERNAME, _cached_password
    if OPENSEARCH_PASSWORD:
        _cached_password = OPENSEARCH_PASSWORD
        _cached_username = OPENSEARCH_USERNAME
        return _cached_username, _cached_password
    if not OPENSEARCH_SECRET_NAME:
        raise RuntimeError("OPENSEARCH_SECRET_NAME is not configured")
    resp = _get_secrets_client().get_secret_value(SecretId=OPENSEARCH_SECRET_NAME)
    payload = json.loads(resp["SecretString"])
    password = payload.get("password") or payload.get("admin_password")
    if not password:
        raise RuntimeError(f"Secret {OPENSEARCH_SECRET_NAME} missing password key")
    _cached_password = str(password)
    _cached_username = str(payload.get("username") or OPENSEARCH_USERNAME)
    return _cached_username, _cached_password


def opensearch_request(method: str, path: str, body: Optional[Any] = None) -> Tuple[int, Any]:
    if not OPENSEARCH_ENDPOINT:
        raise RuntimeError("OPENSEARCH_ENDPOINT is not configured")
    url = f"{OPENSEARCH_ENDPOINT}{path}"
    data = None
    if isinstance(body, bytes):
        # ENC-TSK-M39: msearch's ndjson bodies are pre-built by the caller
        # (a single json.dumps per header/query line, joined with newlines) --
        # re-serializing here would double-encode and raise "Object of type
        # bytes is not JSON serializable".
        data = body
    elif isinstance(body, str):
        data = body.encode("utf-8")
    elif body is not None:
        data = json.dumps(body).encode("utf-8")
    username, password = _get_credentials()
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    auth = base64.b64encode(f"{username}:{password}".encode()).decode()
    req.add_header("Authorization", f"Basic {auth}")
    try:
        with urllib.request.urlopen(req, context=SSL_CONTEXT, timeout=8) as resp:
            raw = resp.read()
            parsed = json.loads(raw) if raw else {}
            return resp.status, parsed
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        parsed = json.loads(raw) if raw else {}
        return exc.code, parsed


def record_id_from_hit(hit: Dict[str, Any]) -> Optional[str]:
    doc_id = str(hit.get("_id") or "").strip()
    if doc_id.count("#") >= 2:
        return doc_id.split("#", 2)[2]
    source = hit.get("_source") or {}
    project_id = str(source.get("project_id") or "").strip()
    record_type = str(source.get("record_type") or "").strip()
    if project_id and record_type:
        return doc_id.split("#")[-1] if "#" in doc_id else doc_id
    return doc_id or None


def _build_search_body(
    project_id: str,
    query_text: str,
    *,
    top_n: int,
    record_type_filter: Optional[str] = None,
    include_facets: bool = True,
) -> Dict[str, Any]:
    filters: List[Dict[str, Any]] = [{"term": {"project_id": project_id}}]
    if record_type_filter:
        filters.append({"term": {"record_type": record_type_filter.lower()}})

    should_clauses: List[Dict[str, Any]] = [
        {
            "multi_match": {
                "query": query_text,
                "fields": _TEXT_FIELDS,
                "type": "best_fields",
                "fuzziness": "AUTO",
            }
        },
        {
            "multi_match": {
                "query": query_text,
                "fields": _PREFIX_FIELDS,
                "type": "bool_prefix",
            }
        },
    ]

    body: Dict[str, Any] = {
        "size": top_n,
        "query": {
            "bool": {
                "filter": filters,
                "should": should_clauses,
                "minimum_should_match": 1,
            }
        },
    }
    if include_facets:
        body["size"] = top_n
        body["aggs"] = {
            field: {"terms": {"field": field, "size": 50}}
            for field in _FACET_FIELDS
        }
    return body


def _parse_facet_aggs(aggregations: Dict[str, Any]) -> Dict[str, Dict[str, int]]:
    facets: Dict[str, Dict[str, int]] = {}
    for field in _FACET_FIELDS:
        buckets = (aggregations.get(field) or {}).get("buckets") or []
        facets[field] = {
            str(bucket.get("key")): int(bucket.get("doc_count") or 0)
            for bucket in buckets
            if bucket.get("key") is not None
        }
    return facets


def hybrid_keyword_ranks(
    project_id: str,
    query_text: str,
    top_n: int,
    record_type_filter: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, int]], Optional[str]]:
    """Return (keyword ranks, facets, error_message). error_message set on failure."""
    if not query_text or not opensearch_configured():
        return [], {}, "opensearch_not_configured" if not opensearch_configured() else None

    body = _build_search_body(
        project_id,
        query_text,
        top_n=top_n,
        record_type_filter=record_type_filter,
        include_facets=True,
    )
    try:
        status, resp = opensearch_request("POST", f"/{READ_ALIAS}/_search", body)
    except Exception as exc:
        logger.warning("[WARNING] OpenSearch keyword search failed: %s", exc)
        return [], {}, str(exc)

    if status >= 400 or resp.get("error"):
        message = str(resp.get("error") or status)
        logger.warning("[WARNING] OpenSearch keyword search HTTP %s: %s", status, message)
        return [], {}, message

    hits = (resp.get("hits") or {}).get("hits") or []
    ranked: List[Dict[str, Any]] = []
    for idx, hit in enumerate(hits, start=1):
        rid = record_id_from_hit(hit)
        if not rid:
            continue
        score = float((hit.get("_score") or 0.0))
        ranked.append({"record_id": rid, "score": score, "rank": idx})

    facets = _parse_facet_aggs(resp.get("aggregations") or {})
    return ranked, facets, None


def feed_selection_msearch(
    project_ids: List[str],
    caps: Dict[str, int],
    page_size: Optional[int] = None,
    before: Optional[str] = None,
) -> Tuple[Dict[str, Any], Optional[str]]:
    """Top-N most-recently-updated record IDs per (project_id, record_type).

    ENC-TSK-M39: the selection-tier query behind feed_query's OpenSearch fast
    path. feed_query is not VPC-attached, so it invokes graph_query_api
    (action='feed_selection') as a proxy rather than querying OpenSearch
    directly; this is the query builder + response parser that call uses.

    One ``_msearch`` round trip covers every (project_id, record_type) pair --
    each header/query line requests ``_id`` sorted by updated_at desc.

    Two modes:
      * LEGACY (page_size is None) -- each sub-query is capped at
        caps[record_type] and returns only ``_id``; the result is
        ({"{project_id}#{record_type}": [bare_id, ...]}, error). Preserved
        byte-for-byte for any caller not on the ENC-TSK-M76 upstream-cap path.
      * PAGE-CAP (page_size given, ENC-TSK-M76) -- each sub-query fetches
        ``page_size + 1`` hits WITH their ``updated_at`` (needed so feed_query
        can merge every pair into one global (updated_at desc) order and cap
        to exactly the page), and, when a ``before`` cursor bound is supplied,
        adds ``range: updated_at <= before`` so deep-page selection stays
        correct while still fetching only page_size+1 per pair. Result is
        ({"{project_id}#{record_type}": [{"id": bare_id, "updated_at": ..}]}, error).
        Fetching page_size+1 per (pair) guarantees the union contains the true
        global top-(page_size+1) most-recent records after the cursor, since
        the target page is at most page_size records.

    error_message is set (dict empty) on any failure so the caller can fall
    back to its DDB fan-out.
    """
    if not project_ids or not caps or not opensearch_configured():
        return {}, "opensearch_not_configured" if not opensearch_configured() else "no_input"

    page_mode = page_size is not None
    per_pair_size = max(1, int(page_size) + 1) if page_mode else None

    pairs = [(pid, rtype) for pid in project_ids for rtype in caps]
    lines: List[str] = []
    for pid, rtype in pairs:
        query_filter: List[Dict[str, Any]] = [
            {"term": {"project_id": pid}},
            {"term": {"record_type": rtype}},
        ]
        if page_mode and before:
            query_filter.append({"range": {"updated_at": {"lte": before}}})
        header = {
            "size": per_pair_size if page_mode else max(1, int(caps[rtype])),
            "_source": ["updated_at"] if page_mode else False,
            "sort": [{"updated_at": "desc"}],
            "query": {"bool": {"filter": query_filter}},
        }
        lines.append(json.dumps({"index": READ_ALIAS}))
        lines.append(json.dumps(header))
    body = "\n".join(lines) + "\n"

    try:
        status, resp = opensearch_request("POST", "/_msearch", body.encode("utf-8"))
    except Exception as exc:
        logger.warning("[WARNING] OpenSearch feed_selection msearch failed: %s", exc)
        return {}, str(exc)

    if status >= 400 or resp.get("error"):
        message = str(resp.get("error") or status)
        logger.warning("[WARNING] OpenSearch feed_selection msearch HTTP %s: %s", status, message)
        return {}, message

    responses = resp.get("responses") or []
    if len(responses) != len(pairs):
        return {}, f"msearch response count mismatch: expected {len(pairs)} got {len(responses)}"

    selection: Dict[str, Any] = {}
    for (pid, rtype), sub_resp in zip(pairs, responses):
        if sub_resp.get("error"):
            logger.warning(
                "[WARNING] OpenSearch feed_selection sub-query failed project=%s type=%s: %s",
                pid, rtype, sub_resp.get("error"),
            )
            continue
        hits = (sub_resp.get("hits") or {}).get("hits") or []
        if page_mode:
            ranked: List[Dict[str, str]] = []
            for hit in hits:
                doc_id = str(hit.get("_id") or "")
                if doc_id.count("#") < 2:
                    continue
                bare_id = doc_id.split("#", 2)[2]
                updated_at = str((hit.get("_source") or {}).get("updated_at") or "")
                ranked.append({"id": bare_id, "updated_at": updated_at})
            if ranked:
                selection[f"{pid}#{rtype}"] = ranked
        else:
            bare_ids: List[str] = []
            for hit in hits:
                doc_id = str(hit.get("_id") or "")
                if doc_id.count("#") >= 2:
                    bare_ids.append(doc_id.split("#", 2)[2])
            if bare_ids:
                selection[f"{pid}#{rtype}"] = bare_ids

    return selection, None


def fetch_feed_corpus_facets(
    *,
    project_id: str,
    query_text: str = "",
    record_type_filter: Optional[str] = None,
) -> Tuple[Dict[str, Dict[str, int]], Optional[str]]:
    """Circuit-breaker facet fallback via GET /feed/corpus (ENC-TSK-L23)."""
    if not COORDINATION_INTERNAL_API_KEY:
        return {}, "feed_internal_key_missing"

    params: Dict[str, str] = {"limit": "1", "project_id": project_id}
    if query_text:
        params["q"] = query_text
    if record_type_filter:
        params["record_type"] = record_type_filter

    url = f"{FEED_API_BASE}/corpus?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, method="GET")
    req.add_header("X-Coordination-Internal-Key", COORDINATION_INTERNAL_API_KEY)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            payload = json.loads(resp.read())
    except Exception as exc:
        logger.warning("[WARNING] feed/corpus facet fallback failed: %s", exc)
        return {}, str(exc)

    facets = payload.get("facets")
    if not isinstance(facets, dict):
        return {}, "feed_corpus_missing_facets"
    normalized: Dict[str, Dict[str, int]] = {}
    for field in _FACET_FIELDS:
        raw = facets.get(field)
        if isinstance(raw, dict):
            normalized[field] = {str(k): int(v) for k, v in raw.items()}
    return normalized, None
