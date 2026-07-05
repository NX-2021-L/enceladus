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
    if body is not None:
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
