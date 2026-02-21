"""reference_search/lambda_function.py

Lambda API for searching project reference documents stored in S3.
Returns matched snippets with line numbers, section context, and
surrounding lines — minimizing client-side full-document processing.

Routes (via API Gateway proxy):
    GET     /api/v1/reference/search    — search reference doc content
    OPTIONS /api/v1/reference/*          — CORS preflight

Auth:
    Reads ``enceladus_id_token`` cookie from Cookie header.
    Validates JWT using Cognito JWKS (RS256, cached module-level).

Environment variables:
    COGNITO_USER_POOL_ID   us-east-1_b2D0V3E1k
    COGNITO_CLIENT_ID      6q607dk3liirhtecgps7hifmlk
    S3_BUCKET              default: jreese-net
    S3_REFERENCE_PREFIX    default: mobile/v1/reference
    DYNAMODB_REGION        default: us-west-2

Related: DVP-TSK-292, DVP-FTR-052
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote
import urllib.request

import boto3
from botocore.exceptions import ClientError

try:
    import jwt
    from jwt.algorithms import RSAAlgorithm

    _JWT_AVAILABLE = True
except Exception as _jwt_import_err:
    _JWT_AVAILABLE = False
    logging.getLogger().error("jwt import failed: %s", _jwt_import_err)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

S3_BUCKET = os.environ.get("S3_BUCKET", "jreese-net")
S3_REFERENCE_PREFIX = os.environ.get("S3_REFERENCE_PREFIX", "mobile/v1/reference")
COGNITO_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "")
COGNITO_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID", "")
CORS_ORIGIN = "https://jreese.net"

MAX_RESULTS_CAP = 100
MAX_CONTEXT_LINES = 10
DEFAULT_CONTEXT_LINES = 2
DEFAULT_MAX_RESULTS = 20
MAX_QUERY_LENGTH = 500

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Module-level caches
# ---------------------------------------------------------------------------

_jwks_cache: Dict[str, Any] = {}
_jwks_fetched_at: float = 0.0
_JWKS_TTL = 3600.0

# ---------------------------------------------------------------------------
# JWT / Auth (mirrors document_api pattern)
# ---------------------------------------------------------------------------


def _get_jwks() -> Dict[str, Any]:
    global _jwks_cache, _jwks_fetched_at
    now = time.time()
    if _jwks_cache and (now - _jwks_fetched_at) < _JWKS_TTL:
        return _jwks_cache
    if not COGNITO_USER_POOL_ID:
        raise ValueError("COGNITO_USER_POOL_ID not set")
    region = COGNITO_USER_POOL_ID.split("_")[0]
    url = (
        f"https://cognito-idp.{region}.amazonaws.com/"
        f"{COGNITO_USER_POOL_ID}/.well-known/jwks.json"
    )
    with urllib.request.urlopen(url, timeout=5) as resp:
        data = json.loads(resp.read())
    new_cache: Dict[str, Any] = {}
    for key_data in data.get("keys", []):
        kid = key_data["kid"]
        if not _JWT_AVAILABLE:
            new_cache[kid] = key_data
        else:
            new_cache[kid] = RSAAlgorithm.from_jwk(json.dumps(key_data))
    _jwks_cache = new_cache
    _jwks_fetched_at = now
    return _jwks_cache


def _verify_token(token: str) -> Dict[str, Any]:
    if not _JWT_AVAILABLE:
        raise ValueError("JWT library not available in Lambda package")
    try:
        header = jwt.get_unverified_header(token)
    except Exception as exc:
        raise ValueError(f"Invalid token header: {exc}") from exc
    kid = header.get("kid")
    alg = header.get("alg", "RS256")
    if alg != "RS256":
        raise ValueError(f"Unexpected token algorithm: {alg}")
    keys = _get_jwks()
    pub_key = keys.get(kid)
    if pub_key is None:
        raise ValueError("Token key ID not found in JWKS")
    try:
        claims = jwt.decode(
            token,
            pub_key,
            algorithms=["RS256"],
            audience=COGNITO_CLIENT_ID,
            options={"verify_exp": True},
        )
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired. Please sign in again.")
    except jwt.InvalidAudienceError:
        raise ValueError("Token audience mismatch.")
    except jwt.PyJWTError as exc:
        raise ValueError(f"Token validation failed: {exc}") from exc
    return claims


def _extract_token(event: Dict) -> Optional[str]:
    headers = event.get("headers") or {}
    cookie_header = headers.get("cookie") or headers.get("Cookie") or ""
    cookie_parts: List[str] = []

    if cookie_header:
        cookie_parts.extend(
            part.strip() for part in cookie_header.split(";") if part.strip()
        )

    event_cookies = event.get("cookies") or []
    if isinstance(event_cookies, list):
        cookie_parts.extend(
            part.strip()
            for part in event_cookies
            if isinstance(part, str) and part.strip()
        )
    elif isinstance(event_cookies, str) and event_cookies.strip():
        cookie_parts.append(event_cookies.strip())

    for part in cookie_parts:
        if not part.startswith("enceladus_id_token="):
            continue
        return unquote(part[len("enceladus_id_token=") :])
    return None


def _authenticate(event: Dict) -> Tuple[Optional[Dict], Optional[Dict]]:
    """Authenticate request. Returns (claims, None) or (None, error_response)."""
    token = _extract_token(event)
    if not token:
        return None, _error(401, "Authentication required. Please sign in.")
    try:
        claims = _verify_token(token)
        return claims, None
    except ValueError as exc:
        logger.warning("auth failed: %s", exc)
        return None, _error(401, str(exc))


# ---------------------------------------------------------------------------
# AWS clients (lazy singletons)
# ---------------------------------------------------------------------------

_s3 = None


def _get_s3():
    global _s3
    if _s3 is None:
        _s3 = boto3.client("s3")
    return _s3


# ---------------------------------------------------------------------------
# Response helpers (mirrors document_api / deploy_intake pattern)
# ---------------------------------------------------------------------------


def _cors_headers() -> Dict[str, str]:
    return {
        "Access-Control-Allow-Origin": CORS_ORIGIN,
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Cookie",
        "Access-Control-Allow-Credentials": "true",
    }


def _response(status_code: int, body: Any) -> Dict:
    return {
        "statusCode": status_code,
        "headers": {**_cors_headers(), "Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def _error(status_code: int, message: str, **extra: Any) -> Dict:
    code = str(extra.pop("code", "") or "").strip().upper()
    if not code:
        if status_code == 400:
            code = "INVALID_INPUT"
        elif status_code == 401:
            code = "PERMISSION_DENIED"
        elif status_code == 404:
            code = "NOT_FOUND"
        elif status_code == 409:
            code = "CONFLICT"
        elif status_code == 429:
            code = "RATE_LIMITED"
        elif status_code >= 500:
            code = "INTERNAL_ERROR"
        else:
            code = "INTERNAL_ERROR"
    retryable = bool(extra.pop("retryable", status_code >= 500))
    details = dict(extra)
    payload: Dict[str, Any] = {
        "success": False,
        "error": message,
        "error_envelope": {
            "code": code,
            "message": message,
            "retryable": retryable,
            "details": details,
        },
    }
    payload.update(details)
    return _response(status_code, payload)


# ---------------------------------------------------------------------------
# S3 reference document fetch
# ---------------------------------------------------------------------------


def _fetch_reference_doc(project_id: str) -> Tuple[Optional[str], Dict[str, Any]]:
    """Fetch a reference document from S3.

    Returns (content, metadata) on success or (None, error_info) on failure.
    """
    s3_key = f"{S3_REFERENCE_PREFIX}/{project_id}.md"
    s3 = _get_s3()
    try:
        resp = s3.get_object(Bucket=S3_BUCKET, Key=s3_key)
        content = resp["Body"].read().decode("utf-8")
        last_modified = resp.get("LastModified")
        last_modified_str = (
            last_modified.strftime("%Y-%m-%dT%H:%M:%SZ") if last_modified else None
        )
        metadata = {
            "total_lines": len(content.splitlines()),
            "last_modified": last_modified_str,
            "s3_key": s3_key,
        }
        return content, metadata
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("NoSuchKey", "404"):
            return None, {
                "error": f"Reference document not found for project: {project_id}",
                "s3_key": s3_key,
            }
        raise


# ---------------------------------------------------------------------------
# Search algorithm
# ---------------------------------------------------------------------------


def _build_section_index(lines: List[str]) -> List[Tuple[int, str]]:
    """Build an ordered list of (line_number, heading_text) for all headings.

    Line numbers are 1-indexed.  Headings are stored with their markdown
    prefix (e.g. ``## Architecture``).
    """
    sections: List[Tuple[int, str]] = []
    for idx, line in enumerate(lines, start=1):
        if re.match(r"^#{1,6}\s+", line):
            sections.append((idx, line.rstrip()))
    return sections


def _find_section_for_line(
    line_num: int, section_index: List[Tuple[int, str]]
) -> Tuple[int, str]:
    """Return the nearest heading at or above *line_num*.

    Returns (section_line, section_heading) or (0, "") if no section exists
    above the given line.
    """
    result_line = 0
    result_heading = ""
    for sec_line, sec_heading in section_index:
        if sec_line <= line_num:
            result_line = sec_line
            result_heading = sec_heading
        else:
            break
    return result_line, result_heading


def _search_content(
    content: str,
    query: str,
    *,
    is_regex: bool = False,
    case_sensitive: bool = False,
    context_lines: int = DEFAULT_CONTEXT_LINES,
    max_results: int = DEFAULT_MAX_RESULTS,
    section_filter: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Search *content* for *query* and return snippet dicts.

    Each snippet contains the matched line, surrounding context, the
    enclosing section heading, and match-position offsets within the line.
    """
    lines = content.splitlines()
    total = len(lines)

    # Compile the search pattern
    flags = 0 if case_sensitive else re.IGNORECASE
    if is_regex:
        pattern = re.compile(query, flags)
    else:
        pattern = re.compile(re.escape(query), flags)

    # Compile optional section filter
    section_pat: Optional[re.Pattern] = None
    if section_filter:
        section_pat = re.compile(section_filter, re.IGNORECASE)

    section_index = _build_section_index(lines)

    snippets: List[Dict[str, Any]] = []

    for idx, line in enumerate(lines):
        line_num = idx + 1  # 1-indexed

        matches = list(pattern.finditer(line))
        if not matches:
            continue

        # Find enclosing section
        sec_line, sec_heading = _find_section_for_line(line_num, section_index)

        # Apply section filter
        if section_pat and not section_pat.search(sec_heading):
            continue

        # Context window (clamped to document bounds)
        ctx_start = max(0, idx - context_lines)
        ctx_end = min(total, idx + context_lines + 1)

        snippet: Dict[str, Any] = {
            "line_number": line_num,
            "section": sec_heading,
            "section_line": sec_line,
            "context_before": lines[ctx_start:idx],
            "matched_line": line,
            "context_after": lines[idx + 1 : ctx_end],
            "match_positions": [[m.start(), m.end()] for m in matches],
        }
        snippets.append(snippet)

        if len(snippets) >= max_results:
            break

    return snippets


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------


def _handle_search(event: Dict, claims: Dict) -> Dict:
    """Handle ``GET /api/v1/reference/search``."""
    qs = event.get("queryStringParameters") or {}

    # --- required params ---
    project_id = qs.get("project", "").strip()
    query = qs.get("query", "").strip()

    if not project_id:
        return _error(400, "Query parameter 'project' is required.")
    if not query:
        return _error(400, "Query parameter 'query' is required.")
    if len(query) > MAX_QUERY_LENGTH:
        return _error(400, f"Query exceeds maximum length of {MAX_QUERY_LENGTH} characters.")

    # --- optional params ---
    is_regex = qs.get("regex", "false").lower() == "true"
    case_sensitive = qs.get("case_sensitive", "false").lower() == "true"

    try:
        context_lines = int(qs.get("context_lines", str(DEFAULT_CONTEXT_LINES)))
    except ValueError:
        return _error(400, "Parameter 'context_lines' must be an integer.")
    context_lines = max(0, min(context_lines, MAX_CONTEXT_LINES))

    try:
        max_results = int(qs.get("max_results", str(DEFAULT_MAX_RESULTS)))
    except ValueError:
        return _error(400, "Parameter 'max_results' must be an integer.")
    max_results = max(1, min(max_results, MAX_RESULTS_CAP))

    section_filter = qs.get("section")

    # --- fetch document ---
    content, meta = _fetch_reference_doc(project_id)
    if content is None:
        return _error(404, meta["error"], s3_key=meta.get("s3_key", ""))

    # --- search ---
    try:
        snippets = _search_content(
            content,
            query,
            is_regex=is_regex,
            case_sensitive=case_sensitive,
            context_lines=context_lines,
            max_results=max_results,
            section_filter=section_filter,
        )
    except re.error as exc:
        return _error(400, f"Invalid regex pattern: {exc}")

    return _response(
        200,
        {
            "success": True,
            "project_id": project_id,
            "query": query,
            "search_mode": "regex" if is_regex else "text",
            "match_count": len(snippets),
            "snippets": snippets,
            "document_info": meta,
        },
    )


# ---------------------------------------------------------------------------
# Lambda entry point
# ---------------------------------------------------------------------------


def lambda_handler(event: Dict, context: Any) -> Dict:
    method = (
        (event.get("requestContext") or {}).get("http", {}).get("method")
        or event.get("httpMethod", "")
    ).upper()
    raw_path = event.get("rawPath") or event.get("path", "")

    logger.info("reference_search: %s %s", method, raw_path)

    # CORS preflight
    if method == "OPTIONS":
        return {"statusCode": 204, "headers": _cors_headers(), "body": ""}

    # Authenticate
    claims, auth_err = _authenticate(event)
    if auth_err:
        return auth_err

    # Route
    if method == "GET" and "reference" in raw_path and "search" in raw_path:
        return _handle_search(event, claims)

    return _error(404, f"Route not found: {method} {raw_path}")
