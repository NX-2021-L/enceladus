"""document_api/lambda_function.py

Lambda API for agent document management on Enceladus.
Handles PUT (upload), GET (retrieve), PATCH (edit), and search operations
for .md documents stored on S3 with metadata in DynamoDB.

Routes (via API Gateway proxy):
    PUT    /api/v1/documents                         — upload new document
    GET    /api/v1/documents/{documentId}             — retrieve document + content
    GET    /api/v1/documents?project={id}             — list documents by project
    PATCH  /api/v1/documents/{documentId}             — edit document
    GET    /api/v1/documents/search?<params>          — search documents
    OPTIONS /api/v1/documents[/*]                     — CORS preflight

Auth:
    Reads `enceladus_id_token` cookie from Cookie header.
    Validates JWT using Cognito JWKS (RS256, cached module-level).
    Optional service-to-service auth via X-Coordination-Internal-Key when
    DOCUMENT_API_INTERNAL_API_KEY (or COORDINATION_INTERNAL_API_KEY) is set.

Environment variables:
    COGNITO_USER_POOL_ID   us-east-1_b2D0V3E1k
    COGNITO_CLIENT_ID      6q607dk3liirhtecgps7hifmlk
    DOCUMENTS_TABLE        default: documents
    PROJECTS_TABLE         default: projects
    S3_BUCKET              default: jreese-net
    S3_PREFIX              default: agent-documents
    DYNAMODB_REGION        default: us-west-2
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import logging
import os
import re
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote
import urllib.request

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

try:
    import jwt
    from jwt.algorithms import RSAAlgorithm
    _JWT_AVAILABLE = True
except Exception as _jwt_import_err:
    _JWT_AVAILABLE = False
    logging.getLogger().error("jwt import failed: %s", _jwt_import_err)


def _normalize_api_keys(*raw_values: str) -> tuple[str, ...]:
    """Return deduplicated, non-empty key values from scalar/csv env sources."""
    keys: list[str] = []
    seen: set[str] = set()
    for raw in raw_values:
        if not raw:
            continue
        for part in str(raw).split(","):
            key = part.strip()
            if not key or key in seen:
                continue
            seen.add(key)
            keys.append(key)
    return tuple(keys)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DOCUMENTS_TABLE = os.environ.get("DOCUMENTS_TABLE", "documents")
PROJECTS_TABLE = os.environ.get("PROJECTS_TABLE", "projects")
TRACKER_TABLE = os.environ.get("TRACKER_TABLE", "devops-project-tracker")
DYNAMODB_REGION = os.environ.get("DYNAMODB_REGION", "us-west-2")
S3_BUCKET = os.environ.get("S3_BUCKET", "jreese-net")
S3_PREFIX = os.environ.get("S3_PREFIX", "agent-documents")
S3_REFERENCE_PREFIX = os.environ.get("S3_REFERENCE_PREFIX", "mobile/v1/reference")
S3_GOVERNANCE_PREFIX = os.environ.get("S3_GOVERNANCE_PREFIX", "governance/live")
COGNITO_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "")
COGNITO_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID", "")
DOCUMENT_API_INTERNAL_API_KEY = os.environ.get(
    "DOCUMENT_API_INTERNAL_API_KEY",
    os.environ.get(
        "COORDINATION_INTERNAL_API_KEY",
        os.environ.get(
            "ENCELADUS_COORDINATION_API_INTERNAL_API_KEY",
            os.environ.get("ENCELADUS_COORDINATION_INTERNAL_API_KEY", ""),
        ),
    ),
)
DOCUMENT_API_INTERNAL_API_KEY_PREVIOUS = os.environ.get(
    "DOCUMENT_API_INTERNAL_API_KEY_PREVIOUS",
    os.environ.get(
        "COORDINATION_INTERNAL_API_KEY_PREVIOUS",
        os.environ.get("ENCELADUS_COORDINATION_INTERNAL_API_KEY_PREVIOUS", ""),
    ),
)
DOCUMENT_API_INTERNAL_API_KEYS = _normalize_api_keys(
    os.environ.get("DOCUMENT_API_INTERNAL_API_KEYS", ""),
    os.environ.get("ENCELADUS_COORDINATION_API_INTERNAL_API_KEYS", ""),
    os.environ.get("ENCELADUS_COORDINATION_INTERNAL_API_KEYS", ""),
    os.environ.get("COORDINATION_INTERNAL_API_KEYS", ""),
    DOCUMENT_API_INTERNAL_API_KEY,
    DOCUMENT_API_INTERNAL_API_KEY_PREVIOUS,
)
_INTERNAL_SCOPE_MAP_RAW = (
    os.environ.get("COORDINATION_INTERNAL_API_KEY_SCOPES", "")
    or os.environ.get("ENCELADUS_INTERNAL_API_KEY_SCOPES", "")
).strip()
GOVERNANCE_PROJECT_ID = os.environ.get("GOVERNANCE_PROJECT_ID", "devops")
GOVERNANCE_KEYWORD = os.environ.get("GOVERNANCE_KEYWORD", "governance-file").strip().lower()
PROJECT_REFERENCE_KEYWORD = os.environ.get("PROJECT_REFERENCE_KEYWORD", "project-reference").strip().lower()
SYNC_CREATED_BY = "document-api-sync"
CORS_ORIGIN = "https://jreese.net"
MAX_CONTENT_SIZE = 1_048_576  # 1 MB max document content
MAX_TITLE_LENGTH = 500
MAX_DESCRIPTION_LENGTH = 5000
MAX_KEYWORDS = 50
MAX_RELATED_ITEMS = 100
PAGE_SIZE = 50
MAX_COMPLIANCE_WARNINGS = 25
MIN_COMPLIANCE_SCORE = int(os.environ.get("MIN_COMPLIANCE_SCORE", "0"))
ALLOWED_FILE_EXTENSIONS = {".md", ".markdown"}

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

_project_cache: Dict[str, bool] = {}
_project_cache_at: float = 0.0
_PROJECT_CACHE_TTL = 300.0


def _parse_internal_scope_map(raw: str) -> Dict[str, set[str]]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("Invalid COORDINATION_INTERNAL_API_KEY_SCOPES JSON; ignoring scoped auth map")
        return {}
    if not isinstance(parsed, dict):
        return {}
    out: Dict[str, set[str]] = {}
    for key, value in parsed.items():
        token = str(key or "").strip()
        if not token:
            continue
        scopes: set[str] = set()
        if isinstance(value, list):
            items = value
        else:
            items = str(value).split(",")
        for item in items:
            scope = str(item or "").strip().lower()
            if scope:
                scopes.add(scope)
        if scopes:
            out[token] = scopes
    return out


INTERNAL_API_KEY_SCOPES = _parse_internal_scope_map(_INTERNAL_SCOPE_MAP_RAW)


def _scope_match(granted: str, required: str) -> bool:
    if granted in {"*", "all"}:
        return True
    if granted == required:
        return True
    if granted.endswith("*"):
        return required.startswith(granted[:-1])
    return False


def _internal_key_has_scopes(internal_key: str, required_scopes: Optional[List[str]]) -> bool:
    if not required_scopes:
        return True
    if not INTERNAL_API_KEY_SCOPES:
        return True
    granted = INTERNAL_API_KEY_SCOPES.get(internal_key) or INTERNAL_API_KEY_SCOPES.get("*") or set()
    if not granted:
        return False
    for required in required_scopes:
        req = str(required or "").strip().lower()
        if req and not any(_scope_match(g, req) for g in granted):
            return False
    return True

# ---------------------------------------------------------------------------
# JWT / Auth (identical pattern to tracker_mutation)
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
            token, pub_key, algorithms=["RS256"],
            audience=COGNITO_CLIENT_ID, options={"verify_exp": True},
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
        cookie_parts.extend(part.strip() for part in cookie_header.split(";") if part.strip())

    # API Gateway HTTP API payload v2 may place cookies here instead of headers.cookie.
    event_cookies = event.get("cookies") or []
    if isinstance(event_cookies, list):
        cookie_parts.extend(part.strip() for part in event_cookies if isinstance(part, str) and part.strip())
    elif isinstance(event_cookies, str) and event_cookies.strip():
        cookie_parts.append(event_cookies.strip())

    for part in cookie_parts:
        if not part.startswith("enceladus_id_token="):
            continue
        return unquote(part[len("enceladus_id_token="):])
    return None


def _authenticate(event: Dict, required_scopes: Optional[List[str]] = None) -> Tuple[Optional[Dict], Optional[Dict]]:
    """Authenticate request. Returns (claims, None) or (None, error_response)."""
    headers = event.get("headers") or {}
    if DOCUMENT_API_INTERNAL_API_KEYS:
        internal_key = (
            headers.get("x-coordination-internal-key")
            or headers.get("X-Coordination-Internal-Key")
            or ""
        )
        if internal_key and internal_key in DOCUMENT_API_INTERNAL_API_KEYS:
            if not _internal_key_has_scopes(internal_key, required_scopes):
                return None, _error(403, "Forbidden: internal key scope is insufficient for this operation.")
            return {"auth_mode": "internal-key", "sub": "internal-key"}, None

    cookie_header = headers.get("cookie") or headers.get("Cookie") or ""
    has_cookie_header = bool(cookie_header)
    cookie_names = [p.strip().split("=")[0] for p in cookie_header.split(";") if "=" in p] if cookie_header else []
    event_cookies = event.get("cookies") or []
    if isinstance(event_cookies, list):
        cookie_names.extend([p.split("=")[0] for p in event_cookies if isinstance(p, str) and "=" in p])
    elif isinstance(event_cookies, str) and "=" in event_cookies:
        cookie_names.append(event_cookies.split("=")[0])
    logger.info("auth debug: has_cookie_header=%s cookie_names=%s header_keys=%s",
                has_cookie_header, cookie_names, list(headers.keys()))
    token = _extract_token(event)
    if not token:
        logger.warning("auth: no enceladus_id_token found. cookie_names=%s", cookie_names)
        return None, _error(401, "Authentication required. Please sign in.")
    try:
        claims = _verify_token(token)
        return claims, None
    except ValueError as exc:
        logger.warning("auth failed: %s", exc)
        return None, _error(401, str(exc))


# ---------------------------------------------------------------------------
# Project validation (fail-open, same as tracker_mutation)
# ---------------------------------------------------------------------------


def _validate_project_exists(project_id: str) -> Optional[str]:
    global _project_cache, _project_cache_at
    now = time.time()
    if (now - _project_cache_at) >= _PROJECT_CACHE_TTL:
        _project_cache = {}
        _project_cache_at = now
    if project_id in _project_cache:
        return None if _project_cache[project_id] else (
            f"Project '{project_id}' is not registered."
        )
    try:
        ddb = _get_ddb()
        resp = ddb.get_item(
            TableName=PROJECTS_TABLE,
            Key={"project_id": {"S": project_id}},
            ProjectionExpression="project_id",
        )
        exists = "Item" in resp
        _project_cache[project_id] = exists
        if not exists:
            return f"Project '{project_id}' is not registered."
        return None
    except Exception as exc:
        logger.warning("project validation failed (fail-open): %s", exc)
        return None


# ---------------------------------------------------------------------------
# AWS clients (lazy singletons)
# ---------------------------------------------------------------------------

_ddb = None
_s3 = None


def _get_ddb():
    global _ddb
    if _ddb is None:
        _ddb = boto3.client(
            "dynamodb", region_name=DYNAMODB_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _ddb


def _get_s3():
    global _s3
    if _s3 is None:
        _s3 = boto3.client("s3")
    return _s3


def _now_z() -> str:
    return dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Markdown compliance scoring (warn-only in v0.3)
# ---------------------------------------------------------------------------


def _is_heading(line: str) -> Optional[Tuple[int, str]]:
    m = re.match(r"^(#{1,6})\s+(.+?)\s*$", line)
    if not m:
        return None
    return len(m.group(1)), m.group(2).strip()


def _is_list_item(line: str) -> Optional[Tuple[int, str]]:
    m = re.match(r"^(\s*)([-*+])\s+.+$", line)
    if not m:
        return None
    return len(m.group(1)), m.group(2)


def _is_table_divider(line: str) -> bool:
    # Valid markdown table divider: | --- | :---: | ---: |
    return bool(re.match(r"^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$", line))


def _evaluate_markdown_compliance(content: str) -> Dict[str, Any]:
    warnings: List[str] = []
    lines = content.splitlines()

    # Rule 1 + 7: title and metadata block.
    first_non_empty_idx = None
    for idx, line in enumerate(lines):
        if line.strip():
            first_non_empty_idx = idx
            break
    if first_non_empty_idx is None:
        warnings.append("Document is empty.")
    else:
        first_line = lines[first_non_empty_idx]
        if not re.match(r"^#\s+\S+", first_line):
            warnings.append("First non-empty line should be a level-1 title heading ('# ...').")
        elif not re.match(
            r"^#\s+([A-Z]{3}-(?:TSK|ISS|FTR)-\d{3}(?:-[0-9][A-Z])?|DOC-[A-Z0-9]{6,})\s+.+$",
            first_line,
        ):
            warnings.append(
                "Title should follow '# {ITEM_ID} Title' (e.g., '# DVP-TSK-123 Name')."
            )

    metadata_window = "\n".join(lines[: min(len(lines), 30)])
    for field in ("Project", "Related", "Created", "Author"):
        if f"**{field}**:" not in metadata_window:
            warnings.append(f"Metadata block missing '**{field}**:' near top of document.")

    # Rule 1: heading hierarchy.
    last_level = 0
    h1_count = 0
    for idx, line in enumerate(lines, start=1):
        parsed = _is_heading(line)
        if not parsed:
            continue
        level, _text = parsed
        if level == 1:
            h1_count += 1
            if idx != (first_non_empty_idx or 0) + 1:
                warnings.append("Level-1 heading should only appear at document start.")
        if last_level and (level - last_level) > 1:
            warnings.append(
                f"Heading level jump detected at line {idx} (h{last_level} -> h{level})."
            )
        last_level = level
    if h1_count > 1:
        warnings.append("Multiple level-1 headings found; use exactly one document title.")

    # Rule 3: fenced code blocks should be closed and include language on opening fence.
    in_fence = False
    fence_line = 0
    for idx, line in enumerate(lines, start=1):
        if not line.strip().startswith("```"):
            continue
        fence = line.strip()
        if not in_fence:
            in_fence = True
            fence_line = idx
            lang = fence[3:].strip()
            if not lang:
                warnings.append(f"Code fence at line {idx} should include a language identifier.")
        else:
            in_fence = False
            fence_line = 0
    if in_fence:
        warnings.append(f"Unclosed code fence opened at line {fence_line}.")

    # Rule 5: list marker consistency inside contiguous list blocks per indentation level.
    active_markers: Dict[int, str] = {}
    for idx, line in enumerate(lines, start=1):
        parsed = _is_list_item(line)
        if not parsed:
            active_markers = {}
            continue
        indent, marker = parsed
        existing = active_markers.get(indent)
        if existing is None:
            active_markers[indent] = marker
        elif existing != marker:
            warnings.append(
                f"Inconsistent list marker at line {idx} for indent {indent} (expected '{existing}', found '{marker}')."
            )

    # Rule 2: table header/divider structure when a table block starts.
    for idx in range(len(lines) - 1):
        current = lines[idx]
        nxt = lines[idx + 1]
        if "|" not in current:
            continue
        if _is_table_divider(nxt):
            continue
        # Only warn when it looks like a table header row.
        if current.strip().startswith("|") and current.strip().endswith("|"):
            warnings.append(
                f"Possible table header at line {idx + 1} missing valid divider row at line {idx + 2}."
            )

    # Rule 4 (alerts): warn-only heuristic if uppercase callout markers are malformed.
    for idx, line in enumerate(lines, start=1):
        if "[!" in line and not re.search(r"^\s*>\s*\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\s*$", line):
            warnings.append(f"Malformed alert syntax at line {idx}.")

    warnings = warnings[:MAX_COMPLIANCE_WARNINGS]
    score = max(0, 100 - (len(warnings) * 10))
    return {
        "compliance_score": score,
        "compliance_warnings": warnings,
    }


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------


def _cors_headers() -> Dict[str, str]:
    return {
        "Access-Control-Allow-Origin": CORS_ORIGIN,
        "Access-Control-Allow-Methods": "PUT, GET, PATCH, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Cookie, X-Coordination-Internal-Key",
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
# S3 helpers
# ---------------------------------------------------------------------------


def _s3_key(project_id: str, document_id: str) -> str:
    return f"{S3_PREFIX}/{project_id}/{document_id}.md"


def _is_allowed_file_name(file_name: str) -> bool:
    name = str(file_name or "").strip()
    if not name:
        return False
    lower_name = name.lower()
    return any(lower_name.endswith(ext) for ext in ALLOWED_FILE_EXTENSIONS)


def _upload_content(project_id: str, document_id: str, content: str) -> Tuple[str, str, int]:
    """Upload .md content to S3. Returns (s3_key, content_hash, size_bytes)."""
    s3 = _get_s3()
    key = _s3_key(project_id, document_id)
    content_bytes = content.encode("utf-8")
    content_hash = hashlib.sha256(content_bytes).hexdigest()
    size_bytes = len(content_bytes)

    s3.put_object(
        Bucket=S3_BUCKET,
        Key=key,
        Body=content_bytes,
        ContentType="text/markdown; charset=utf-8",
        CacheControl="max-age=0, s-maxage=300, must-revalidate",
    )
    return key, content_hash, size_bytes


def _get_content(project_id: str, document_id: str) -> Optional[str]:
    """Download .md content from S3. Returns content string or None."""
    s3 = _get_s3()
    key = _s3_key(project_id, document_id)
    try:
        resp = s3.get_object(Bucket=S3_BUCKET, Key=key)
        return resp["Body"].read().decode("utf-8")
    except s3.exceptions.NoSuchKey:
        return None
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchKey":
            return None
        raise


# ---------------------------------------------------------------------------
# DynamoDB helpers
# ---------------------------------------------------------------------------


def _serialize_list(items: List[str]) -> Dict:
    return {"L": [{"S": s} for s in items]}


def _deserialize_list(attr: Dict) -> List[str]:
    if not attr or "L" not in attr:
        return []
    return [item.get("S", "") for item in attr["L"] if "S" in item]


def _deserialize_item(item: Dict) -> Dict[str, Any]:
    """Convert DynamoDB typed map to plain dict."""
    result = {}
    for k, v in item.items():
        if "S" in v:
            result[k] = v["S"]
        elif "N" in v:
            result[k] = int(v["N"]) if "." not in v["N"] else float(v["N"])
        elif "L" in v:
            result[k] = _deserialize_list(v)
        elif "BOOL" in v:
            result[k] = v["BOOL"]
        elif "NULL" in v:
            result[k] = None
    return result


# ---------------------------------------------------------------------------
# Primary reference reconciliation (project reference + governance files)
# ---------------------------------------------------------------------------


def _keywords_lower_set(value: Any) -> set[str]:
    if not isinstance(value, list):
        return set()
    out: set[str] = set()
    for entry in value:
        text = str(entry).strip().lower()
        if text:
            out.add(text)
    return out


def _merge_keywords(existing: Any, required: List[str]) -> List[str]:
    merged = _keywords_lower_set(existing)
    for kw in required:
        text = str(kw).strip().lower()
        if text:
            merged.add(text)
    return sorted(merged)


def _query_project_documents(project_id: str) -> List[Dict[str, Any]]:
    ddb = _get_ddb()
    params: Dict[str, Any] = {
        "TableName": DOCUMENTS_TABLE,
        "IndexName": "project-updated-index",
        "KeyConditionExpression": "project_id = :pid",
        "ExpressionAttributeValues": {":pid": {"S": project_id}},
        "ScanIndexForward": False,
    }
    out: List[Dict[str, Any]] = []
    while True:
        resp = ddb.query(**params)
        out.extend(_deserialize_item(item) for item in resp.get("Items", []))
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        params["ExclusiveStartKey"] = lek
    return out


def _stable_doc_id(seed: str) -> str:
    digest = hashlib.sha1(seed.encode("utf-8")).hexdigest()[:12].upper()
    return f"DOC-{digest}"


def _put_document_content_bytes(
    project_id: str,
    document_id: str,
    content_bytes: bytes,
) -> Tuple[str, str, int]:
    key = _s3_key(project_id, document_id)
    content_hash = hashlib.sha256(content_bytes).hexdigest()
    size_bytes = len(content_bytes)
    _get_s3().put_object(
        Bucket=S3_BUCKET,
        Key=key,
        Body=content_bytes,
        ContentType="text/markdown; charset=utf-8",
        CacheControl="max-age=0, s-maxage=300, must-revalidate",
    )
    return key, content_hash, size_bytes


def _upsert_synced_document(
    *,
    existing: Optional[Dict[str, Any]],
    project_id: str,
    file_name: str,
    title: str,
    description: str,
    keywords: List[str],
    content_bytes: bytes,
) -> None:
    now = _now_z()
    ddb = _get_ddb()
    document_id = (existing or {}).get("document_id") or _stable_doc_id(f"{project_id}:{file_name}")

    s3_key, content_hash, size_bytes = _put_document_content_bytes(project_id, document_id, content_bytes)

    if existing:
        ddb.update_item(
            TableName=DOCUMENTS_TABLE,
            Key={"document_id": {"S": document_id}},
            UpdateExpression=(
                "SET title = :title, description = :desc, file_name = :fn, "
                "s3_bucket = :sb, s3_key = :sk, content_type = :ct, "
                "content_hash = :hash, size_bytes = :size, keywords = :kw, "
                "updated_at = :ts, #status = :status, #ver = if_not_exists(#ver, :zero) + :one"
            ),
            ExpressionAttributeNames={
                "#status": "status",
                "#ver": "version",
            },
            ExpressionAttributeValues={
                ":title": {"S": title},
                ":desc": {"S": description},
                ":fn": {"S": file_name},
                ":sb": {"S": S3_BUCKET},
                ":sk": {"S": s3_key},
                ":ct": {"S": "text/markdown"},
                ":hash": {"S": content_hash},
                ":size": {"N": str(size_bytes)},
                ":kw": _serialize_list(keywords),
                ":ts": {"S": now},
                ":status": {"S": "active"},
                ":zero": {"N": "0"},
                ":one": {"N": "1"},
            },
        )
        return

    item = {
        "document_id": {"S": document_id},
        "project_id": {"S": project_id},
        "title": {"S": title},
        "description": {"S": description},
        "file_name": {"S": file_name},
        "s3_bucket": {"S": S3_BUCKET},
        "s3_key": {"S": s3_key},
        "content_type": {"S": "text/markdown"},
        "content_hash": {"S": content_hash},
        "size_bytes": {"N": str(size_bytes)},
        "related_items": _serialize_list([]),
        "keywords": _serialize_list(keywords),
        "created_by": {"S": SYNC_CREATED_BY},
        "created_at": {"S": now},
        "updated_at": {"S": now},
        "status": {"S": "active"},
        "version": {"N": "1"},
    }
    try:
        ddb.put_item(
            TableName=DOCUMENTS_TABLE,
            Item=item,
            ConditionExpression="attribute_not_exists(document_id)",
        )
    except ddb.exceptions.ConditionalCheckFailedException:
        # Concurrent creation path: convert this attempt into an update.
        resp = ddb.get_item(
            TableName=DOCUMENTS_TABLE,
            Key={"document_id": {"S": document_id}},
            ConsistentRead=True,
        )
        current = _deserialize_item(resp.get("Item", {}))
        if current:
            _upsert_synced_document(
                existing=current,
                project_id=project_id,
                file_name=file_name,
                title=title,
                description=description,
                keywords=keywords,
                content_bytes=content_bytes,
            )


def _sync_project_reference_document(project_id: str) -> None:
    ddb = _get_ddb()
    ref_row = ddb.get_item(
        TableName=TRACKER_TABLE,
        Key={
            "project_id": {"S": project_id},
            "record_id": {"S": f"reference#{project_id}"},
        },
        ConsistentRead=True,
    ).get("Item")

    if not ref_row:
        logger.info("project reference sync skipped (no tracker row): project=%s", project_id)
        return

    ref_meta = _deserialize_item(ref_row)
    s3_bucket = str(ref_meta.get("s3_bucket") or S3_BUCKET)
    s3_key = str(ref_meta.get("s3_key") or f"{S3_REFERENCE_PREFIX.rstrip('/')}/{project_id}.md")

    docs = _query_project_documents(project_id)
    by_keyword = [
        doc for doc in docs
        if PROJECT_REFERENCE_KEYWORD in _keywords_lower_set(doc.get("keywords"))
    ]
    canonical_file = f"{project_id}-reference.md"
    canonical = [d for d in by_keyword if str(d.get("file_name") or "").strip() == canonical_file]
    if canonical:
        existing = canonical[0]
    else:
        by_title = [
            d for d in by_keyword
            if "project reference" in str(d.get("title") or "").strip().lower()
        ]
        existing = by_title[0] if by_title else (by_keyword[0] if by_keyword else None)

    # Always hash-check against the current S3 object body (tracker metadata can lag).
    body = _get_s3().get_object(Bucket=s3_bucket, Key=s3_key)["Body"].read()
    body_hash = hashlib.sha256(body).hexdigest()

    if existing and str(existing.get("content_hash") or "") == body_hash:
        return

    default_title = f"{project_id} Project Reference"
    title = str((existing or {}).get("title") or default_title).strip()
    file_name = str((existing or {}).get("file_name") or f"{project_id}-reference.md").strip()
    description = str((existing or {}).get("description") or "Canonical project reference document.").strip()
    keywords = _merge_keywords(
        (existing or {}).get("keywords", []),
        ["reference", PROJECT_REFERENCE_KEYWORD, project_id],
    )

    _upsert_synced_document(
        existing=existing,
        project_id=project_id,
        file_name=file_name,
        title=title,
        description=description,
        keywords=keywords,
        content_bytes=body,
    )


def _list_governance_live_files() -> List[str]:
    s3 = _get_s3()
    prefix = S3_GOVERNANCE_PREFIX.rstrip("/") + "/"
    paginator = s3.get_paginator("list_objects_v2")
    files: List[str] = []
    for page in paginator.paginate(Bucket=S3_BUCKET, Prefix=prefix):
        for obj in page.get("Contents", []):
            key = str(obj.get("Key") or "")
            if not key.startswith(prefix):
                continue
            rel = key[len(prefix):]
            if not rel or rel.endswith("/"):
                continue
            files.append(rel)
    return sorted(set(files))


def _sync_governance_documents() -> None:
    docs = _query_project_documents(GOVERNANCE_PROJECT_ID)
    doc_by_file: Dict[str, Dict[str, Any]] = {}
    for doc in docs:
        file_name = str(doc.get("file_name") or "").strip()
        if not file_name:
            continue
        kws = _keywords_lower_set(doc.get("keywords"))
        title = str(doc.get("title") or "")
        if GOVERNANCE_KEYWORD in kws or title.startswith("Governance:"):
            doc_by_file[file_name] = doc

    for rel_file in _list_governance_live_files():
        key = f"{S3_GOVERNANCE_PREFIX.rstrip('/')}/{rel_file}"
        existing = doc_by_file.get(rel_file)

        # Fast path: compare metadata hash when available.
        metadata_hash = ""
        try:
            head = _get_s3().head_object(Bucket=S3_BUCKET, Key=key)
            metadata_hash = str((head.get("Metadata") or {}).get("content_sha256") or "").strip()
        except Exception as exc:
            logger.warning("governance sync head_object failed for %s: %s", key, exc)

        if existing and metadata_hash and str(existing.get("content_hash") or "") == metadata_hash:
            continue

        body = _get_s3().get_object(Bucket=S3_BUCKET, Key=key)["Body"].read()
        content_hash = hashlib.sha256(body).hexdigest()
        if existing and str(existing.get("content_hash") or "") == content_hash:
            continue

        title = str((existing or {}).get("title") or f"Governance: {rel_file}").strip()
        file_name = str((existing or {}).get("file_name") or rel_file).strip()
        description = str(
            (existing or {}).get("description")
            or "Authoritative Enceladus governance file."
        ).strip()
        keywords = _merge_keywords(
            (existing or {}).get("keywords", []),
            ["coordination", "enceladus", "governance", GOVERNANCE_KEYWORD, "mcp"],
        )

        _upsert_synced_document(
            existing=existing,
            project_id=GOVERNANCE_PROJECT_ID,
            file_name=file_name,
            title=title,
            description=description,
            keywords=keywords,
            content_bytes=body,
        )


def _sync_primary_reference_documents(project_id: str, keyword: str) -> None:
    key = str(keyword or "").strip().lower()
    if not project_id or not key:
        return
    if key == PROJECT_REFERENCE_KEYWORD:
        _sync_project_reference_document(project_id)
    elif key == GOVERNANCE_KEYWORD and project_id == GOVERNANCE_PROJECT_ID:
        _sync_governance_documents()


# ---------------------------------------------------------------------------
# PUT — Upload new document
# ---------------------------------------------------------------------------


def _handle_put(event: Dict, claims: Dict) -> Dict:
    """Create a new document."""
    try:
        body_raw = event.get("body") or "{}"
        if event.get("isBase64Encoded"):
            body_raw = base64.b64decode(body_raw).decode("utf-8")
        body = json.loads(body_raw)
    except (ValueError, TypeError):
        return _error(400, "Invalid JSON body.")

    # Required fields
    project_id = body.get("project_id", "").strip()
    title = body.get("title", "").strip()
    content = body.get("content", "")

    if not project_id:
        return _error(400, "Field 'project_id' is required.")
    if not title:
        return _error(400, "Field 'title' is required.")
    if content is None or not isinstance(content, str) or not content:
        return _error(400, "Field 'content' is required (document body).")
    if len(title) > MAX_TITLE_LENGTH:
        return _error(400, f"Title exceeds {MAX_TITLE_LENGTH} characters.")
    if len(content.encode("utf-8")) > MAX_CONTENT_SIZE:
        return _error(400, f"Content exceeds {MAX_CONTENT_SIZE} bytes.")

    compliance = _evaluate_markdown_compliance(content)
    if MIN_COMPLIANCE_SCORE > 0 and compliance["compliance_score"] < MIN_COMPLIANCE_SCORE:
        return _error(
            400,
            (
                f"Document compliance_score {compliance['compliance_score']} is below "
                f"minimum required score {MIN_COMPLIANCE_SCORE}."
            ),
            compliance_score=compliance["compliance_score"],
            compliance_warnings=compliance["compliance_warnings"],
        )

    # Validate project
    project_err = _validate_project_exists(project_id)
    if project_err:
        return _error(404, project_err)

    # Optional fields
    description = body.get("description", "").strip()[:MAX_DESCRIPTION_LENGTH]
    related_items = body.get("related_items", [])
    keywords = body.get("keywords", [])
    file_name = str(body.get("file_name", "")).strip()
    if file_name and not _is_allowed_file_name(file_name):
        return _error(
            400,
            f"file_name must end with one of: {', '.join(sorted(ALLOWED_FILE_EXTENSIONS))}",
        )

    if not isinstance(related_items, list):
        return _error(400, "Field 'related_items' must be an array of strings.")
    if not isinstance(keywords, list):
        return _error(400, "Field 'keywords' must be an array of strings.")
    related_items = [str(r).strip() for r in related_items[:MAX_RELATED_ITEMS] if str(r).strip()]
    keywords = [str(k).strip().lower() for k in keywords[:MAX_KEYWORDS] if str(k).strip()]

    # Generate document ID
    document_id = f"DOC-{uuid.uuid4().hex[:12].upper()}"
    now = _now_z()
    created_by = claims.get("email") or claims.get("sub", "unknown")

    # Upload to S3
    try:
        s3_key, content_hash, size_bytes = _upload_content(project_id, document_id, content)
    except Exception as exc:
        logger.error("S3 upload failed: %s", exc)
        return _error(500, "Failed to store document content.")

    # Write metadata to DynamoDB
    ddb = _get_ddb()
    item = {
        "document_id": {"S": document_id},
        "project_id": {"S": project_id},
        "title": {"S": title},
        "description": {"S": description},
        "file_name": {"S": file_name or f"{document_id}.md"},
        "s3_bucket": {"S": S3_BUCKET},
        "s3_key": {"S": s3_key},
        "content_type": {"S": "text/markdown"},
        "content_hash": {"S": content_hash},
        "size_bytes": {"N": str(size_bytes)},
        "related_items": _serialize_list(related_items),
        "keywords": _serialize_list(keywords),
        "created_by": {"S": created_by},
        "created_at": {"S": now},
        "updated_at": {"S": now},
        "status": {"S": "active"},
        "version": {"N": "1"},
        "compliance_score": {"N": str(compliance["compliance_score"])},
        "compliance_warnings": _serialize_list(compliance["compliance_warnings"]),
        "compliance_checked_at": {"S": now},
    }

    try:
        ddb.put_item(TableName=DOCUMENTS_TABLE, Item=item)
    except Exception as exc:
        logger.error("DynamoDB put_item failed: %s", exc)
        # Attempt to clean up S3
        try:
            _get_s3().delete_object(Bucket=S3_BUCKET, Key=s3_key)
        except Exception:
            pass
        return _error(500, "Failed to save document metadata.")

    logger.info("document created: %s project=%s size=%d", document_id, project_id, size_bytes)
    return _response(201, {
        "success": True,
        "document_id": document_id,
        "s3_location": f"s3://{S3_BUCKET}/{s3_key}",
        "content_hash": content_hash,
        "size_bytes": size_bytes,
        "created_at": now,
        "compliance_score": compliance["compliance_score"],
        "compliance_warnings": compliance["compliance_warnings"],
    })


# ---------------------------------------------------------------------------
# GET — Retrieve document (by ID or list by project)
# ---------------------------------------------------------------------------


def _handle_get(event: Dict, claims: Dict, document_id: Optional[str]) -> Dict:
    """Retrieve a single document or list documents."""
    qs = event.get("queryStringParameters") or {}

    if document_id and document_id != "search":
        return _get_single(document_id, qs)
    elif document_id == "search":
        return _handle_search(qs)
    elif "project" in qs:
        return _list_by_project(qs)
    else:
        return _error(400, "Provide a document ID or ?project= query parameter.")


def _get_single(document_id: str, qs: Dict) -> Dict:
    """Get a single document by ID, optionally including content."""
    ddb = _get_ddb()
    try:
        resp = ddb.get_item(
            TableName=DOCUMENTS_TABLE,
            Key={"document_id": {"S": document_id}},
            ConsistentRead=True,
        )
    except Exception as exc:
        logger.error("get_item failed: %s", exc)
        return _error(500, "Database read failed.")

    item = resp.get("Item")
    if not item:
        return _error(404, f"Document not found: {document_id}")

    doc = _deserialize_item(item)
    include_content = qs.get("include_content", "true").lower() == "true"

    if include_content:
        content = _get_content(doc.get("project_id", ""), document_id)
        if content is not None:
            doc["content"] = content

    # Backward-compatible payload:
    # - `document` wrapper supports API clients expecting structured envelope.
    # - top-level document fields support legacy/mobile clients reading raw doc.
    payload = {"success": True, "document": doc, **doc}
    return _response(200, payload)


def _list_by_project(qs: Dict) -> Dict:
    """List documents for a project using GSI."""
    project_id = qs.get("project", "").strip()
    if not project_id:
        return _error(400, "Query parameter 'project' is required.")

    ddb = _get_ddb()
    params = {
        "TableName": DOCUMENTS_TABLE,
        "IndexName": "project-updated-index",
        "KeyConditionExpression": "project_id = :pid",
        "ExpressionAttributeValues": {":pid": {"S": project_id}},
        "ScanIndexForward": False,  # newest first
        "Limit": PAGE_SIZE,
    }

    # Pagination
    if qs.get("cursor"):
        try:
            cursor = json.loads(base64.b64decode(qs["cursor"]).decode("utf-8"))
            params["ExclusiveStartKey"] = cursor
        except Exception:
            return _error(400, "Invalid pagination cursor.")

    try:
        resp = ddb.query(**params)
    except Exception as exc:
        logger.error("query failed: %s", exc)
        return _error(500, "Database query failed.")

    docs = [_deserialize_item(item) for item in resp.get("Items", [])]

    result: Dict[str, Any] = {
        "success": True,
        "documents": docs,
        "count": len(docs),
    }
    if resp.get("LastEvaluatedKey"):
        result["next_cursor"] = base64.b64encode(
            json.dumps(resp["LastEvaluatedKey"]).encode()
        ).decode()

    return _response(200, result)


# ---------------------------------------------------------------------------
# PATCH — Edit document
# ---------------------------------------------------------------------------


def _handle_patch(event: Dict, claims: Dict, document_id: str) -> Dict:
    """Update document content and/or metadata."""
    if not document_id:
        return _error(400, "Document ID is required in path.")

    try:
        body_raw = event.get("body") or "{}"
        if event.get("isBase64Encoded"):
            body_raw = base64.b64decode(body_raw).decode("utf-8")
        body = json.loads(body_raw)
    except (ValueError, TypeError):
        return _error(400, "Invalid JSON body.")

    # Fetch current record
    ddb = _get_ddb()
    try:
        resp = ddb.get_item(
            TableName=DOCUMENTS_TABLE,
            Key={"document_id": {"S": document_id}},
            ConsistentRead=True,
        )
    except Exception as exc:
        logger.error("get_item failed: %s", exc)
        return _error(500, "Database read failed.")

    existing = resp.get("Item")
    if not existing:
        return _error(404, f"Document not found: {document_id}")

    current_version = int(existing.get("version", {}).get("N", "0"))
    project_id = existing.get("project_id", {}).get("S", "")
    now = _now_z()

    # Build update expression
    expr_parts = ["updated_at = :ts", "#ver = #ver + :one"]
    attr_names: Dict[str, str] = {"#ver": "version"}
    attr_values: Dict[str, Dict] = {
        ":ts": {"S": now},
        ":one": {"N": "1"},
        ":expected": {"N": str(current_version)},
    }
    compliance: Optional[Dict[str, Any]] = None

    # Updatable metadata fields
    if "title" in body:
        title = str(body["title"]).strip()
        if not title or len(title) > MAX_TITLE_LENGTH:
            return _error(400, f"Title must be 1-{MAX_TITLE_LENGTH} characters.")
        expr_parts.append("title = :title")
        attr_values[":title"] = {"S": title}

    if "description" in body:
        expr_parts.append("description = :desc")
        attr_values[":desc"] = {"S": str(body["description"]).strip()[:MAX_DESCRIPTION_LENGTH]}

    if "related_items" in body:
        items = body["related_items"]
        if not isinstance(items, list):
            return _error(400, "'related_items' must be an array.")
        items = [str(r).strip() for r in items[:MAX_RELATED_ITEMS] if str(r).strip()]
        expr_parts.append("related_items = :ri")
        attr_values[":ri"] = _serialize_list(items)

    if "keywords" in body:
        kws = body["keywords"]
        if not isinstance(kws, list):
            return _error(400, "'keywords' must be an array.")
        kws = [str(k).strip().lower() for k in kws[:MAX_KEYWORDS] if str(k).strip()]
        expr_parts.append("keywords = :kw")
        attr_values[":kw"] = _serialize_list(kws)

    if "status" in body:
        status = str(body["status"]).strip().lower()
        if status not in ("active", "archived"):
            return _error(400, "Status must be 'active' or 'archived'.")
        expr_parts.append("#status = :status")
        attr_names["#status"] = "status"
        attr_values[":status"] = {"S": status}

    if "file_name" in body:
        file_name = str(body.get("file_name") or "").strip()
        if not file_name or not _is_allowed_file_name(file_name):
            return _error(
                400,
                f"file_name must end with one of: {', '.join(sorted(ALLOWED_FILE_EXTENSIONS))}",
            )
        expr_parts.append("file_name = :file_name")
        attr_values[":file_name"] = {"S": file_name}

    # Content update — re-upload to S3
    if "content" in body:
        content = body["content"]
        if content is None or not isinstance(content, str) or not content:
            return _error(400, "Field 'content' must be a non-empty string.")
        if len(content.encode("utf-8")) > MAX_CONTENT_SIZE:
            return _error(400, f"Content must be 1-{MAX_CONTENT_SIZE} bytes.")
        try:
            compliance = _evaluate_markdown_compliance(content)
            if MIN_COMPLIANCE_SCORE > 0 and compliance["compliance_score"] < MIN_COMPLIANCE_SCORE:
                return _error(
                    400,
                    (
                        f"Document compliance_score {compliance['compliance_score']} is below "
                        f"minimum required score {MIN_COMPLIANCE_SCORE}."
                    ),
                    compliance_score=compliance["compliance_score"],
                    compliance_warnings=compliance["compliance_warnings"],
                )
            s3_key, content_hash, size_bytes = _upload_content(project_id, document_id, content)
            expr_parts.append("content_hash = :hash")
            expr_parts.append("size_bytes = :size")
            expr_parts.append("s3_key = :s3k")
            expr_parts.append("compliance_score = :cscore")
            expr_parts.append("compliance_warnings = :cwarnings")
            expr_parts.append("compliance_checked_at = :cchecked")
            attr_values[":hash"] = {"S": content_hash}
            attr_values[":size"] = {"N": str(size_bytes)}
            attr_values[":s3k"] = {"S": s3_key}
            attr_values[":cscore"] = {"N": str(compliance["compliance_score"])}
            attr_values[":cwarnings"] = _serialize_list(compliance["compliance_warnings"])
            attr_values[":cchecked"] = {"S": now}
        except Exception as exc:
            logger.error("S3 upload (edit) failed: %s", exc)
            return _error(500, "Failed to update document content.")

    update_expr = "SET " + ", ".join(expr_parts)

    try:
        ddb.update_item(
            TableName=DOCUMENTS_TABLE,
            Key={"document_id": {"S": document_id}},
            UpdateExpression=update_expr,
            ConditionExpression="#ver = :expected",
            ExpressionAttributeNames=attr_names,
            ExpressionAttributeValues=attr_values,
        )
    except ddb.exceptions.ConditionalCheckFailedException:
        return _error(409, "Document was modified concurrently. Please refresh and try again.")
    except Exception as exc:
        logger.error("update_item failed: %s", exc)
        return _error(500, "Database write failed.")

    logger.info("document updated: %s", document_id)
    payload: Dict[str, Any] = {
        "success": True,
        "document_id": document_id,
        "updated_at": now,
        "version": current_version + 1,
    }
    if compliance is not None:
        payload["compliance_score"] = compliance["compliance_score"]
        payload["compliance_warnings"] = compliance["compliance_warnings"]
    return _response(200, payload)


# ---------------------------------------------------------------------------
# Search — Query by project, keyword, related_items
# ---------------------------------------------------------------------------


def _handle_search(qs: Dict) -> Dict:
    """Search documents by project, keyword, related_items, title."""
    ddb = _get_ddb()
    project_id = qs.get("project", "").strip()
    keyword = qs.get("keyword", "").strip().lower()
    related = qs.get("related", "").strip()
    title_search = qs.get("title", "").strip().lower()
    status_filter = qs.get("status", "active").strip().lower()

    # Keep primary reference docs current at read-time for PWA document routes.
    if project_id and keyword in {PROJECT_REFERENCE_KEYWORD, GOVERNANCE_KEYWORD}:
        try:
            _sync_primary_reference_documents(project_id, keyword)
        except Exception as exc:
            logger.warning(
                "primary reference sync failed (project=%s keyword=%s): %s",
                project_id,
                keyword,
                exc,
            )

    # If project specified, use GSI query + client-side filter
    if project_id:
        params: Dict[str, Any] = {
            "TableName": DOCUMENTS_TABLE,
            "IndexName": "project-updated-index",
            "KeyConditionExpression": "project_id = :pid",
            "ExpressionAttributeValues": {":pid": {"S": project_id}},
            "ScanIndexForward": False,
        }
        try:
            resp = ddb.query(**params)
        except Exception as exc:
            logger.error("search query failed: %s", exc)
            return _error(500, "Search failed.")
        items = resp.get("Items", [])
    else:
        # Full table scan with limit (for cross-project search)
        try:
            resp = ddb.scan(TableName=DOCUMENTS_TABLE, Limit=500)
        except Exception as exc:
            logger.error("search scan failed: %s", exc)
            return _error(500, "Search failed.")
        items = resp.get("Items", [])

    docs = [_deserialize_item(item) for item in items]

    # Client-side filtering
    if keyword:
        docs = [d for d in docs if keyword in [k.lower() for k in d.get("keywords", [])]]
    if related:
        docs = [d for d in docs if related in d.get("related_items", [])]
    if title_search:
        docs = [d for d in docs if title_search in d.get("title", "").lower()]
    if status_filter:
        docs = [d for d in docs if d.get("status", "active") == status_filter]

    # Don't include content in search results
    for d in docs:
        d.pop("content", None)

    return _response(200, {
        "success": True,
        "documents": docs[:PAGE_SIZE],
        "count": len(docs[:PAGE_SIZE]),
        "total_matches": len(docs),
    })


# ---------------------------------------------------------------------------
# Path parsing
# ---------------------------------------------------------------------------

def _parse_request(event: Dict) -> Tuple[str, Optional[str], Dict]:
    """Parse method, document_id, and query params from event."""
    method = (
        (event.get("requestContext") or {}).get("http", {}).get("method")
        or event.get("httpMethod", "")
    )
    raw_path = event.get("rawPath") or event.get("path", "")
    path_params = event.get("pathParameters") or {}

    document_id = (
        path_params.get("documentId")
        or path_params.get("document_id")
        or None
    )

    if not document_id:
        # Handle arbitrary API mappings/stage prefixes by matching the tail.
        match = re.search(r"/documents/(?P<documentId>[A-Za-z0-9_-]+)/?$", raw_path)
        if match:
            document_id = match.group("documentId")
        elif re.search(r"/documents/search/?$", raw_path):
            document_id = "search"

    qs = event.get("queryStringParameters") or {}
    logger.info(
        "request parse: method=%s raw_path=%s document_id=%s qs_keys=%s",
        method, raw_path, document_id, sorted(qs.keys()),
    )
    return method, document_id, qs


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------


def lambda_handler(event: Dict, context: Any) -> Dict:
    method, document_id, qs = _parse_request(event)

    # CORS preflight
    if method == "OPTIONS":
        return {"statusCode": 204, "headers": _cors_headers(), "body": ""}

    # Authenticate
    required_scopes = ["documents:read"] if method == "GET" else ["documents:write"]
    claims, auth_err = _authenticate(event, required_scopes)
    if auth_err:
        return auth_err

    # Route
    if method == "PUT" or method == "POST":
        return _handle_put(event, claims)
    elif method == "GET":
        return _handle_get(event, claims, document_id)
    elif method == "PATCH":
        if not document_id:
            return _error(400, "PATCH requires a document ID in the path.")
        return _handle_patch(event, claims, document_id)
    else:
        return _error(405, f"Method {method} not allowed.")
