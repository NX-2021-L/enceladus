"""doc_prep/lambda_function.py

Lambda API for document preparation — resolves primary project documentation
from S3 and returns content for agents to write into repo docs/ directories.

Routes (via API Gateway proxy on devops-tracker-api):
    POST    /api/v1/doc-prep/{projectName}   — fetch primary docs for project
    OPTIONS /api/v1/doc-prep/{projectName}   — CORS preflight

Auth:
    AWS_IAM (SigV4) — agents call this with their existing AWS credentials.
    No Cognito needed for agent-to-cloud calls.

Environment variables:
    PROJECTS_TABLE     default: projects
    TRACKER_TABLE      default: devops-project-tracker
    DOCUMENTS_TABLE    default: documents
    S3_BUCKET          default: jreese-net
    DYNAMODB_REGION    default: us-west-2
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PROJECTS_TABLE = os.environ.get("PROJECTS_TABLE", "projects")
TRACKER_TABLE = os.environ.get("TRACKER_TABLE", "devops-project-tracker")
DOCUMENTS_TABLE = os.environ.get("DOCUMENTS_TABLE", "documents")
DYNAMODB_REGION = os.environ.get("DYNAMODB_REGION", "us-west-2")
S3_BUCKET = os.environ.get("S3_BUCKET", "jreese-net")
CORS_ORIGIN = "https://jreese.net"
DEFAULT_MAX_DOCS = 5

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Module-level caches
# ---------------------------------------------------------------------------

_project_cache: Dict[str, Dict] = {}
_project_cache_at: float = 0.0
_PROJECT_CACHE_TTL = 300.0  # 5 minutes

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
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------


def _cors_headers() -> Dict[str, str]:
    return {
        "Access-Control-Allow-Origin": CORS_ORIGIN,
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Allow-Credentials": "true",
    }


def _response(status_code: int, body: Any) -> Dict:
    return {
        "statusCode": status_code,
        "headers": {**_cors_headers(), "Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def _error(status_code: int, message: str) -> Dict:
    return _response(status_code, {"success": False, "error": message})


# ---------------------------------------------------------------------------
# DynamoDB helpers
# ---------------------------------------------------------------------------


def _deserialize_value(v: Dict) -> Any:
    """Simple DynamoDB AttributeValue → Python value."""
    if "S" in v:
        return v["S"]
    if "N" in v:
        raw = v["N"]
        return int(raw) if "." not in raw else float(raw)
    if "BOOL" in v:
        return v["BOOL"]
    if "NULL" in v:
        return None
    if "L" in v:
        return [_deserialize_value(item) for item in v["L"]]
    if "M" in v:
        return {k: _deserialize_value(val) for k, val in v["M"].items()}
    return None


def _deserialize_item(item: Dict) -> Dict:
    return {k: _deserialize_value(v) for k, v in item.items()}


# ---------------------------------------------------------------------------
# Project resolution
# ---------------------------------------------------------------------------


def _get_project(project_id: str) -> Optional[Dict]:
    """Get full project record from DynamoDB projects table (with caching)."""
    global _project_cache, _project_cache_at
    now = time.time()
    if (now - _project_cache_at) >= _PROJECT_CACHE_TTL:
        _project_cache = {}
        _project_cache_at = now
    if project_id in _project_cache:
        return _project_cache[project_id]
    try:
        ddb = _get_ddb()
        resp = ddb.get_item(
            TableName=PROJECTS_TABLE,
            Key={"project_id": {"S": project_id}},
        )
        if "Item" not in resp:
            _project_cache[project_id] = None
            return None
        project = _deserialize_item(resp["Item"])
        _project_cache[project_id] = project
        return project
    except Exception as exc:
        logger.warning("project lookup failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Reference doc resolution
# ---------------------------------------------------------------------------


def _get_reference_doc(project_id: str) -> Optional[Dict]:
    """Fetch the project reference doc from S3 using tracker metadata."""
    ddb = _get_ddb()
    try:
        resp = ddb.get_item(
            TableName=TRACKER_TABLE,
            Key={
                "project_id": {"S": project_id},
                "record_id": {"S": f"reference#{project_id}"},
            },
            ConsistentRead=True,
        )
    except (BotoCoreError, ClientError) as exc:
        logger.error("reference metadata lookup failed for %s: %s", project_id, exc)
        return None

    item = resp.get("Item")
    if not item:
        logger.warning("no reference metadata row for project %s", project_id)
        return None

    meta = _deserialize_item(item)
    s3_key = meta.get("s3_key")
    s3_bucket = meta.get("s3_bucket", S3_BUCKET)

    if not s3_key:
        logger.error("reference row for %s has no s3_key", project_id)
        return None

    # Fetch content from S3
    try:
        s3 = _get_s3()
        s3_resp = s3.get_object(Bucket=s3_bucket, Key=s3_key)
        content = s3_resp["Body"].read().decode("utf-8")
    except Exception as exc:
        logger.error("S3 fetch failed for reference doc %s/%s: %s", s3_bucket, s3_key, exc)
        return None

    content_bytes = content.encode("utf-8")
    return {
        "filename": f"{project_id}-reference.md",
        "source": f"s3://{s3_bucket}/{s3_key}",
        "category": "reference",
        "size_bytes": len(content_bytes),
        "content_hash": hashlib.sha256(content_bytes).hexdigest(),
        "content": content,
    }


# ---------------------------------------------------------------------------
# Additional doc resolution
# ---------------------------------------------------------------------------


def _get_additional_doc_from_s3(doc_config: Dict) -> Optional[Dict]:
    """Fetch an additional doc from S3 based on doc_prep_config entry."""
    s3_key = doc_config.get("s3_key")
    filename = doc_config.get("filename", "unknown.md")
    category = doc_config.get("category", "general")

    if not s3_key:
        logger.warning("additional doc '%s' has no s3_key", filename)
        return None

    try:
        s3 = _get_s3()
        s3_resp = s3.get_object(Bucket=S3_BUCKET, Key=s3_key)
        content = s3_resp["Body"].read().decode("utf-8")
    except Exception as exc:
        logger.error("S3 fetch failed for additional doc %s: %s", s3_key, exc)
        return None

    content_bytes = content.encode("utf-8")
    return {
        "filename": filename,
        "source": f"s3://{S3_BUCKET}/{s3_key}",
        "category": category,
        "size_bytes": len(content_bytes),
        "content_hash": hashlib.sha256(content_bytes).hexdigest(),
        "content": content,
    }


def _get_additional_doc_from_docstore(doc_config: Dict) -> Optional[Dict]:
    """Fetch an additional doc from the documents DynamoDB table + S3."""
    document_id = doc_config.get("document_id")
    filename = doc_config.get("filename", "unknown.md")
    category = doc_config.get("category", "general")

    if not document_id:
        logger.warning("additional doc '%s' has no document_id", filename)
        return None

    try:
        ddb = _get_ddb()
        resp = ddb.get_item(
            TableName=DOCUMENTS_TABLE,
            Key={"document_id": {"S": document_id}},
        )
    except (BotoCoreError, ClientError) as exc:
        logger.error("docstore lookup failed for %s: %s", document_id, exc)
        return None

    item = resp.get("Item")
    if not item:
        logger.warning("document %s not found in docstore", document_id)
        return None

    meta = _deserialize_item(item)
    s3_key = meta.get("s3_key")
    s3_bucket = meta.get("s3_bucket", S3_BUCKET)

    if not s3_key:
        logger.error("document %s has no s3_key in docstore", document_id)
        return None

    try:
        s3 = _get_s3()
        s3_resp = s3.get_object(Bucket=s3_bucket, Key=s3_key)
        content = s3_resp["Body"].read().decode("utf-8")
    except Exception as exc:
        logger.error("S3 fetch failed for docstore doc %s/%s: %s", s3_bucket, s3_key, exc)
        return None

    content_bytes = content.encode("utf-8")
    return {
        "filename": filename,
        "source": f"s3://{s3_bucket}/{s3_key}",
        "category": category,
        "size_bytes": len(content_bytes),
        "content_hash": hashlib.sha256(content_bytes).hexdigest(),
        "content": content,
    }


def _resolve_additional_docs(doc_prep_config: Dict) -> List[Dict]:
    """Resolve all additional docs from the project's doc_prep_config."""
    docs = []
    additional = doc_prep_config.get("additional_docs", [])

    for doc_config in additional:
        source_type = doc_config.get("source_type", "s3")
        required = doc_config.get("required", False)
        filename = doc_config.get("filename", "unknown.md")

        if source_type == "s3":
            doc = _get_additional_doc_from_s3(doc_config)
        elif source_type == "docstore":
            doc = _get_additional_doc_from_docstore(doc_config)
        else:
            logger.warning("unknown source_type '%s' for doc '%s'", source_type, filename)
            doc = None

        if doc:
            docs.append(doc)
        elif required:
            logger.error("required doc '%s' could not be fetched", filename)
            # Return a placeholder so the count is accurate
            docs.append({
                "filename": filename,
                "source": "ERROR: could not fetch",
                "category": doc_config.get("category", "general"),
                "size_bytes": 0,
                "content_hash": "",
                "content": None,
                "error": f"Required document '{filename}' could not be fetched.",
            })

    return docs


# ---------------------------------------------------------------------------
# Main handler
# ---------------------------------------------------------------------------


def _handle_post(event: Dict) -> Dict:
    """Handle POST /api/v1/doc-prep/{projectName}."""
    # Extract project name from path
    raw_path = event.get("rawPath", "")
    path_params = event.get("pathParameters") or {}
    project_id = path_params.get("projectName", "").lower().strip()

    if not project_id:
        # Fallback: parse from rawPath
        parts = raw_path.rstrip("/").split("/")
        project_id = parts[-1].lower().strip() if parts else ""

    if not project_id:
        return _error(400, "Project name is required.")

    # Parse body
    body_str = event.get("body") or "{}"
    try:
        body = json.loads(body_str)
    except (json.JSONDecodeError, TypeError):
        body = {}

    dry_run = body.get("dry_run", False)

    # Validate project exists
    project = _get_project(project_id)
    if not project:
        return _error(404, f"Project '{project_id}' not found.")

    # Get doc_prep_config (defaults if not set)
    doc_prep_config = project.get("doc_prep_config", {})
    auto_include_reference = doc_prep_config.get("auto_include_reference", True)
    max_docs = doc_prep_config.get("max_docs", DEFAULT_MAX_DOCS)

    # Build document list
    documents: List[Dict] = []

    # 1. Reference doc (always included by default)
    if auto_include_reference:
        ref_doc = _get_reference_doc(project_id)
        if ref_doc:
            documents.append(ref_doc)
        else:
            logger.warning("reference doc not available for %s", project_id)

    # 2. Additional docs from config
    additional_docs = _resolve_additional_docs(doc_prep_config)
    documents.extend(additional_docs)

    # 3. Check for errors in required docs
    doc_errors = [d for d in documents if d.get("error")]
    if doc_errors:
        error_filenames = [d["filename"] for d in doc_errors]
        return _error(500, f"Failed to fetch required documents: {', '.join(error_filenames)}")

    # 4. Enforce max docs limit
    total_docs = len(documents)
    if total_docs > max_docs:
        # Return manifest without content for over-limit response
        manifest = [
            {k: v for k, v in doc.items() if k != "content"}
            for doc in documents
        ]
        return _response(400, {
            "success": False,
            "error": f"Document count ({total_docs}) exceeds maximum of {max_docs}.",
            "recommendation": (
                "Consolidate documents before retrying. Consider merging "
                "smaller docs into the reference doc or removing non-essential documents."
            ),
            "documents": manifest,
            "total_docs": total_docs,
            "max_docs": max_docs,
        })

    # 5. Build response
    if dry_run:
        # Manifest only — no content
        response_docs = [
            {k: v for k, v in doc.items() if k != "content"}
            for doc in documents
        ]
    else:
        response_docs = documents

    return _response(200, {
        "success": True,
        "project_id": project_id,
        "documents": response_docs,
        "total_docs": total_docs,
        "max_docs": max_docs,
        "prepared_at": _now_z(),
    })


def lambda_handler(event: Dict, context: Any) -> Dict:
    """API Gateway v2 proxy handler."""
    logger.info("doc_prep invoked: %s %s",
                event.get("requestContext", {}).get("http", {}).get("method", "?"),
                event.get("rawPath", "?"))

    http_ctx = event.get("requestContext", {}).get("http", {})
    method = http_ctx.get("method", "").upper()

    # CORS preflight
    if method == "OPTIONS":
        return {
            "statusCode": 204,
            "headers": _cors_headers(),
            "body": "",
        }

    if method == "POST":
        return _handle_post(event)

    return _error(405, f"Method {method} not allowed.")
