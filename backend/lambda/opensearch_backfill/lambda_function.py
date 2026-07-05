#!/usr/bin/env python3
"""devops-opensearch-backfill — full-corpus OpenSearch backfill (ENC-TSK-L42).

Paginated scan of tracker + documents DynamoDB tables, bulk-indexing into
OpenSearch via records_write (or a physical records_v{n} index during reindex).
Uses the same document mapping and external-version idempotency contract as the
L41 CDC indexer (search_index_core). Gamma-only; manual invoke.

Invocation (product-lead terminal):
    aws lambda invoke --function-name devops-opensearch-backfill-gamma \\
      --payload '{"dry_run": true, "limit": 50}' /tmp/out.json

Reindex workflow (AC-2):
    1. apply_records_index.py --mode create-only --version 2
    2. invoke backfill with {"target_index": "records_v2"}
    3. apply_records_index.py --mode swap --version 2 [--delete-old]
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import boto3

from search_index_core import build_index_action, bulk_execute, is_success_status

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

TRACKER_TABLE = os.environ.get("TRACKER_TABLE", "devops-project-tracker")
DOCUMENTS_TABLE = os.environ.get("DOCUMENTS_TABLE", "documents")
DDB_REGION = os.environ.get("DDB_REGION", os.environ.get("AWS_REGION", "us-west-2"))
DEFAULT_WRITE_ALIAS = os.environ.get("OPENSEARCH_WRITE_ALIAS", "records_write")

_ddb = None


def _get_ddb():
    global _ddb
    if _ddb is None:
        _ddb = boto3.resource("dynamodb", region_name=DDB_REGION)
    return _ddb


def _iter_tracker_items() -> Iterable[Dict[str, Any]]:
    table = _get_ddb().Table(TRACKER_TABLE)
    kwargs: Dict[str, Any] = {}
    while True:
        resp = table.scan(**kwargs)
        for item in resp.get("Items", []):
            record_id = str(item.get("record_id") or "")
            if not record_id or record_id.startswith("COUNTER-"):
                continue
            if record_id.startswith("rel#"):
                continue
            yield item
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        kwargs["ExclusiveStartKey"] = last_key


def _iter_document_items() -> Iterable[Dict[str, Any]]:
    table = _get_ddb().Table(DOCUMENTS_TABLE)
    kwargs: Dict[str, Any] = {}
    while True:
        resp = table.scan(**kwargs)
        for item in resp.get("Items", []):
            document_id = str(item.get("document_id") or "")
            if not document_id:
                continue
            if str(item.get("status") or "active") != "active":
                continue
            if not item.get("record_type"):
                item["record_type"] = "document"
            if not item.get("record_id"):
                item["record_id"] = document_id
            yield item
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        kwargs["ExclusiveStartKey"] = last_key


def _iter_corpus(sources: Set[str]) -> Iterable[Tuple[str, Dict[str, Any]]]:
    if "tracker" in sources:
        for item in _iter_tracker_items():
            yield "tracker", item
    if "documents" in sources:
        for item in _iter_document_items():
            yield "documents", item


def _flush_batch(
    batch: List[Tuple[str, Dict[str, Any]]],
    target_index: str,
    dry_run: bool,
) -> Tuple[int, int]:
    if not batch:
        return 0, 0
    if dry_run:
        return len(batch), 0
    results = bulk_execute(batch, target_index)
    errors = sum(1 for status, _ in results if not is_success_status(status))
    return len(batch), errors


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    started = time.time()
    payload = event or {}
    if isinstance(payload.get("body"), str):
        try:
            payload = {**payload, **json.loads(payload["body"])}
        except json.JSONDecodeError:
            pass

    dry_run = bool(payload.get("dry_run", False))
    limit = payload.get("limit")
    if limit is not None:
        limit = int(limit)
    batch_size = int(payload.get("batch_size") or 100)
    batch_size = max(1, min(batch_size, 500))
    target_index = str(payload.get("target_index") or DEFAULT_WRITE_ALIAS).strip()
    raw_sources = payload.get("sources") or ["tracker", "documents"]
    sources: Set[str] = {str(s).lower() for s in raw_sources}
    sources &= {"tracker", "documents"}
    if not sources:
        sources = {"tracker", "documents"}

    indexed = 0
    skipped = 0
    errors = 0
    pending: List[Tuple[str, Dict[str, Any]]] = []

    for source_name, item in _iter_corpus(sources):
        if limit is not None and indexed + skipped >= limit:
            break
        action = build_index_action(item, target_index)
        if action is None:
            skipped += 1
            continue
        pending.append(action)
        if len(pending) >= batch_size:
            flushed, batch_errors = _flush_batch(pending, target_index, dry_run)
            indexed += flushed
            errors += batch_errors
            pending = []
            if batch_errors:
                logger.warning("[WARN] Bulk batch had %d errors (source=%s)", batch_errors, source_name)

    if pending:
        flushed, batch_errors = _flush_batch(pending, target_index, dry_run)
        indexed += flushed
        errors += batch_errors

    elapsed = round(time.time() - started, 2)
    status = "ok" if errors == 0 else "partial"
    result = {
        "status": status,
        "indexed": indexed,
        "skipped": skipped,
        "errors": errors,
        "dry_run": dry_run,
        "target_index": target_index,
        "sources": sorted(sources),
        "batch_size": batch_size,
        "elapsed_seconds": elapsed,
    }
    logger.info("[INFO] Backfill complete: %s", result)
    return result
