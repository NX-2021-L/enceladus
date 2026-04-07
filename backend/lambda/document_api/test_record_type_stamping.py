"""Regression tests for ENC-PLN-014 / ENC-FTR-065 record_type stamping.

These tests assert that the document_api Lambda stamps record_type="document"
on every DynamoDB write path so that DynamoDB Streams events flow through the
graph_sync record-type dispatch and project Document nodes to Neo4j.

Three write sites are covered:

1. Internal sync put_item (_upsert_synced_document, no-existing branch)
2. Primary document creation put_item (POST /api/v1/documents)
3. Edit / update_item (PATCH /api/v1/documents/{id})

The test approach loads the lambda module via importlib (mirroring the
pattern in feed_query/test_lambda_function.py) and substitutes a fake
DynamoDB client that captures the request payload.
"""

from __future__ import annotations

import importlib.util
import os
from typing import Any, Dict, List


_SPEC = importlib.util.spec_from_file_location(
    "document_api_lambda",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
document_api = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(document_api)


# ---------------------------------------------------------------------------
# Fake DynamoDB / S3 plumbing
# ---------------------------------------------------------------------------


class _FakeDDBExceptions:
    class ConditionalCheckFailedException(Exception):
        pass


class _FakeDDB:
    """Captures put_item / update_item arguments for assertion."""

    def __init__(self, existing_item: Dict[str, Any] | None = None) -> None:
        self.put_calls: List[Dict[str, Any]] = []
        self.update_calls: List[Dict[str, Any]] = []
        self._existing_item = existing_item
        self.exceptions = _FakeDDBExceptions()

    def put_item(self, **kwargs: Any) -> Dict[str, Any]:
        self.put_calls.append(kwargs)
        return {}

    def update_item(self, **kwargs: Any) -> Dict[str, Any]:
        self.update_calls.append(kwargs)
        return {}

    def get_item(self, **_kwargs: Any) -> Dict[str, Any]:
        if self._existing_item is None:
            return {}
        return {"Item": self._existing_item}


class _FakeS3:
    def put_object(self, **_kwargs: Any) -> Dict[str, Any]:
        return {}

    def delete_object(self, **_kwargs: Any) -> Dict[str, Any]:
        return {}


def _install_fakes(monkeypatch, ddb: _FakeDDB) -> None:
    monkeypatch.setattr(document_api, "_get_ddb", lambda: ddb)
    monkeypatch.setattr(document_api, "_get_s3", lambda: _FakeS3())
    # Bypass S3 upload helpers used by both create and edit handlers.
    monkeypatch.setattr(
        document_api,
        "_put_document_content_bytes",
        lambda project_id, document_id, content_bytes: (
            f"agent-documents/{project_id}/{document_id}.md",
            "deadbeef" * 8,
            len(content_bytes),
        ),
    )
    monkeypatch.setattr(
        document_api,
        "_upload_content",
        lambda project_id, document_id, content: (
            f"agent-documents/{project_id}/{document_id}.md",
            "deadbeef" * 8,
            len(content.encode("utf-8")),
        ),
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_sync_put_item_stamps_record_type(monkeypatch):
    """_upsert_synced_document(existing=None) must stamp record_type='document'."""
    ddb = _FakeDDB(existing_item=None)
    _install_fakes(monkeypatch, ddb)

    document_api._upsert_synced_document(
        existing=None,
        project_id="enceladus",
        file_name="test.md",
        title="Test Document",
        description="A regression test document.",
        keywords=["test"],
        content_bytes=b"# Test",
    )

    assert len(ddb.put_calls) == 1, "expected exactly one put_item call"
    item = ddb.put_calls[0]["Item"]
    assert "record_type" in item, "record_type must be stamped on sync put_item"
    assert item["record_type"] == {"S": "document"}, (
        f"expected record_type=document, got {item['record_type']!r}"
    )


def test_sync_update_item_backfills_record_type(monkeypatch):
    """_upsert_synced_document(existing=...) must include record_type if_not_exists."""
    existing_doc = {
        "document_id": "DOC-OLD12345678",
        "project_id": "enceladus",
        "title": "Old Doc",
        "version": 3,
    }
    ddb = _FakeDDB(existing_item=existing_doc)
    _install_fakes(monkeypatch, ddb)

    document_api._upsert_synced_document(
        existing=existing_doc,
        project_id="enceladus",
        file_name="old.md",
        title="Updated Title",
        description="Updated.",
        keywords=["updated"],
        content_bytes=b"# Updated",
    )

    assert len(ddb.update_calls) == 1, "expected exactly one update_item call"
    call = ddb.update_calls[0]
    update_expr = call["UpdateExpression"]
    attr_values = call["ExpressionAttributeValues"]
    assert "record_type = if_not_exists(record_type, :rtype)" in update_expr, (
        f"sync update_item must backfill record_type via if_not_exists, got: {update_expr}"
    )
    assert ":rtype" in attr_values, "missing :rtype expression attribute value"
    assert attr_values[":rtype"] == {"S": "document"}


def _read_lambda_source() -> str:
    src_path = os.path.join(os.path.dirname(__file__), "lambda_function.py")
    with open(src_path, "r", encoding="utf-8") as f:
        return f.read()


def test_create_document_put_item_stamps_record_type():
    """The create-document item dict literal must stamp record_type='document'.

    The full POST /documents handler has many validation gates that are not
    germane to ENC-PLN-014; we assert the stamping is present in the source
    by verifying the create-handler item dict contains the literal field.
    """
    src = _read_lambda_source()
    # The create handler item dict (around line 1100) is the only one that
    # carries document_subtype + compliance_checked_at; locate that block and
    # assert record_type is stamped within it.
    create_block_marker = '"compliance_checked_at": {"S": now},'
    assert create_block_marker in src, (
        "create-document item dict not found — has the file structure changed?"
    )
    block_start = src.index(create_block_marker)
    # Look ahead in a window for the record_type stamp.
    window = src[block_start:block_start + 800]
    assert '"record_type": {"S": "document"}' in window, (
        "create-document put_item must stamp record_type='document'"
    )


def test_patch_document_update_item_backfills_record_type():
    """The PATCH /documents/{id} update_item path must backfill record_type via if_not_exists.

    Verified by static source inspection of the expr_parts list initializer
    used by the patch handler. The full HTTP path has many validation gates
    that are not germane to ENC-PLN-014.
    """
    src = _read_lambda_source()
    # The patch handler is the only place expr_parts is initialized with
    # both updated_at and the version increment together.
    init_marker = (
        '"updated_at = :ts",\n'
        '        "record_type = if_not_exists(record_type, :rtype)",\n'
        '        "#ver = #ver + :one"'
    )
    assert init_marker in src, (
        "patch handler expr_parts initializer must include record_type if_not_exists "
        "backfill (ENC-PLN-014)"
    )
    assert '":rtype": {"S": "document"}' in src, (
        "patch handler attr_values must define :rtype = document"
    )
