"""Regression test for ENC-TSK-C49 document record_id normalization.

Documents use 'document_id' as their DynamoDB primary key, not 'record_id'.
Prior to this fix _upsert_node and _reconcile_edges silently bailed out on
every document stream event because record.get("record_id", ...) returned
empty. _process_record now normalizes the record so downstream Cypher runs.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import types
import unittest
from unittest.mock import MagicMock


def _load_lambda_module():
    """Load graph_sync/lambda_function.py as a standalone module.

    Stubs the `neo4j` dependency so the import succeeds in test environments
    that don't vendor the driver. We don't touch Neo4j at runtime here.
    """
    if "neo4j" not in sys.modules:
        fake_neo4j = types.ModuleType("neo4j")
        fake_neo4j.GraphDatabase = MagicMock()
        sys.modules["neo4j"] = fake_neo4j

    here = pathlib.Path(__file__).resolve().parent
    src = here / "lambda_function.py"
    spec = importlib.util.spec_from_file_location(
        "graph_sync_lambda_function_under_test", src
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GS = _load_lambda_module()


def _dynamodb_image_for_document(
    document_id: str, title: str = "Test Document"
) -> dict:
    """Build a DynamoDB-typed NewImage for a document item.

    Document items are keyed by `document_id` in DynamoDB, with no top-level
    `record_id` attribute. This mirrors the production docstore shape.
    """
    return {
        "document_id": {"S": document_id},
        "record_type": {"S": "document"},
        "project_id": {"S": "enceladus"},
        "title": {"S": title},
        "status": {"S": "active"},
        "created_at": {"S": "2026-04-08T00:00:00Z"},
        "updated_at": {"S": "2026-04-08T09:30:00Z"},
    }


class TestDocumentRecordIdNormalization(unittest.TestCase):
    def setUp(self):
        # Snapshot the originals so monkey-patches in one test do not
        # leak into other tests (the third test exercises the real
        # _upsert_node function).
        self._orig_upsert_node = GS._upsert_node
        self._orig_reconcile_edges = GS._reconcile_edges
        self._orig_upsert_project_node = GS._upsert_project_node

    def tearDown(self):
        GS._upsert_node = self._orig_upsert_node
        GS._reconcile_edges = self._orig_reconcile_edges
        GS._upsert_project_node = self._orig_upsert_project_node

    def test_process_record_normalizes_document_id_to_record_id(self):
        """_process_record must copy document_id -> record_id for documents."""
        captured: dict = {}

        def fake_upsert_node(tx, record):
            captured["upsert_record"] = dict(record)

        def fake_reconcile_edges(tx, record):
            captured["reconcile_record"] = dict(record)

        def fake_upsert_project_node(tx, project_id):
            captured["project_id"] = project_id

        # Patch the three write helpers to capture the normalized record.
        GS._upsert_node = fake_upsert_node  # type: ignore[assignment]
        GS._reconcile_edges = fake_reconcile_edges  # type: ignore[assignment]
        GS._upsert_project_node = fake_upsert_project_node  # type: ignore[assignment]

        # Minimal driver stub that matches the `with driver.session() as s`
        # + s.execute_write(lambda tx: fn(tx, ...)) contract.
        driver = MagicMock()
        session_cm = MagicMock()
        driver.session.return_value = session_cm
        session_cm.__enter__.return_value = session_cm
        session_cm.__exit__.return_value = False
        session_cm.execute_write.side_effect = lambda fn: fn(MagicMock())

        stream_record = {
            "eventName": "MODIFY",
            "dynamodb": {"NewImage": _dynamodb_image_for_document("DOC-TEST-123")},
        }

        GS._process_record(driver, stream_record)

        self.assertIn("upsert_record", captured, "_upsert_node was not invoked")
        self.assertEqual(
            captured["upsert_record"].get("record_id"),
            "DOC-TEST-123",
            "record_id must be normalized from document_id before _upsert_node runs",
        )
        self.assertEqual(captured["upsert_record"].get("record_type"), "document")
        self.assertIn("reconcile_record", captured)
        self.assertEqual(
            captured["reconcile_record"].get("record_id"),
            "DOC-TEST-123",
            "record_id must also flow through to _reconcile_edges",
        )
        self.assertEqual(captured.get("project_id"), "enceladus")

    def test_process_record_preserves_existing_record_id(self):
        """If a document record already has record_id, don't clobber it."""
        captured: dict = {}

        def fake_upsert_node(tx, record):
            captured["upsert_record"] = dict(record)

        GS._upsert_node = fake_upsert_node  # type: ignore[assignment]
        GS._reconcile_edges = lambda tx, record: None  # type: ignore[assignment]
        GS._upsert_project_node = lambda tx, project_id: None  # type: ignore[assignment]

        driver = MagicMock()
        session_cm = MagicMock()
        driver.session.return_value = session_cm
        session_cm.__enter__.return_value = session_cm
        session_cm.__exit__.return_value = False
        session_cm.execute_write.side_effect = lambda fn: fn(MagicMock())

        image = _dynamodb_image_for_document("DOC-TEST-456")
        image["record_id"] = {"S": "DOC-EXPLICIT-999"}
        stream_record = {"eventName": "MODIFY", "dynamodb": {"NewImage": image}}

        GS._process_record(driver, stream_record)

        self.assertEqual(
            captured["upsert_record"].get("record_id"),
            "DOC-EXPLICIT-999",
            "existing record_id must not be overwritten by document_id",
        )

    def test_upsert_node_no_longer_bails_out_for_document(self):
        """_upsert_node must run MERGE Cypher for a normalized document record.

        This reproduces the production bug: prior to the fix,
        record.get("record_id") was "" for documents and _upsert_node bailed
        out at `if not record_id: return` without calling tx.run.
        """
        tx = MagicMock()
        record = {
            "record_type": "document",
            "record_id": "DOC-TEST-789",  # normalized shape
            "project_id": "enceladus",
            "title": "Normalized Doc",
            "status": "active",
        }
        GS._upsert_node(tx, record)
        self.assertTrue(
            tx.run.called, "_upsert_node must call tx.run for a normalized document"
        )
        # First positional arg is the Cypher string.
        cypher = tx.run.call_args[0][0]
        self.assertIn("Document", cypher)
        self.assertIn("MERGE", cypher)

    def test_process_remove_uses_document_id_key_for_document_delete(self):
        """REMOVE events from the documents table must resolve document_id."""
        captured: dict = {}

        def fake_delete_node(tx, record_id):
            captured["deleted_record_id"] = record_id

        def fake_purge(tx, refs):
            captured["purge_refs"] = set(refs)

        GS._delete_node = fake_delete_node  # type: ignore[assignment]
        GS._purge_orphan_placeholders = fake_purge  # type: ignore[assignment]

        driver = MagicMock()
        session_cm = MagicMock()
        driver.session.return_value = session_cm
        session_cm.__enter__.return_value = session_cm
        session_cm.__exit__.return_value = False
        session_cm.execute_write.side_effect = lambda fn: fn(MagicMock())

        stream_record = {
            "eventName": "REMOVE",
            "dynamodb": {
                "Keys": {"document_id": {"S": "DOC-REMOVE-123"}},
                "OldImage": _dynamodb_image_for_document("DOC-REMOVE-123"),
            },
        }

        GS._process_record(driver, stream_record)

        self.assertEqual(captured.get("deleted_record_id"), "DOC-REMOVE-123")
        self.assertNotIn("purge_refs", captured)

    def test_process_remove_purges_orphan_placeholders_from_old_document_edges(self):
        """REMOVE should purge placeholder stubs that only existed for old doc edges."""
        captured: dict = {}

        def fake_delete_node(tx, record_id):
            captured["deleted_record_id"] = record_id

        def fake_purge(tx, refs):
            captured["purge_refs"] = set(refs)

        GS._delete_node = fake_delete_node  # type: ignore[assignment]
        GS._purge_orphan_placeholders = fake_purge  # type: ignore[assignment]

        driver = MagicMock()
        session_cm = MagicMock()
        driver.session.return_value = session_cm
        session_cm.__enter__.return_value = session_cm
        session_cm.__exit__.return_value = False
        session_cm.execute_write.side_effect = lambda fn: fn(MagicMock())

        image = _dynamodb_image_for_document("DOC-REMOVE-EDGE")
        image["related_items"] = {"L": [{"S": "ENC-TSK-999"}]}
        stream_record = {
            "eventName": "REMOVE",
            "dynamodb": {
                "Keys": {"document_id": {"S": "DOC-REMOVE-EDGE"}},
                "OldImage": image,
            },
        }

        GS._process_record(driver, stream_record)

        self.assertEqual(captured.get("deleted_record_id"), "DOC-REMOVE-EDGE")
        self.assertEqual(
            captured.get("purge_refs"),
            {("Task", "ENC-TSK-999")},
            "document REMOVE should surface old placeholder targets for cleanup",
        )


if __name__ == "__main__":
    unittest.main()
