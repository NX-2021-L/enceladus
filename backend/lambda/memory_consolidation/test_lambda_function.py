"""Unit tests for the Memory Consolidation Lambda (ENC-TSK-I84).

All tests run without AWS: pure extraction/clustering helpers are tested
directly, and docstore I/O is exercised against in-memory fakes.

    python -m unittest backend.lambda.memory_consolidation.test_lambda_function -v
"""

from __future__ import annotations

import importlib.util
import os
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "memory_consolidation_lambda", os.path.join(_HERE, "lambda_function.py")
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


def _handoff(doc_id, related=None, source=None, title="", description="", updated_at="2026-06-30T00:00:00Z"):
    return {
        "document_id": doc_id,
        "document_subtype": "handoff",
        "related_items": related or [],
        "source_record_id": source or "",
        "title": title,
        "description": description,
        "updated_at": updated_at,
        "s3_bucket": "jreese-net",
        "s3_key": f"agent-documents/enceladus/{doc_id}.md",
    }


# ---------------------------------------------------------------------------
# id extraction
# ---------------------------------------------------------------------------

class TestIdExtraction(unittest.TestCase):
    def test_extract_tracker_and_doc_tokens(self):
        text = "Work on ENC-TSK-I84 and ENC-ISS-145; see DOC-499FA089EC30 and doc-abc123abc123."
        tokens = mod.extract_id_tokens(text)
        self.assertIn("ENC-TSK-I84", tokens)
        self.assertIn("ENC-ISS-145", tokens)
        self.assertIn("DOC-499FA089EC30", tokens)
        # lowercase doc id normalized to uppercase
        self.assertIn("DOC-ABC123ABC123", tokens)

    def test_extract_cited_ids_excludes_self(self):
        h = _handoff(
            "DOC-AAAAAAAAAAAA",
            related=["ENC-TSK-100", "DOC-AAAAAAAAAAAA"],
            source="ENC-FTR-096",
            title="HANDOFF — ENC-ISS-200",
        )
        cited = mod.extract_cited_ids(h)
        self.assertEqual(
            cited, {"ENC-TSK-100", "ENC-FTR-096", "ENC-ISS-200"}
        )
        self.assertNotIn("DOC-AAAAAAAAAAAA", cited)


# ---------------------------------------------------------------------------
# co-citation clustering (AC-2)
# ---------------------------------------------------------------------------

class TestCocitationClusters(unittest.TestCase):
    def test_pair_co_cited_across_two_handoffs_qualifies(self):
        handoffs = [
            _handoff("DOC-000000000001", related=["ENC-TSK-1", "ENC-TSK-2"]),
            _handoff("DOC-000000000002", related=["ENC-TSK-1", "ENC-TSK-2"]),
        ]
        clusters = mod.build_cocitation_clusters(handoffs, min_waves=2)
        self.assertEqual(len(clusters), 1)
        c = clusters[0]
        self.assertEqual(c["member_ids"], ["ENC-TSK-1", "ENC-TSK-2"])
        self.assertEqual(c["frequency_count"], 2)
        self.assertEqual(
            c["source_handoff_ids"], ["DOC-000000000001", "DOC-000000000002"]
        )

    def test_single_occurrence_does_not_qualify(self):
        handoffs = [
            _handoff("DOC-000000000001", related=["ENC-TSK-1", "ENC-TSK-2"]),
            _handoff("DOC-000000000002", related=["ENC-TSK-9", "ENC-TSK-8"]),
        ]
        clusters = mod.build_cocitation_clusters(handoffs, min_waves=2)
        self.assertEqual(clusters, [])

    def test_transitive_cluster_merges_overlapping_pairs(self):
        # (A,B) in two handoffs, (B,C) in two handoffs -> one cluster {A,B,C}
        handoffs = [
            _handoff("DOC-000000000001", related=["ENC-TSK-A", "ENC-TSK-B"]),
            _handoff("DOC-000000000002", related=["ENC-TSK-A", "ENC-TSK-B"]),
            _handoff("DOC-000000000003", related=["ENC-TSK-B", "ENC-TSK-C"]),
            _handoff("DOC-000000000004", related=["ENC-TSK-B", "ENC-TSK-C"]),
        ]
        clusters = mod.build_cocitation_clusters(handoffs, min_waves=2)
        self.assertEqual(len(clusters), 1)
        self.assertEqual(
            clusters[0]["member_ids"], ["ENC-TSK-A", "ENC-TSK-B", "ENC-TSK-C"]
        )
        self.assertEqual(clusters[0]["frequency_count"], 4)

    def test_handoff_with_fewer_than_two_citations_ignored(self):
        handoffs = [
            _handoff("DOC-000000000001", related=["ENC-TSK-1"]),
            _handoff("DOC-000000000002", related=["ENC-TSK-1"]),
        ]
        self.assertEqual(mod.build_cocitation_clusters(handoffs, min_waves=2), [])


# ---------------------------------------------------------------------------
# draft payload (AC-3, AC-9)
# ---------------------------------------------------------------------------

class TestDraftPayload(unittest.TestCase):
    def test_payload_fields(self):
        cluster = {
            "member_ids": ["ENC-TSK-1", "ENC-TSK-2"],
            "source_handoff_ids": ["DOC-000000000001", "DOC-000000000002"],
            "frequency_count": 2,
        }
        p = mod.draft_candidate_payload("enceladus", cluster)
        self.assertEqual(p["document_subtype"], "lesson-candidate")
        self.assertEqual(p["subtypepattern"], "lesson-candidate")
        self.assertEqual(p["handoff_status"], "pending")
        self.assertEqual(p["status"], "draft")
        # related_items point at the source Handoff docs (AC-3)
        self.assertEqual(
            p["related_items"], ["DOC-000000000001", "DOC-000000000002"]
        )
        self.assertTrue(p["document_id"].startswith("DOC-"))
        self.assertIn("lesson-candidate", p["keywords"])

    def test_doc_id_is_deterministic_per_cluster(self):
        cluster = {
            "member_ids": ["ENC-TSK-2", "ENC-TSK-1"],
            "source_handoff_ids": ["DOC-000000000001"],
            "frequency_count": 2,
        }
        a = mod.draft_candidate_payload("enceladus", dict(cluster))
        b = mod.draft_candidate_payload("enceladus", dict(cluster))
        self.assertEqual(a["document_id"], b["document_id"])


# ---------------------------------------------------------------------------
# io-approval gate (AC-4) + OGTM (AC-5)
# ---------------------------------------------------------------------------

class TestGates(unittest.TestCase):
    def test_io_gate_emits_zero_forbidden_ops(self):
        gate = mod._log_io_gate()
        self.assertEqual(
            gate, {"tracker_create": 0, "checkout_advance": 0, "lesson_promote": 0}
        )

    def test_ogtm_preflight_introduces_no_new_edge_types(self):
        og = mod._ogtm_preflight()
        self.assertEqual(og["new_edge_types"], [])
        self.assertFalse(og["graph_sync_modified"])
        self.assertTrue(og["compliant"])
        self.assertEqual(og["emitted_edge_types"], ["RELATED_TO"])

    def test_module_makes_no_governed_mutation_calls(self):
        # The Lambda must not *call* any governed mutation surface: no Lambda
        # invoke client, no HTTP client, no checkout/advance call. (Conceptual
        # references to the io promotion path in docstrings are allowed.)
        with open(os.path.join(_HERE, "lambda_function.py"), encoding="utf-8") as fh:
            src = fh.read()
        for forbidden in (
            "InvokeFunction",
            "invoke(",
            'client("lambda")',
            "client('lambda')",
            "import requests",
            "urllib.request",
            "advance_task_status",
        ):
            self.assertNotIn(forbidden, src)
        # Only dynamodb + s3 clients are constructed.
        self.assertIn('boto3.client("dynamodb"', src)
        self.assertIn('boto3.client("s3"', src)


# ---------------------------------------------------------------------------
# docstore put + idempotency (in-memory fakes)
# ---------------------------------------------------------------------------

class _CCFE(Exception):
    pass


class _FakeDDBExceptions:
    ConditionalCheckFailedException = _CCFE


class _FakeDDB:
    def __init__(self):
        self.items = {}
        self.exceptions = _FakeDDBExceptions()

    def get_item(self, TableName, Key, ConsistentRead=False):
        doc_id = Key["document_id"]["S"]
        item = self.items.get(doc_id)
        return {"Item": item} if item else {}

    def put_item(self, TableName, Item, ConditionExpression=None):
        doc_id = Item["document_id"]["S"]
        if ConditionExpression and "attribute_not_exists" in ConditionExpression and doc_id in self.items:
            raise self.exceptions.ConditionalCheckFailedException()
        self.items[doc_id] = Item


class _FakeS3:
    def __init__(self):
        self.objects = {}

    def put_object(self, Bucket, Key, Body, **kwargs):
        self.objects[(Bucket, Key)] = Body


class TestDocstorePut(unittest.TestCase):
    def setUp(self):
        self._ddb = _FakeDDB()
        self._s3 = _FakeS3()
        mod._ddb_client = self._ddb
        mod._s3_client = self._s3

    def tearDown(self):
        mod._ddb_client = None
        mod._s3_client = None

    def test_put_then_idempotent_skip(self):
        cluster = {
            "member_ids": ["ENC-TSK-1", "ENC-TSK-2"],
            "source_handoff_ids": ["DOC-000000000001", "DOC-000000000002"],
            "frequency_count": 2,
        }
        payload = mod.draft_candidate_payload("enceladus", cluster)

        first = mod._put_lesson_candidate(payload)
        self.assertEqual(first, "created")
        item = self._ddb.items[payload["document_id"]]
        self.assertEqual(item["document_subtype"]["S"], "lesson-candidate")
        self.assertEqual(item["handoff_status"]["S"], "pending")
        self.assertEqual(item["status"]["S"], "draft")
        self.assertEqual(item["record_type"]["S"], "document")
        self.assertEqual(item["write_source"]["M"]["channel"]["S"], "memory_consolidation_lambda")
        related = [v["S"] for v in item["related_items"]["L"]]
        self.assertEqual(related, ["DOC-000000000001", "DOC-000000000002"])

        # Second run with the same cluster must not duplicate.
        second = mod._put_lesson_candidate(payload)
        self.assertEqual(second, "exists")


# ---------------------------------------------------------------------------
# handler wiring (mocked scan) — must exit cleanly with io gate satisfied
# ---------------------------------------------------------------------------

class TestHandler(unittest.TestCase):
    def setUp(self):
        self._orig_scan = mod._scan_recent_handoffs
        self._orig_body = mod._read_document_body
        self._ddb = _FakeDDB()
        self._s3 = _FakeS3()
        mod._ddb_client = self._ddb
        mod._s3_client = self._s3

    def tearDown(self):
        mod._scan_recent_handoffs = self._orig_scan
        mod._read_document_body = self._orig_body
        mod._ddb_client = None
        mod._s3_client = None

    def test_handler_creates_candidate_and_reports_gate(self):
        handoffs = [
            _handoff("DOC-000000000001", related=["ENC-TSK-1", "ENC-TSK-2"]),
            _handoff("DOC-000000000002", related=["ENC-TSK-1", "ENC-TSK-2"]),
        ]
        mod._scan_recent_handoffs = lambda project_id, cutoff_iso: handoffs
        mod._read_document_body = lambda doc: ""

        result = mod.lambda_handler({}, None)
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(result["handoffs_scanned"], 2)
        self.assertEqual(result["clusters_found"], 1)
        self.assertEqual(result["candidates_created"], 1)
        self.assertEqual(
            result["io_gate"],
            {"tracker_create": 0, "checkout_advance": 0, "lesson_promote": 0},
        )
        self.assertTrue(result["ogtm"]["compliant"])
        self.assertEqual(result["ogtm"]["new_edge_types"], [])

    def test_handler_survives_project_error(self):
        def boom(project_id, cutoff_iso):
            raise RuntimeError("ddb down")

        mod._scan_recent_handoffs = boom
        result = mod.lambda_handler({}, None)
        self.assertEqual(result["statusCode"], 200)  # never raises (AC-1)
        self.assertEqual(result["candidates_created"], 0)
        self.assertIn("error", result["projects"][0])


class RhythmStanzaTests(unittest.TestCase):
    """ENC-TSK-N23: heavy-beat completion-stanza contract (tenant_invoker.py)."""

    def test_no_result_key_is_noop(self):
        from unittest import mock

        with mock.patch("boto3.client") as client:
            self.assertFalse(mod._write_rhythm_stanza({}, "completed", {}))
            self.assertFalse(mod._write_rhythm_stanza(None, "completed", {}))
            client.assert_not_called()

    def test_result_key_writes_contract_stanza(self):
        import json
        from unittest import mock

        key = "gamma/rhythm-cycle/heavy_integrate/tenant-results/20260712-000000/memory_consolidation.json"
        with mock.patch("boto3.client") as client:
            ok = mod._write_rhythm_stanza({"result_key": key}, "completed", {"candidates_created": 2})
        self.assertTrue(ok)
        kwargs = client.return_value.put_object.call_args.kwargs
        self.assertEqual(kwargs["Bucket"], mod.RHYTHM_RESULTS_BUCKET)
        self.assertEqual(kwargs["Key"], key)
        stanza = json.loads(kwargs["Body"].decode("utf-8"))
        self.assertEqual(stanza["tenant"], "memory_consolidation")
        self.assertEqual(stanza["status"], "completed")
        self.assertIn("completed_at", stanza)
        self.assertEqual(stanza["detail"], {"candidates_created": 2})

    def test_stanza_write_failure_never_raises(self):
        from unittest import mock

        with mock.patch("boto3.client", side_effect=RuntimeError("boom")):
            self.assertFalse(mod._write_rhythm_stanza({"result_key": "k"}, "completed", {}))


if __name__ == "__main__":
    unittest.main()
