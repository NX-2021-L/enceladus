"""test_docstore_metrics_p84.py — Tests for ENC-TSK-P84 (T-D3, FR-B6-1..2):
Enceladus/Docstore CloudWatch metrics emitted by patch_section outcomes.

Mirrors the MagicMock-based mocking style of test_hash_precondition_p70.py /
test_patch_section_handler_p71.py (no moto; _get_ddb / _get_s3 / _get_content /
_get_cloudwatch are patched directly on the document_api module object).

Covers:
  AC-1: _emit_patch_section_outcome_metric batches all datapoints of one
        outcome into a single put_metric_data call, with Namespace
        Enceladus/Docstore and dims ProjectId + Surface on every datapoint;
        PatchSectionAccepted additionally emits EditCostRatio (as a
        StatisticValues set) plus plain PatchBytes/DocumentBytes; a
        put_metric_data exception is swallowed (never raises, never changes
        the HTTP response). The handler wires PatchSectionRejected412 (412
        CONTENT_HASH_MISMATCH), AnchorNotFound (404 ANCHOR_NOT_FOUND),
        PatchSectionRejected409 (409 ANCHOR_AMBIGUOUS), and
        PatchSectionAccepted (the committed 200 write) to the surface
        returned by the same _derive_write_surface normalizer ENC-TSK-P72
        uses for the history-event `surface` field.

Run: python3 -m pytest test_docstore_metrics_p84.py -v
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(__file__))

_spec = importlib.util.spec_from_file_location(
    "document_api_docstore_metrics",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
document_api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(document_api)


CLAIMS = {"auth_mode": "internal-key", "sub": "internal-key"}
DOC_ID = "DOC-P84TEST0001"
CONTENT_A = "# Title\n\n## Alpha\n\nOriginal alpha body.\n\n## Beta\n\nBeta body.\n"
HASH_A = hashlib.sha256(CONTENT_A.encode("utf-8")).hexdigest()


class _CCFE(Exception):
    pass


def _doc_item(version=3, content_hash=HASH_A):
    return {
        "document_id": {"S": DOC_ID},
        "project_id": {"S": "enceladus"},
        "document_subtype": {"S": "doc"},
        "title": {"S": "Test doc"},
        "version": {"N": str(version)},
        "content_hash": {"S": content_hash},
        "s3_key": {"S": f"agent-documents/enceladus/{DOC_ID}.md"},
        "updated_at": {"S": "2026-09-15T00:00:00Z"},
    }


def _req(payload, if_match=None):
    body = dict(payload)
    if if_match is not None:
        body["if_match"] = if_match
    return {"body": json.dumps(body)}


def _base_payload(**overrides):
    payload = {
        "anchor": {"heading_path": ["Alpha"]},
        "op": "replace",
        "body": "New alpha body, a bit longer than the original.",
        "governance_hash": "abc123",
    }
    payload.update(overrides)
    return payload


class TestEmitPatchSectionOutcomeMetricShape(unittest.TestCase):
    """Direct unit tests of the fire-and-forget helper (no handler plumbing)."""

    @patch.object(document_api, "_get_cloudwatch")
    def test_accepted_batches_four_datapoints_in_one_call(self, mock_cw):
        fake_cw = MagicMock()
        mock_cw.return_value = fake_cw
        document_api._emit_patch_section_outcome_metric(
            "enceladus", "mcp", "PatchSectionAccepted", patch_bytes=50, document_bytes=200,
        )
        fake_cw.put_metric_data.assert_called_once()
        kwargs = fake_cw.put_metric_data.call_args.kwargs
        self.assertEqual(kwargs["Namespace"], "Enceladus/Docstore")
        names = [m["MetricName"] for m in kwargs["MetricData"]]
        self.assertEqual(
            names, ["PatchSectionAccepted", "EditCostRatio", "PatchBytes", "DocumentBytes"],
        )
        for m in kwargs["MetricData"]:
            self.assertEqual(
                m["Dimensions"],
                [{"Name": "ProjectId", "Value": "enceladus"}, {"Name": "Surface", "Value": "mcp"}],
            )
        accepted, ratio, pb, db = kwargs["MetricData"]
        self.assertEqual(accepted["Value"], 1)
        self.assertEqual(accepted["Unit"], "Count")
        self.assertEqual(
            ratio["StatisticValues"],
            {"SampleCount": 1, "Sum": 0.25, "Minimum": 0.25, "Maximum": 0.25},
        )
        self.assertEqual(pb["Value"], 50)
        self.assertEqual(pb["Unit"], "Bytes")
        self.assertEqual(db["Value"], 200)
        self.assertEqual(db["Unit"], "Bytes")

    @patch.object(document_api, "_get_cloudwatch")
    def test_accepted_zero_document_bytes_does_not_divide_by_zero(self, mock_cw):
        fake_cw = MagicMock()
        mock_cw.return_value = fake_cw
        document_api._emit_patch_section_outcome_metric(
            "enceladus", "mcp", "PatchSectionAccepted", patch_bytes=10, document_bytes=0,
        )
        kwargs = fake_cw.put_metric_data.call_args.kwargs
        ratio = kwargs["MetricData"][1]
        self.assertEqual(ratio["StatisticValues"]["Sum"], 0.0)

    @patch.object(document_api, "_get_cloudwatch")
    def test_rejected_412_emits_single_datapoint_no_edit_cost_ratio(self, mock_cw):
        fake_cw = MagicMock()
        mock_cw.return_value = fake_cw
        document_api._emit_patch_section_outcome_metric("enceladus", "pwa", "PatchSectionRejected412")
        kwargs = fake_cw.put_metric_data.call_args.kwargs
        self.assertEqual(len(kwargs["MetricData"]), 1)
        self.assertEqual(kwargs["MetricData"][0]["MetricName"], "PatchSectionRejected412")

    def test_metric_emission_never_raises_even_if_cloudwatch_client_fails(self):
        with patch.object(document_api, "_get_cloudwatch", side_effect=RuntimeError("no creds")):
            document_api._emit_patch_section_outcome_metric(
                "enceladus", "mcp", "PatchSectionAccepted", patch_bytes=1, document_bytes=1,
            )
        # Reaching here (no exception propagated) is the assertion.


class TestHandlerOutcomeMetricWiring(unittest.TestCase):
    @patch.object(document_api, "_emit_patch_section_outcome_metric")
    @patch.object(document_api, "_get_ddb")
    def test_content_hash_mismatch_emits_rejected_412(self, mock_ddb, mock_metric):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _doc_item(content_hash="1" * 64)}
        resp = document_api._handle_patch_section(_req(_base_payload(), if_match=HASH_A), CLAIMS, DOC_ID)
        self.assertEqual(resp["statusCode"], 412)
        mock_metric.assert_called_once_with("enceladus", "unknown", "PatchSectionRejected412")

    @patch.object(document_api, "_get_content")
    @patch.object(document_api, "_emit_patch_section_outcome_metric")
    @patch.object(document_api, "_get_ddb")
    def test_anchor_not_found_emits_anchor_not_found(self, mock_ddb, mock_metric, mock_content):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _doc_item()}
        mock_content.return_value = CONTENT_A
        payload = _base_payload(anchor={"heading_path": ["Nonexistent"]})
        resp = document_api._handle_patch_section(_req(payload, if_match=HASH_A), CLAIMS, DOC_ID)
        self.assertEqual(resp["statusCode"], 404)
        mock_metric.assert_called_once_with("enceladus", "unknown", "AnchorNotFound")

    @patch.object(document_api, "_get_content")
    @patch.object(document_api, "_emit_patch_section_outcome_metric")
    @patch.object(document_api, "_get_ddb")
    def test_anchor_ambiguous_emits_rejected_409(self, mock_ddb, mock_metric, mock_content):
        # Two "Beta" headings with no ordinal supplied -> ANCHOR_AMBIGUOUS (409).
        content = "# Title\n\n## Beta\n\nOne.\n\n## Beta\n\nTwo.\n"
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _doc_item(content_hash=content_hash)}
        mock_content.return_value = content
        payload = _base_payload(anchor={"heading_path": ["Beta"]})
        resp = document_api._handle_patch_section(
            _req(payload, if_match=content_hash), CLAIMS, DOC_ID,
        )
        self.assertEqual(resp["statusCode"], 409)
        self.assertEqual(json.loads(resp["body"])["error_envelope"]["code"], "ANCHOR_AMBIGUOUS")
        mock_metric.assert_called_once_with("enceladus", "unknown", "PatchSectionRejected409")

    @patch.object(document_api, "_get_content")
    @patch.object(document_api, "_get_s3")
    @patch.object(document_api, "_emit_patch_section_outcome_metric")
    @patch.object(document_api, "_get_ddb")
    def test_success_emits_accepted_with_byte_counts(self, mock_ddb, mock_metric, mock_s3, mock_content):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _doc_item(version=3, content_hash=HASH_A)}
        fake_ddb.exceptions.ConditionalCheckFailedException = _CCFE
        fake_s3 = MagicMock()
        mock_s3.return_value = fake_s3
        mock_content.return_value = CONTENT_A

        payload = _base_payload()
        resp = document_api._handle_patch_section(_req(payload, if_match=HASH_A), CLAIMS, DOC_ID)
        self.assertEqual(resp["statusCode"], 200)
        mock_metric.assert_called_once()
        call = mock_metric.call_args
        self.assertEqual(call.args[0], "enceladus")
        self.assertEqual(call.args[1], "unknown")
        self.assertEqual(call.args[2], "PatchSectionAccepted")
        self.assertEqual(
            call.kwargs["patch_bytes"], len(payload["body"].encode("utf-8")),
        )
        self.assertGreater(call.kwargs["document_bytes"], 0)

    @patch.object(document_api, "_get_content")
    @patch.object(document_api, "_get_s3")
    @patch.object(document_api, "_get_ddb")
    def test_success_path_survives_cloudwatch_failure(self, mock_ddb, mock_s3, mock_content):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _doc_item(version=3, content_hash=HASH_A)}
        fake_ddb.exceptions.ConditionalCheckFailedException = _CCFE
        fake_s3 = MagicMock()
        mock_s3.return_value = fake_s3
        mock_content.return_value = CONTENT_A

        with patch.object(document_api, "_get_cloudwatch", side_effect=RuntimeError("no creds")):
            resp = document_api._handle_patch_section(_req(_base_payload(), if_match=HASH_A), CLAIMS, DOC_ID)
        self.assertEqual(resp["statusCode"], 200)


if __name__ == "__main__":
    unittest.main()
