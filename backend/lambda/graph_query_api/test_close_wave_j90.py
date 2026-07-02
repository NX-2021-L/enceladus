"""Unit tests for ENC-TSK-J90 — wave-close orchestrator (close_wave action).

Exercises the S3 read-back + energy.records[] aggregation + drift-telemetry
drive-through purely with fakes/mocks (no live S3 or DynamoDB), matching the
client-injection conventions in test_flow_weight_refresh_j02.py and
test_pathway_telemetry_ftr082.py.

The aggregator (``_iter_wave_pathway_telemetry_records`` / ``_handle_close_wave``)
is the missing consumer that feeds ``compute_spurious_attractor_rate`` with the
real per-wave retrieval records emitted by every _query_hybrid call.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import drift_telemetry  # noqa: E402
import lambda_function as lf  # noqa: E402


class _FakeS3:
    """In-memory S3 stand-in: list_objects_v2 paginator over a fixed key set +
    get_object returning canned bodies (bytes)."""

    def __init__(self, bodies, pages=None):
        # bodies: {key: bytes-or-str}
        self._bodies = bodies
        # pages: optional list of page dicts to simulate pagination; default one
        # page containing every key in bodies.
        if pages is None:
            pages = [{"Contents": [{"Key": k} for k in bodies]}]
        self._pages = pages
        self.get_object_calls = []

    def get_paginator(self, name):
        assert name == "list_objects_v2"
        return self

    def paginate(self, Bucket, Prefix):
        self.paginate_prefix = Prefix
        for page in self._pages:
            yield page

    def get_object(self, Bucket, Key):
        self.get_object_calls.append(Key)
        body = self._bodies[Key]
        if isinstance(body, str):
            body = body.encode("utf-8")

        class _Body:
            def read(self_inner):
                return body

        return {"Body": _Body()}


def _telemetry_obj(records, wave_id="wave-1"):
    """A pathway-telemetry record (single-line JSONL body) with an energy block."""
    return json.dumps({
        "schema": "enceladus.pathway.telemetry.v1",
        "wave_id": wave_id,
        "project_id": "PROJ-1",
        "energy": {
            "schema": "enceladus.energy.v1",
            "lambda_graph": 0.5,
            "lambda_kw": 0.5,
            "records": records,
        },
    })


def _rec(record_id, avg):
    return {
        "record_id": record_id,
        "avg_retrieval_energy": avg,
        "retrieval_energy": [avg],
        "E_vector": 0.1,
        "E_PPR": 0.1,
        "E_keyword": 0.1,
        "graph_algorithm": "gds_pagerank",
    }


class TestIterWavePathwayTelemetry(unittest.TestCase):
    def test_no_bucket_configured_returns_empty(self):
        with mock.patch.object(lf, "PATHWAY_TELEMETRY_BUCKET", ""):
            records, seen, failed = lf._iter_wave_pathway_telemetry_records("wave-1")
        self.assertEqual((records, seen, failed), ([], 0, 0))

    def test_flattens_multiple_objects(self):
        bodies = {
            "pathway-telemetry/wave_id=wave-1/a.jsonl": _telemetry_obj([_rec("r1", 0.9)]),
            "pathway-telemetry/wave_id=wave-1/b.jsonl": _telemetry_obj([_rec("r2", 0.2), _rec("r3", 0.95)]),
        }
        s3 = _FakeS3(bodies)
        with mock.patch.object(lf, "PATHWAY_TELEMETRY_BUCKET", "bucket"), \
             mock.patch.object(lf, "PATHWAY_TELEMETRY_PREFIX", "pathway-telemetry"), \
             mock.patch.object(lf, "_get_s3", return_value=s3):
            records, seen, failed = lf._iter_wave_pathway_telemetry_records("wave-1")
        self.assertEqual(seen, 2)
        self.assertEqual(failed, 0)
        self.assertEqual(len(records), 2)  # 2 telemetry objects (records, not energy records)
        self.assertEqual(s3.paginate_prefix, "pathway-telemetry/wave_id=wave-1/")

    def test_multiline_jsonl_object_parsed_line_by_line(self):
        two_lines = _telemetry_obj([_rec("r1", 0.9)]) + "\n" + _telemetry_obj([_rec("r2", 0.1)])
        bodies = {"pathway-telemetry/wave_id=wave-1/multi.jsonl": two_lines}
        s3 = _FakeS3(bodies)
        with mock.patch.object(lf, "PATHWAY_TELEMETRY_BUCKET", "bucket"), \
             mock.patch.object(lf, "PATHWAY_TELEMETRY_PREFIX", "pathway-telemetry"), \
             mock.patch.object(lf, "_get_s3", return_value=s3):
            records, seen, failed = lf._iter_wave_pathway_telemetry_records("wave-1")
        self.assertEqual(seen, 1)
        self.assertEqual(len(records), 2)

    def test_malformed_line_skipped_not_fatal(self):
        good = _telemetry_obj([_rec("r1", 0.9)])
        bodies = {
            "pathway-telemetry/wave_id=wave-1/good.jsonl": good,
            "pathway-telemetry/wave_id=wave-1/bad.jsonl": "{not valid json",
        }
        s3 = _FakeS3(bodies)
        with mock.patch.object(lf, "PATHWAY_TELEMETRY_BUCKET", "bucket"), \
             mock.patch.object(lf, "PATHWAY_TELEMETRY_PREFIX", "pathway-telemetry"), \
             mock.patch.object(lf, "_get_s3", return_value=s3):
            records, seen, failed = lf._iter_wave_pathway_telemetry_records("wave-1")
        self.assertEqual(seen, 2)
        self.assertEqual(failed, 0)  # bad line skipped inside a readable object
        self.assertEqual(len(records), 1)

    def test_get_object_failure_counts_as_failed(self):
        s3 = _FakeS3({"pathway-telemetry/wave_id=wave-1/x.jsonl": _telemetry_obj([])})
        s3.get_object = mock.MagicMock(side_effect=RuntimeError("AccessDenied"))
        with mock.patch.object(lf, "PATHWAY_TELEMETRY_BUCKET", "bucket"), \
             mock.patch.object(lf, "PATHWAY_TELEMETRY_PREFIX", "pathway-telemetry"), \
             mock.patch.object(lf, "_get_s3", return_value=s3):
            records, seen, failed = lf._iter_wave_pathway_telemetry_records("wave-1")
        self.assertEqual((seen, failed), (1, 1))
        self.assertEqual(records, [])

    def test_list_failure_degrades_to_empty(self):
        s3 = mock.MagicMock()
        s3.get_paginator.side_effect = RuntimeError("ListDenied")
        with mock.patch.object(lf, "PATHWAY_TELEMETRY_BUCKET", "bucket"), \
             mock.patch.object(lf, "PATHWAY_TELEMETRY_PREFIX", "pathway-telemetry"), \
             mock.patch.object(lf, "_get_s3", return_value=s3):
            records, seen, failed = lf._iter_wave_pathway_telemetry_records("wave-1")
        self.assertEqual((records, seen, failed), ([], 0, 0))

    def test_pagination_across_pages(self):
        bodies = {
            "pathway-telemetry/wave_id=wave-1/p1.jsonl": _telemetry_obj([_rec("r1", 0.9)]),
            "pathway-telemetry/wave_id=wave-1/p2.jsonl": _telemetry_obj([_rec("r2", 0.1)]),
        }
        pages = [
            {"Contents": [{"Key": "pathway-telemetry/wave_id=wave-1/p1.jsonl"}]},
            {"Contents": [{"Key": "pathway-telemetry/wave_id=wave-1/p2.jsonl"}]},
        ]
        s3 = _FakeS3(bodies, pages=pages)
        with mock.patch.object(lf, "PATHWAY_TELEMETRY_BUCKET", "bucket"), \
             mock.patch.object(lf, "PATHWAY_TELEMETRY_PREFIX", "pathway-telemetry"), \
             mock.patch.object(lf, "_get_s3", return_value=s3):
            records, seen, failed = lf._iter_wave_pathway_telemetry_records("wave-1")
        self.assertEqual(seen, 2)


class TestHandleCloseWave(unittest.TestCase):
    def _run(self, s3, event, table="drift-table"):
        captured = {}

        def _fake_emit(**kwargs):
            captured.update(kwargs)
            # Mirror the real function's return shape closely enough for the test.
            return drift_telemetry.build_drift_record(
                wave_id=kwargs["wave_id"],
                project_id=kwargs["project_id"],
                d_centroid_L2=None,
                d_spectral_value=None,
                prev_wave_id=kwargs.get("prev_wave_id"),
                spurious_attractor_rate=drift_telemetry.compute_spurious_attractor_rate(
                    kwargs.get("retrieval_records")
                ),
            )

        with mock.patch.object(lf, "PATHWAY_TELEMETRY_BUCKET", "bucket"), \
             mock.patch.object(lf, "PATHWAY_TELEMETRY_PREFIX", "pathway-telemetry"), \
             mock.patch.object(lf, "DRIFT_TELEMETRY_TABLE", table), \
             mock.patch.object(lf, "_get_s3", return_value=s3), \
             mock.patch.object(lf, "_get_dynamodb", return_value=mock.MagicMock()), \
             mock.patch.object(drift_telemetry, "compute_and_emit_wave_close_drift",
                               side_effect=_fake_emit) as emit:
            resp = lf._handle_close_wave(event)
        return resp, captured, emit

    def test_missing_ids_returns_400(self):
        resp, _, _ = self._run(_FakeS3({}), {"action": "close_wave", "project_id": "PROJ-1"})
        self.assertEqual(resp["statusCode"], 400)

    def test_no_table_returns_503(self):
        resp, _, _ = self._run(
            _FakeS3({}), {"action": "close_wave", "project_id": "PROJ-1", "wave_id": "wave-1"}, table=""
        )
        self.assertEqual(resp["statusCode"], 503)

    def test_aggregates_energy_records_and_computes_rate(self):
        # 3 energy records across 2 telemetry objects; 2 of 3 exceed 0.85.
        bodies = {
            "pathway-telemetry/wave_id=wave-1/a.jsonl": _telemetry_obj([_rec("r1", 0.90), _rec("r2", 0.20)]),
            "pathway-telemetry/wave_id=wave-1/b.jsonl": _telemetry_obj([_rec("r3", 0.95)]),
        }
        s3 = _FakeS3(bodies)
        resp, captured, emit = self._run(
            s3, {"action": "close_wave", "project_id": "PROJ-1", "wave_id": "wave-1", "prev_wave_id": "wave-0"}
        )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        # Aggregation: 3 energy records flattened from 2 objects.
        self.assertEqual(body["records_aggregated"], 3)
        self.assertEqual(body["objects_seen"], 2)
        # The exact combined retrieval_records list reached the drift function.
        passed = captured["retrieval_records"]
        self.assertEqual([r["record_id"] for r in passed], ["r1", "r2", "r3"])
        self.assertEqual(captured["project_id"], "PROJ-1")
        self.assertEqual(captured["wave_id"], "wave-1")
        self.assertEqual(captured["prev_wave_id"], "wave-0")
        # 2/3 records exceed the 0.85 WARNING threshold.
        self.assertAlmostEqual(body["emitted"]["spurious_attractor_rate"], 2 / 3)
        emit.assert_called_once()

    def test_empty_wave_degrades_cleanly(self):
        # No S3 objects for the wave: still call through with empty list, rate=None.
        s3 = _FakeS3({})
        resp, captured, emit = self._run(
            s3, {"action": "close_wave", "project_id": "PROJ-1", "wave_id": "empty-wave"}
        )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["records_aggregated"], 0)
        self.assertEqual(body["objects_seen"], 0)
        self.assertEqual(captured["retrieval_records"], [])
        self.assertIsNone(body["emitted"]["spurious_attractor_rate"])
        emit.assert_called_once()

    def test_records_without_energy_block_ignored(self):
        # A telemetry object with no energy block contributes nothing.
        no_energy = json.dumps({"schema": "enceladus.pathway.telemetry.v1", "wave_id": "wave-1"})
        bodies = {
            "pathway-telemetry/wave_id=wave-1/plain.jsonl": no_energy,
            "pathway-telemetry/wave_id=wave-1/withenergy.jsonl": _telemetry_obj([_rec("r1", 0.9)]),
        }
        s3 = _FakeS3(bodies)
        resp, captured, _ = self._run(
            s3, {"action": "close_wave", "project_id": "PROJ-1", "wave_id": "wave-1"}
        )
        self.assertEqual(resp["statusCode"], 200)
        self.assertEqual([r["record_id"] for r in captured["retrieval_records"]], ["r1"])


class TestDispatch(unittest.TestCase):
    def test_close_wave_action_routes_to_handler(self):
        with mock.patch.object(lf, "_handle_close_wave", return_value={"statusCode": 200}) as h:
            lf.lambda_handler({"action": "close_wave", "project_id": "P", "wave_id": "w"}, None)
        h.assert_called_once()


if __name__ == "__main__":
    unittest.main()
