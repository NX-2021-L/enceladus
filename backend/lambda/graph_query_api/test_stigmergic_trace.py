"""Unit tests for ENC-FTR-109 / ENC-TSK-K05 stigmergic trace emission."""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from unittest import mock

import stigmergic_trace as st


class _FakeDdb:
    def __init__(self) -> None:
        self.items = []

    def put_item(self, TableName, Item):  # noqa: N803
        self.items.append({"TableName": TableName, "Item": Item})


class StigmergicTraceTests(unittest.TestCase):
    def test_build_trace_record_schema_and_ttl(self):
        fixed = datetime(2026, 7, 2, 10, 0, 0, tzinfo=timezone.utc)
        rec = st.build_trace_record(
            project_id="enceladus",
            session_id="ENC-SES-02L",
            event_type="retrieval",
            record_id_path=["ENC-TSK-K05", "ENC-FTR-109"],
            outcome_signal={"result_count": 2},
            now=fixed,
        )
        self.assertEqual(rec["schema"], st.STIGMERGIC_TRACE_SCHEMA)
        self.assertEqual(rec["session_id"], "ENC-SES-02L")
        self.assertEqual(rec["record_id_path"], "ENC-TSK-K05|ENC-FTR-109")
        self.assertEqual(json.loads(rec["outcome_signal"]), {"result_count": 2})
        self.assertEqual(rec["expires_at"], int(fixed.timestamp()) + 90 * 86400)

    def test_emit_puts_ddb_item(self):
        ddb = _FakeDdb()
        rec = st.build_trace_record(
            project_id="enceladus",
            session_id="s1",
            event_type="traversal",
            record_id_path=["ENC-PLN-006"],
            outcome_signal={"node_count": 1},
        )
        st.emit_stigmergic_trace(ddb, "enceladus-stigmergic-trace-gamma", rec)
        self.assertEqual(len(ddb.items), 1)
        self.assertEqual(ddb.items[0]["TableName"], "enceladus-stigmergic-trace-gamma")

    def test_record_id_path_from_graph_result_prefers_pathway_sequence(self):
        path = st.record_id_path_from_graph_result({
            "pathway": {"node_sequence": ["A", "B"]},
            "nodes": [{"record_id": "C"}],
        })
        self.assertEqual(path, ["A", "B", "C"])

    def test_lambda_emit_suppressed_without_table(self):
        import lambda_function as lf

        with mock.patch.object(lf, "STIGMERGIC_TRACE_TABLE", ""):
            with self.assertLogs(lf.logger, level="INFO") as cm:
                lf._emit_stigmergic_trace({
                    "project_id": "enceladus",
                    "session_id": "s1",
                    "event_type": "retrieval",
                    "record_id_path": "A",
                    "outcome_signal": {"result_count": 0},
                    "timestamp": "2026-07-02T10:00:00.000000Z",
                    "trace_id": "t1",
                    "schema": st.STIGMERGIC_TRACE_SCHEMA,
                    "expires_at": 1,
                })
        self.assertTrue(any("STIGMERGIC_TRACE" in line for line in cm.output))


if __name__ == "__main__":
    unittest.main()
