"""ENC-TSK-N23: heavy-beat completion-stanza contract tests
(backend/lambda/rhythm_cycle/tenant_invoker.py contract) for the
graph_health_metrics tenant. Runs without Neo4j/CloudWatch."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

_HERE = Path(__file__).resolve().parent
sys.path.append(str(_HERE.parent / "graph_query_api"))
sys.path.insert(0, str(_HERE))

import lambda_function as lf  # noqa: E402


class RhythmStanzaTests(unittest.TestCase):
    def test_no_result_key_is_noop(self):
        with mock.patch.object(lf.boto3, "client") as client:
            self.assertFalse(lf._write_rhythm_stanza({}, "completed", {}))
            client.assert_not_called()

    def test_result_key_writes_contract_stanza(self):
        key = "gamma/rhythm-cycle/heavy_integrate/tenant-results/20260712-000000/graph_health_metrics.json"
        with mock.patch.object(lf.boto3, "client") as client:
            ok = lf._write_rhythm_stanza({"result_key": key}, "completed", {"statusCode": 200})
        self.assertTrue(ok)
        kwargs = client.return_value.put_object.call_args.kwargs
        self.assertEqual(kwargs["Bucket"], lf.RHYTHM_RESULTS_BUCKET)
        self.assertEqual(kwargs["Key"], key)
        stanza = json.loads(kwargs["Body"].decode("utf-8"))
        self.assertEqual(stanza["tenant"], "graph_health_metrics")
        self.assertEqual(stanza["status"], "completed")
        self.assertIn("completed_at", stanza)

    def test_stanza_write_failure_never_raises(self):
        with mock.patch.object(lf.boto3, "client", side_effect=RuntimeError("boom")):
            self.assertFalse(lf._write_rhythm_stanza({"result_key": "k"}, "failed", {}))


if __name__ == "__main__":
    unittest.main()
