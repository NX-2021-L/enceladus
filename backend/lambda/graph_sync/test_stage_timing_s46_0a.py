"""ENC-TSK-S46-0A: graph_sync per-record BRD 7.1 stage fields on the consumer [WRITE-AUDIT] line.

Run: python3 -m pytest test_stage_timing_s46_0a.py -q
"""
import contextlib
import io
import json
import unittest
from unittest.mock import MagicMock, patch

import lambda_function as lf

ARN = "arn:aws:dynamodb:us-west-2:123:table/devops-project-tracker/stream/2026-11-04T00:00:00.000"


def _img(vseq=7, **extra):
    img = {"project_id": {"S": "enceladus"}, "record_id": {"S": "task#ENC-TSK-1"}, "item_id": {"S": "ENC-TSK-1"},
           "version_seq": {"N": str(vseq)}, "t_ack": {"N": "1000"}, "correlation_id": {"S": "corr-1"}}
    img.update(extra)
    return img


def _rec(seq, new, old=None, creation=1.5):
    d = {"SequenceNumber": seq, "NewImage": new, "ApproximateCreationDateTime": creation}
    if old is not None:
        d["OldImage"] = old
    return {"eventName": "MODIFY", "eventSourceARN": ARN, "dynamodb": d}


class _Ctx:
    memory_limit_in_mb = "512"


class _FakeTx:
    def __init__(self):
        self.queries = []

    def run(self, q, **kw):
        self.queries.append(q)


def _fake_driver():
    tx = _FakeTx()
    session = MagicMock()
    session.execute_write.side_effect = lambda fn, *a, **k: fn(tx)
    session.execute_read.side_effect = lambda fn, *a, **k: fn(tx)
    driver = MagicMock()
    driver.session.return_value.__enter__.return_value = session
    return driver, tx


def _project(driver, stream_record):
    with driver.session() as s:
        s.execute_read(lambda tx: tx.run("MATCH (n) RETURN n"))
        s.execute_write(lambda tx: tx.run("MERGE (n:Task {record_id: $r})", r="x"))
        s.execute_write(lambda tx: tx.run("MATCH (s), (t) MERGE (s)-[r:RELATED_TO {a: 1}]->(t)"))
        s.execute_write(lambda tx: tx.run("MATCH (n)-[r]->() DELETE r"))
    lf._WA_REC["mark_ms"] += 1.25


class StageTimingTests(unittest.TestCase):
    def _run(self, records, driver, ctx=_Ctx(), process=None):
        buf = io.StringIO()
        with patch.object(lf, "_get_neo4j_driver", return_value=driver), \
                patch.object(lf, "_process_record", side_effect=process or _project), \
                contextlib.redirect_stdout(buf):
            lf.handler({"Records": records}, ctx)
        return [json.loads(l.split("[WRITE-AUDIT] ", 1)[1]) for l in buf.getvalue().splitlines()
                if l.startswith("[WRITE-AUDIT] ")]

    def test_stage_fields_present_with_types_and_existing_fields_kept(self):
        driver, _ = _fake_driver()
        lines = self._run([_rec("1", _img()), _rec("2", _img(vseq=8))], driver)
        self.assertEqual(len(lines), 2)
        l0, l1 = lines
        for key, typ in (("t_batch_start", int), ("batch_size", int), ("batch_position", int), ("t_record_start", int),
                         ("t_record_done", int), ("cold_start", bool), ("init_ms", float), ("store_ms", float),
                         ("store_calls", int), ("edges_written", int), ("edges_skipped_missing_target", int),
                         ("mark_ms", float), ("marker_only_skipped", bool), ("shard_id", str), ("memory_mb", int),
                         ("stream_approx_creation_ms", int), ("t_ack", int), ("version_seq", int),
                         ("correlation_id", str), ("record_id", str), ("event_name", str)):
            self.assertIsInstance(l0[key], typ, key)
        self.assertEqual((l0["batch_size"], l0["batch_position"], l1["batch_position"]), (2, 0, 1))
        self.assertEqual((l0["store_calls"], l0["edges_written"], l0["edges_skipped_missing_target"]), (4, 1, 0))
        self.assertEqual(l0["store_statements"], 4)
        self.assertEqual((l0["mark_ms"], l0["stream_approx_creation_ms"], l0["memory_mb"]), (1.25, 1500, 512))
        self.assertEqual(l0["shard_id"], "2026-11-04T00:00:00.000")
        self.assertFalse(l0["marker_only_skipped"])
        self.assertEqual(l0["t_record_done"], l0["t_projection_done"])
        self.assertLessEqual(l0["t_batch_start"], l0["t_record_start"])
        self.assertGreaterEqual(l0["store_ms"], 0)
        self.assertEqual(l1["cold_start"], False)  # only the first record's invocation can be cold; same invocation here
        # unchanged existing fields
        for key in ("governed_lag_ms", "projection_phase", "attempt", "consumer"):
            self.assertIn(key, l0)
        self.assertEqual((l0["consumer"], l0["projection_phase"], l0["attempt"]), ("graph_sync", "projected", 1))

    def test_per_record_stats_reset_between_records(self):
        driver, _ = _fake_driver()
        lines = self._run([_rec("1", _img()), _rec("2", _img(vseq=8))], driver)
        self.assertEqual((lines[0]["store_calls"], lines[1]["store_calls"]), (4, 4))
        self.assertEqual((lines[0]["edges_written"], lines[1]["edges_written"]), (1, 1))

    def test_cold_start_true_once_per_container(self):
        driver, _ = _fake_driver()
        with patch.object(lf, "_WA_COLD", True):
            first = self._run([_rec("1", _img())], driver)[0]
            second = self._run([_rec("2", _img(vseq=8))], driver)[0]
        self.assertEqual((first["cold_start"], second["cold_start"]), (True, False))
        self.assertEqual(second["init_ms"], 0.0)

    def test_marker_only_modify_emits_skipped_line_without_metric_lag(self):
        old = _img(vseq=7)
        new = _img(vseq=7, projection_status={"S": "projected"}, projected_version_seq={"N": "7"}, t_projected={"N": "5"})
        driver, _ = _fake_driver()
        buf = io.StringIO()
        proc = MagicMock()
        with patch.object(lf, "_get_neo4j_driver", return_value=driver), patch.object(lf, "_process_record", proc), \
                contextlib.redirect_stdout(buf):
            lf.handler({"Records": [_rec("1", new, old)]}, _Ctx())
        proc.assert_not_called()
        out = buf.getvalue().splitlines()
        lines = [json.loads(l.split("[WRITE-AUDIT] ", 1)[1]) for l in out if l.startswith("[WRITE-AUDIT] ")]
        self.assertEqual(len(lines), 1)
        self.assertIs(lines[0]["marker_only_skipped"], True)
        self.assertEqual((lines[0]["projection_phase"], lines[0]["governed_lag_ms"], lines[0]["store_calls"]),
                         ("marker_skipped", None, 0))
        self.assertFalse([l for l in out if l.startswith("{") and "_aws" in l])  # no EMF for a skipped marker write

    def test_error_line_carries_stage_fields(self):
        driver, _ = _fake_driver()

        def boom(d, r):
            raise RuntimeError("x")
        lines = self._run([_rec("1", _img())], driver, process=boom)
        self.assertEqual((lines[0]["attempt_outcome"], lines[0]["batch_position"], lines[0]["marker_only_skipped"]),
                         ("error", 0, False))

    def test_missing_context_and_arn_degrade_to_none(self):
        driver, _ = _fake_driver()
        rec = _rec("1", _img())
        del rec["eventSourceARN"]
        line = self._run([rec], driver, ctx=None)[0]
        self.assertEqual((line["memory_mb"], line["shard_id"]), (None, None))

    def test_overhead_is_small(self):
        import time
        driver, _ = _fake_driver()
        recs = [_rec(str(i), _img(vseq=i + 1)) for i in range(200)]
        t0 = time.perf_counter()
        self._run(recs, driver)
        per_record_ms = (time.perf_counter() - t0) * 1000.0 / 200
        self.assertLess(per_record_ms, 5.0)


if __name__ == "__main__":
    unittest.main()
