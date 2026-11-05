"""ENC-TSK-S47-0C: one graph transaction per stream batch (UNWIND), per-record fallback, audit fields.

Run: python3 -m pytest test_batched_graph_tx_s47_0c.py -q
"""
import contextlib
import io
import json
import sys
import types
import unittest
from unittest.mock import MagicMock, patch

import graph_repo
import lambda_function as lf

ARN = "arn:aws:dynamodb:us-west-2:123:table/devops-project-tracker/stream/2026-11-04T00:00:00.000"


def _img(n, vseq=7, parent=None):
    img = {"project_id": {"S": "enceladus"}, "record_id": {"S": f"task#ENC-TSK-{n}"}, "item_id": {"S": f"ENC-TSK-{n}"},
           "record_type": {"S": "task"}, "title": {"S": f"t{n}"}, "status": {"S": "open"},
           "version_seq": {"N": str(vseq)}, "t_ack": {"N": "1000"}, "correlation_id": {"S": f"corr-{n}"}}
    if parent:
        img["parent"] = {"S": parent}
    return img


def _rec(seq, new):
    return {"eventName": "MODIFY", "eventSourceARN": ARN,
            "dynamodb": {"SequenceNumber": seq, "NewImage": new, "ApproximateCreationDateTime": 1.5}}


class _Res:
    def __init__(self, rows):
        self._rows = rows

    def __iter__(self):
        return iter(self._rows)

    def single(self):
        return self._rows[0] if self._rows else None

    def consume(self):
        return None


class _Store:
    """Fake driver: records every statement; optionally fails UNWIND batches or one record."""

    def __init__(self, fail_batch=False, fail_rid=None):
        self.writes = 0
        self.reads = 0
        self.queries = []
        self.fail_batch = fail_batch
        self.fail_rid = fail_rid

    def run(self, q, **kw):
        self.queries.append((q, kw))
        if q.startswith("UNWIND $rids") or " AS v" in q or " AS h" in q:
            return _Res([])  # node-state reads: nothing projected yet
        if q.startswith("UNWIND $__rows"):
            if self.fail_batch:
                raise RuntimeError("batch boom")
            rows = kw["__rows"]
            if "AS created" in q:
                return _Res([{"__i": r["__i"], "created": True} for r in rows])
            if "AS n" in q and "__n" not in q:
                return _Res([{"__i": r["__i"], "n": 1} for r in rows])
            return _Res([{"__n": len(rows)}])
        if self.fail_rid and kw.get("record_id") == self.fail_rid:
            raise RuntimeError("record boom")
        if "AS created" in q:
            return _Res([{"created": True}])
        return _Res([{"n": 1}])

    def session(self):
        store = self
        sess = MagicMock()

        def _w(fn, *a, **k):
            store.writes += 1
            return fn(store)

        def _r(fn, *a, **k):
            store.reads += 1
            return fn(store)

        sess.execute_write.side_effect = _w
        sess.execute_read.side_effect = _r
        cm = MagicMock()
        cm.__enter__.return_value = sess
        cm.__exit__.return_value = False
        return cm


class _Ctx:
    memory_limit_in_mb = "1024"


class BatchedGraphTxTests(unittest.TestCase):
    def _run(self, records, store):
        buf = io.StringIO()
        with patch.object(lf, "_get_neo4j_driver", return_value=store), \
                patch.object(lf, "_mark_source_projected", return_value=True) as mark, \
                patch.object(lf, "compute_embedding_for_record", return_value=None), \
                contextlib.redirect_stdout(buf):
            out = lf.handler({"Records": records}, _Ctx())
        lines = [json.loads(l.split("[WRITE-AUDIT] ", 1)[1]) for l in buf.getvalue().splitlines()
                 if l.startswith("[WRITE-AUDIT] ")]
        return out, lines, mark

    def test_one_execute_write_per_batch_with_unwind_rows(self):
        store = _Store()
        out, lines, mark = self._run([_rec(str(i), _img(i)) for i in (1, 2, 3)], store)
        self.assertNotIn("batchItemFailures", out)
        self.assertEqual(store.writes, 1)
        self.assertEqual(store.reads, 1)  # one node-state prefetch for the batch
        writes = [(q, kw) for q, kw in store.queries if not q.startswith("UNWIND $rids")]
        self.assertTrue(all(q.startswith("UNWIND $__rows AS __row CALL { WITH __row ") for q, _ in writes))
        upsert = [kw for q, kw in writes if "SET n += __row.props" in q]
        self.assertEqual(len(upsert), 1)
        self.assertEqual([r["record_id"] for r in upsert[0]["__rows"]], ["ENC-TSK-1", "ENC-TSK-2", "ENC-TSK-3"])
        self.assertEqual(mark.call_count, 3)  # projection marker stays per record, after commit
        self.assertEqual(len(lines), 3)
        for line in lines:
            self.assertEqual((line["store_calls"], line["store_ms_basis"], line["batch_tx_fallback"]),
                             (1, "batch_share", False))
            self.assertEqual(line["store_statements"], len(writes))
            self.assertGreaterEqual(line["edges_written"], 1)  # BELONGS_TO at least
            self.assertIsInstance(line["store_ms"], float)

    def test_edges_written_matches_per_record_count(self):
        store = _Store()
        _, lines, _ = self._run([_rec("1", _img(1, parent="ENC-TSK-9"))], store)
        tx = lf._graph_repo.StagedRecord(("Task", "ENC-TSK-1")).capture()
        rec = lf._normalize_record_for_graph(lf._deser_image(_img(1, parent="ENC-TSK-9")))
        lf._reconcile_edges(tx, rec)
        expected = sum(1 for st in tx._record.statements if lf._WA_EDGE_MERGE_RE.search(st.query))
        self.assertGreaterEqual(expected, 2)
        self.assertEqual(lines[0]["edges_written"], expected)

    def test_order_guard_placeholder_inside_batch(self):
        store = _Store()
        _, lines, _ = self._run([_rec("1", _img(1, parent="ENC-TSK-9")), _rec("2", _img(2))], store)
        self.assertEqual(store.writes, 1)
        ph = [kw for q, kw in store.queries if "is_placeholder = true" in q and q.startswith("UNWIND $__rows")]
        self.assertEqual(len(ph), 1)
        self.assertEqual([r["rid"] for r in ph[0]["__rows"]], ["ENC-TSK-9"])
        self.assertEqual((lines[0]["edges_placeholder_targets"], lines[1]["edges_placeholder_targets"]), (1, 0))

    def test_fallback_per_record_on_batch_failure(self):
        store = _Store(fail_batch=True, fail_rid="ENC-TSK-2")
        out, lines, mark = self._run([_rec(str(i), _img(i)) for i in (1, 2, 3)], store)
        self.assertEqual(out, {"batchItemFailures": [{"itemIdentifier": "2"}]})
        self.assertEqual(store.writes, 1 + 3)  # failed batch + one per record
        self.assertEqual(mark.call_count, 2)
        self.assertEqual([l["batch_tx_fallback"] for l in lines], [True, True, True])
        self.assertEqual([l["store_ms_basis"] for l in lines], ["record"] * 3)
        self.assertEqual([l.get("attempt_outcome") for l in lines][1], "error")
        self.assertEqual(lines[0]["store_calls"], 1)

    def test_duplicate_record_splits_waves_and_skips_stale(self):
        store = _Store()
        _, lines, _ = self._run([_rec("1", _img(1, vseq=7)), _rec("2", _img(1, vseq=8)), _rec("3", _img(1, vseq=8))], store)
        self.assertEqual(store.writes, 1)
        upserts = [kw for q, kw in store.queries if "SET n += __row.props" in q]
        self.assertEqual([[r["props"]["version_seq"] for r in kw["__rows"]] for kw in upserts], [[7], [8]])
        self.assertEqual(len(lines), 3)  # the stale third delivery still emits its line

    def test_kill_switch_restores_per_record_path(self):
        store = _Store()
        with patch.object(lf, "_GRAPH_BATCH_TX", False):
            _, lines, _ = self._run([_rec("1", _img(1)), _rec("2", _img(2))], store)
        self.assertFalse(any(q.startswith("UNWIND $__rows") for q, _ in store.queries))
        self.assertGreater(store.writes, 2)
        self.assertEqual(lines[0]["store_ms_basis"], "record")

    def test_driver_built_once_across_invocations(self):
        fake_neo4j = types.ModuleType("neo4j")
        fake_neo4j.GraphDatabase = MagicMock()
        fake_neo4j.GraphDatabase.driver.return_value = _Store()
        with patch.dict(sys.modules, {"neo4j": fake_neo4j}), \
                patch.object(lf, "_neo4j_driver", None), \
                patch.object(lf, "_get_neo4j_credentials",
                             return_value={"NEO4J_URI": "bolt://x", "NEO4J_PASSWORD": "p"}), \
                patch.object(lf, "_mark_source_projected", return_value=True), \
                patch.object(lf, "compute_embedding_for_record", return_value=None), \
                contextlib.redirect_stdout(io.StringIO()):
            lf.handler({"Records": [_rec("1", _img(1))]}, _Ctx())
            lf.handler({"Records": [_rec("2", _img(2))]}, _Ctx())
        self.assertEqual(fake_neo4j.GraphDatabase.driver.call_count, 1)


class RewriteTests(unittest.TestCase):
    def test_with_clause_carries_row_and_params_rewritten(self):
        q, cols = graph_repo.rewrite_for_unwind(
            "OPTIONAL MATCH (x:Task {record_id: $rid}) WITH count(x) AS existed "
            "MERGE (n:Task {record_id: $rid}) RETURN existed = 0 AS created")
        self.assertEqual(cols, ["created"])
        self.assertIn("WITH __row, count(x) AS existed", q)
        self.assertNotIn("$rid", q)
        self.assertTrue(q.endswith("RETURN __row.__i AS __i, created"))

    def test_starts_with_predicate_untouched(self):
        q, _ = graph_repo.rewrite_for_unwind("MATCH (n) WHERE n.record_id STARTS WITH $p DELETE n")
        self.assertIn("STARTS WITH __row.p", q)
        self.assertTrue(q.endswith("RETURN count(*) AS __n"))

    def test_unaliased_return_is_unbatchable(self):
        with self.assertRaises(graph_repo.UnbatchableStatement):
            graph_repo.rewrite_for_unwind("MATCH (n) RETURN n")


if __name__ == "__main__":
    unittest.main()
