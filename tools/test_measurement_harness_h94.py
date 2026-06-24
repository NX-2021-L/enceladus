#!/usr/bin/env python3
"""Unit tests for ENC-TSK-H94 measurement harness (tools/measurement_harness_h94.py).

stdlib unittest (NOT pytest). Synthetic / in-memory data only — no network, no
S3, no live corpus. The retrieval surface is exercised through a STUB
``retrieve_fn`` (a dict query->ranked-list); the gamma/mcp live paths are never
invoked.

Covers the testable core:
  * precision_at_1 / recall_at_k on hand-built ranked results with known truth.
  * capture_run with a stub retrieve_fn (the full run schema + metrics).
  * compare verdict rule: met (delta>=bar) / not_met (0<=delta<bar) /
    baseline_only (after=None => null after & delta — the no-fabrication guard).
  * require_projection_live: live / stale / not-exist / name-mismatch.
  * build_eval_set self-retrieval derivation + holdout reservation.
  * file/no-fabrication edge behaviors.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import measurement_harness_h94 as mh  # noqa: E402


def _item(query, expected, cluster="c0"):
    return {"query": query, "expected": expected, "cluster": cluster}


def _stub_retrieve(table):
    """A retrieve_fn(query, k) backed by an in-memory query->ranked-list dict."""
    def retrieve(query, k):
        return list(table.get(query, []))[:k]
    return retrieve


# ===========================================================================
# precision_at_1 / recall_at_k
# ===========================================================================
class PrecisionAt1Test(unittest.TestCase):
    def test_all_rank1_hits_precision_one(self):
        eval_set = [_item("q1", "A"), _item("q2", "B")]
        results = {"q1": ["A", "Z"], "q2": ["B", "Y"]}
        self.assertEqual(mh.precision_at_1(results, eval_set), 1.0)

    def test_half_rank1_hits(self):
        # q1 hits at rank 1; q2's expected is at rank 2 (a precision@1 miss).
        eval_set = [_item("q1", "A"), _item("q2", "B")]
        results = {"q1": ["A", "Z"], "q2": ["X", "B"]}
        self.assertEqual(mh.precision_at_1(results, eval_set), 0.5)

    def test_no_hits_precision_zero(self):
        eval_set = [_item("q1", "A"), _item("q2", "B")]
        results = {"q1": ["Z"], "q2": ["Y"]}
        self.assertEqual(mh.precision_at_1(results, eval_set), 0.0)

    def test_missing_and_empty_results_count_as_miss(self):
        eval_set = [_item("q1", "A"), _item("q2", "B"), _item("q3", "C")]
        results = {"q1": ["A"], "q2": []}  # q3 absent entirely
        self.assertAlmostEqual(mh.precision_at_1(results, eval_set), 1.0 / 3.0, places=9)

    def test_empty_eval_set_precision_zero(self):
        self.assertEqual(mh.precision_at_1({}, []), 0.0)


class RecallAtKTest(unittest.TestCase):
    def test_recall_within_k(self):
        # Expected appears within top-3 for both items.
        eval_set = [_item("q1", "A"), _item("q2", "B")]
        results = {"q1": ["Z", "Y", "A"], "q2": ["B", "X", "W"]}
        self.assertEqual(mh.recall_at_k(results, eval_set, k=3), 1.0)

    def test_recall_excludes_beyond_k(self):
        # q1's expected is at rank 3 (index 2): inside k=3, outside k=2.
        eval_set = [_item("q1", "A")]
        results = {"q1": ["Z", "Y", "A"]}
        self.assertEqual(mh.recall_at_k(results, eval_set, k=3), 1.0)
        self.assertEqual(mh.recall_at_k(results, eval_set, k=2), 0.0)

    def test_recall_partial(self):
        eval_set = [_item("q1", "A"), _item("q2", "B")]
        results = {"q1": ["A", "Z"], "q2": ["X", "Y"]}  # q2 misses entirely
        self.assertEqual(mh.recall_at_k(results, eval_set, k=10), 0.5)

    def test_k_clamped_to_one(self):
        eval_set = [_item("q1", "A")]
        results = {"q1": ["A", "B"]}
        self.assertEqual(mh.recall_at_k(results, eval_set, k=0), 1.0)

    def test_empty_eval_set_recall_zero(self):
        self.assertEqual(mh.recall_at_k({}, [], k=5), 0.0)


# ===========================================================================
# capture_run (stub retrieve_fn — no network)
# ===========================================================================
class CaptureRunTest(unittest.TestCase):
    def test_capture_run_schema_and_metrics(self):
        eval_set = [_item("q1", "A", "c1"), _item("q2", "B", "c2")]
        # q1: rank-1 hit. q2: expected at rank 2 (recall@2 hit, precision@1 miss).
        table = {"q1": ["A", "Z"], "q2": ["Y", "B"]}
        run = mh.capture_run(eval_set, _stub_retrieve(table), k=2, label="before",
                             generated_at="2026-06-23T00:00:00Z")

        self.assertEqual(
            set(run.keys()),
            {"version", "label", "k", "n", "precision_at_1", "recall_at_k",
             "per_query", "generated_at"},
        )
        self.assertEqual(run["version"], mh.RUN_VERSION)
        self.assertEqual(run["label"], "before")
        self.assertEqual(run["k"], 2)
        self.assertEqual(run["n"], 2)
        self.assertEqual(run["precision_at_1"], 0.5)
        self.assertEqual(run["recall_at_k"], 1.0)
        self.assertEqual(run["generated_at"], "2026-06-23T00:00:00Z")

    def test_per_query_rows_audit_trail(self):
        eval_set = [_item("q1", "A", "c1"), _item("q2", "B", "c2")]
        table = {"q1": ["A", "Z"], "q2": ["Y", "B"]}
        run = mh.capture_run(eval_set, _stub_retrieve(table), k=2, label="after")
        rows = {r["query"]: r for r in run["per_query"]}

        self.assertEqual(rows["q1"]["rank1"], "A")
        self.assertTrue(rows["q1"]["rank1_hit"])
        self.assertEqual(rows["q1"]["expected_rank"], 0)
        self.assertTrue(rows["q1"]["recall_hit"])

        self.assertEqual(rows["q2"]["rank1"], "Y")
        self.assertFalse(rows["q2"]["rank1_hit"])
        self.assertEqual(rows["q2"]["expected_rank"], 1)  # 0-based within top-k
        self.assertTrue(rows["q2"]["recall_hit"])
        self.assertEqual(rows["q2"]["retrieved"], ["Y", "B"])

    def test_capture_run_rejects_bad_label(self):
        with self.assertRaises(ValueError):
            mh.capture_run([_item("q1", "A")], _stub_retrieve({}), label="middle")

    def test_capture_run_uses_k_window(self):
        # Expected at index 2 is outside k=2 => recall miss, precision miss.
        eval_set = [_item("q1", "A")]
        table = {"q1": ["Z", "Y", "A"]}
        run = mh.capture_run(eval_set, _stub_retrieve(table), k=2, label="before")
        self.assertEqual(run["precision_at_1"], 0.0)
        self.assertEqual(run["recall_at_k"], 0.0)
        self.assertEqual(run["per_query"][0]["expected_rank"], None)


# ===========================================================================
# compare — the verdict rule (incl. the no-fabrication guarantee)
# ===========================================================================
class CompareVerdictTest(unittest.TestCase):
    def _run(self, label, p1, recall=0.9, k=10, n=4):
        return {
            "version": mh.RUN_VERSION, "label": label, "k": k, "n": n,
            "precision_at_1": p1, "recall_at_k": recall, "per_query": [],
            "generated_at": None,
        }

    def test_delta_meets_bar_is_met(self):
        before = self._run("before", 0.50)
        after = self._run("after", 0.60)  # delta 0.10 >= 0.05
        verdict = mh.compare(before, after, bar=0.05)
        self.assertEqual(verdict["verdict"], mh.VERDICT_MET)
        self.assertAlmostEqual(verdict["delta"], 0.10, places=9)
        self.assertEqual(verdict["precision_at_1_before"], 0.50)
        self.assertEqual(verdict["precision_at_1_after"], 0.60)
        self.assertEqual(verdict["bar"], 0.05)

    def test_delta_exactly_at_bar_is_met(self):
        before = self._run("before", 0.50)
        after = self._run("after", 0.55)  # delta exactly 0.05 (>= bar)
        verdict = mh.compare(before, after, bar=0.05)
        self.assertEqual(verdict["verdict"], mh.VERDICT_MET)

    def test_small_positive_delta_is_not_met(self):
        before = self._run("before", 0.50)
        after = self._run("after", 0.52)  # 0 <= delta 0.02 < 0.05
        verdict = mh.compare(before, after, bar=0.05)
        self.assertEqual(verdict["verdict"], mh.VERDICT_NOT_MET)
        self.assertAlmostEqual(verdict["delta"], 0.02, places=9)

    def test_zero_delta_is_not_met(self):
        before = self._run("before", 0.50)
        after = self._run("after", 0.50)  # delta 0.0 < 0.05
        verdict = mh.compare(before, after, bar=0.05)
        self.assertEqual(verdict["verdict"], mh.VERDICT_NOT_MET)
        self.assertEqual(verdict["delta"], 0.0)

    def test_negative_delta_is_not_met(self):
        before = self._run("before", 0.60)
        after = self._run("after", 0.40)  # regression
        verdict = mh.compare(before, after, bar=0.05)
        self.assertEqual(verdict["verdict"], mh.VERDICT_NOT_MET)
        self.assertLess(verdict["delta"], 0.0)

    def test_after_none_is_baseline_only_no_fabrication(self):
        # THE no-fabrication guarantee (AC-3): no after_run => baseline_only with
        # null after/delta. The harness must never invent the AFTER number.
        before = self._run("before", 0.50)
        verdict = mh.compare(before, None, bar=0.05)
        self.assertEqual(verdict["verdict"], mh.VERDICT_BASELINE_ONLY)
        self.assertIsNone(verdict["precision_at_1_after"])
        self.assertIsNone(verdict["delta"])
        self.assertIsNone(verdict["recall_at_k_after"])
        # The baseline number is still present and real.
        self.assertEqual(verdict["precision_at_1_before"], 0.50)

    def test_compare_requires_before(self):
        with self.assertRaises(ValueError):
            mh.compare(None, self._run("after", 0.6))

    def test_compare_refuses_run_missing_metric(self):
        # A malformed run with no precision_at_1 must raise, never default to 0.
        bad_before = {"label": "before", "k": 10, "n": 4}  # no precision_at_1
        with self.assertRaises(ValueError):
            mh.compare(bad_before, None)

    def test_verdict_version_and_render_summary(self):
        before = self._run("before", 0.50)
        after = self._run("after", 0.62)
        verdict = mh.compare(before, after, bar=0.05)
        self.assertEqual(verdict["version"], mh.VERDICT_VERSION)
        text = mh.render_summary(verdict)
        self.assertIn("VERDICT", text)
        self.assertIn(mh.VERDICT_MET, text)
        # baseline_only summary shows the not-captured markers.
        baseline = mh.compare(before, None)
        btext = mh.render_summary(baseline)
        self.assertIn("not captured", btext)


# ===========================================================================
# require_projection_live (AC-2 preflight)
# ===========================================================================
class RequireProjectionLiveTest(unittest.TestCase):
    def _health(self, **proj):
        # MCP composite shape: graph_index.graph_projection.
        return {"graph_index": {"graph_projection": proj}}

    def test_live_projection_ok(self):
        health = self._health(
            configured=True, name="gds_standing_enceladus",
            exists=True, stale=False, age_seconds=30, max_age_seconds=900,
        )
        ok, reason = mh.require_projection_live(health)
        self.assertTrue(ok)
        self.assertIn("live", reason)

    def test_stale_projection_not_ok(self):
        health = self._health(
            name="gds_standing_enceladus", exists=True, stale=True,
            age_seconds=5000, max_age_seconds=900,
        )
        ok, reason = mh.require_projection_live(health)
        self.assertFalse(ok)
        self.assertIn("stale", reason)

    def test_missing_projection_not_ok(self):
        health = self._health(name="gds_standing_enceladus", exists=False, stale=False)
        ok, reason = mh.require_projection_live(health)
        self.assertFalse(ok)
        self.assertIn("exist", reason)

    def test_name_mismatch_not_ok(self):
        health = self._health(name="gds_other", exists=True, stale=False)
        ok, reason = mh.require_projection_live(health, projection_name="gds_standing_enceladus")
        self.assertFalse(ok)
        self.assertIn("mismatch", reason)

    def test_name_check_skipped_when_none(self):
        # When no name is required, a live block passes regardless of name.
        health = self._health(name="anything", exists=True, stale=False)
        ok, _ = mh.require_projection_live(health, projection_name=None)
        self.assertTrue(ok)

    def test_raw_graph_query_health_shape_accepted(self):
        # The graph-query-api health puts graph_projection at the top level.
        health = {"graph_projection": {
            "name": "gds_standing_enceladus", "exists": True, "stale": False,
        }}
        ok, _ = mh.require_projection_live(health)
        self.assertTrue(ok)

    def test_no_block_not_ok(self):
        ok, reason = mh.require_projection_live({"signals": {}})
        self.assertFalse(ok)
        self.assertIn("no graph_projection", reason)


# ===========================================================================
# build_eval_set — self-retrieval derivation + holdout
# ===========================================================================
class BuildEvalSetTest(unittest.TestCase):
    def _corpus(self):
        return [
            {"record_id": "ENC-TSK-A", "title": "deploy the checkout service"},
            {"record_id": "ENC-TSK-B", "title": "deploy checkout service now"},
            {"record_id": "ENC-ISS-C", "title": "unrelated keyword index bug"},
            {"record_id": "ENC-TSK-D", "text": "fallback body text only"},
        ]

    def _pairs(self):
        return [
            {"a": "ENC-TSK-A", "b": "ENC-TSK-B", "cosine": 0.99},
            {"a": "ENC-TSK-A", "b": "ENC-TSK-D", "cosine": 0.96},
        ]

    def test_self_retrieval_items_derived(self):
        items = mh.build_eval_set(self._pairs(), self._corpus())
        by_expected = {it["expected"]: it for it in items}
        # All three distinct pair endpoints with usable text become items.
        self.assertEqual(set(by_expected), {"ENC-TSK-A", "ENC-TSK-B", "ENC-TSK-D"})
        # Each item's query is the record's own text; expected is its own id.
        self.assertEqual(by_expected["ENC-TSK-A"]["query"], "deploy the checkout service")
        self.assertEqual(by_expected["ENC-TSK-D"]["query"], "fallback body text only")

    def test_clusters_group_linked_records(self):
        # A-B and A-D are linked through A => all three share one cluster id.
        items = mh.build_eval_set(self._pairs(), self._corpus())
        clusters = {it["cluster"] for it in items}
        self.assertEqual(len(clusters), 1)

    def test_endpoint_without_text_skipped(self):
        corpus = [{"record_id": "ENC-TSK-A", "title": "has text"}]  # B absent/no text
        pairs = [{"a": "ENC-TSK-A", "b": "ENC-TSK-NO-TEXT", "cosine": 0.99}]
        items = mh.build_eval_set(pairs, corpus)
        self.assertEqual([it["expected"] for it in items], ["ENC-TSK-A"])

    def test_holdout_frac_reserves_subset(self):
        items_all = mh.build_eval_set(self._pairs(), self._corpus(), holdout_frac=1.0)
        items_half = mh.build_eval_set(self._pairs(), self._corpus(), holdout_frac=0.5)
        self.assertEqual(len(items_all), 3)
        # ceil(0.5 * 3) == 2 reserved.
        self.assertEqual(len(items_half), 2)

    def test_invalid_holdout_frac_raises(self):
        with self.assertRaises(ValueError):
            mh.build_eval_set(self._pairs(), self._corpus(), holdout_frac=0.0)
        with self.assertRaises(ValueError):
            mh.build_eval_set(self._pairs(), self._corpus(), holdout_frac=1.5)

    def test_empty_pairs_yields_empty_eval(self):
        self.assertEqual(mh.build_eval_set([], self._corpus()), [])


# ===========================================================================
# Loaders + retrieval-surface helpers (pure, no network)
# ===========================================================================
class LoaderTest(unittest.TestCase):
    def test_load_eval_set_dict_and_list_forms(self):
        with tempfile.TemporaryDirectory() as td:
            p1 = Path(td) / "eval_obj.json"
            p2 = Path(td) / "eval_list.json"
            p1.write_text(json.dumps({"eval_set": [
                {"query": "q1", "expected": "A", "cluster": "c0"},
                {"query": None, "expected": "B"},  # dropped (no query)
            ]}), encoding="utf-8")
            p2.write_text(json.dumps([
                {"query": "q2", "expected": "B"},
                {"missing": True},  # dropped
            ]), encoding="utf-8")
            a = mh.load_eval_set_from_file(str(p1))
            b = mh.load_eval_set_from_file(str(p2))
        self.assertEqual([it["expected"] for it in a], ["A"])
        self.assertEqual([it["expected"] for it in b], ["B"])
        self.assertIsNone(b[0]["cluster"])  # cluster optional

    def test_nodes_to_record_ids_orders_and_filters(self):
        body = {"nodes": [
            {"record_id": "A", "score": 0.9},
            {"no_id": True},                 # dropped
            {"record_id": "B", "score": 0.8},
        ]}
        self.assertEqual(mh._nodes_to_record_ids(body), ["A", "B"])
        self.assertEqual(mh._nodes_to_record_ids({}), [])

    def test_parse_invoke_payload_unwraps_proxy_envelope(self):
        envelope = {"statusCode": 200, "body": json.dumps({"nodes": [{"record_id": "A"}]})}
        body = mh._parse_invoke_payload(json.dumps(envelope))
        self.assertEqual(mh._nodes_to_record_ids(body), ["A"])

    def test_parse_invoke_payload_raises_on_http_error(self):
        envelope = {"statusCode": 500, "body": json.dumps({"error": "boom"})}
        with self.assertRaises(RuntimeError):
            mh._parse_invoke_payload(json.dumps(envelope))

    def test_file_retrieve_fn_dict_and_list(self):
        with tempfile.TemporaryDirectory() as td:
            obj = Path(td) / "res_obj.json"
            lst = Path(td) / "res_list.json"
            obj.write_text(json.dumps({"results": {"q1": ["A", "B"]}}), encoding="utf-8")
            lst.write_text(json.dumps([
                {"query": "q2", "ranked": [{"record_id": "C"}, {"record_id": "D"}]},
            ]), encoding="utf-8")
            f1 = mh.make_file_retrieve_fn(str(obj))
            f2 = mh.make_file_retrieve_fn(str(lst))
        self.assertEqual(f1("q1", 10), ["A", "B"])
        self.assertEqual(f1("q1", 1), ["A"])          # k window honored
        self.assertEqual(f1("absent", 10), [])         # miss => empty
        self.assertEqual(f2("q2", 10), ["C", "D"])     # node-dict ranked coerced

    def test_build_hybrid_event_shape(self):
        ev = mh._build_hybrid_event("enceladus", "deploy", 10, "secret-key")
        self.assertEqual(ev["queryStringParameters"]["search_type"], "hybrid")
        self.assertEqual(ev["queryStringParameters"]["project_id"], "enceladus")
        self.assertEqual(ev["queryStringParameters"]["query"], "deploy")
        self.assertEqual(ev["queryStringParameters"]["top_n"], "10")
        self.assertEqual(ev["headers"]["x-coordination-internal-key"], "secret-key")
        self.assertEqual(ev["requestContext"]["http"]["method"], "GET")
        self.assertTrue(ev["rawPath"].endswith("/graphsearch"))


# ===========================================================================
# End-to-end (in-memory): capture before/after via stub -> compare verdict
# ===========================================================================
class EndToEndStubTest(unittest.TestCase):
    def test_before_after_compare_met(self):
        # Two near-duplicates A and B. BEFORE (encoding OFF): crosstalk makes the
        # near-duplicate outrank the true item for both queries -> precision@1 0.0.
        # AFTER (encoding ON): the true item ranks first -> precision@1 1.0.
        eval_set = [_item("qa", "A", "c0"), _item("qb", "B", "c0")]
        before_table = {"qa": ["B", "A"], "qb": ["A", "B"]}
        after_table = {"qa": ["A", "B"], "qb": ["B", "A"]}

        before = mh.capture_run(eval_set, _stub_retrieve(before_table), k=10, label="before")
        after = mh.capture_run(eval_set, _stub_retrieve(after_table), k=10, label="after")
        self.assertEqual(before["precision_at_1"], 0.0)
        self.assertEqual(after["precision_at_1"], 1.0)

        verdict = mh.compare(before, after, bar=0.05)
        self.assertEqual(verdict["verdict"], mh.VERDICT_MET)
        self.assertAlmostEqual(verdict["delta"], 1.0, places=9)
        # recall@k unchanged (both items always in the top-2) — the discriminating
        # signal is precision@1, exactly as the AC frames it.
        self.assertEqual(before["recall_at_k"], 1.0)
        self.assertEqual(after["recall_at_k"], 1.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
