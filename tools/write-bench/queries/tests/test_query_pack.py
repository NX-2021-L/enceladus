import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

QDIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(QDIR))
import make_fixture  # noqa: E402
import run_queries as rq  # noqa: E402

FIXTURE = QDIR / "fixtures" / "synthetic_audit_lines.jsonl"


def fixture_result(grace=15):
    lines, ws, we = rq.load_fixture(FIXTURE)
    return rq.compute(lines, [], ws, we, grace, 0), lines


class QueryPackTests(unittest.TestCase):
    def test_fixture_is_current_and_about_200_lines(self):
        rows = make_fixture.make()
        with open(FIXTURE) as fh:
            self.assertEqual(len(rows), sum(1 for _ in fh))
        self.assertTrue(180 <= len(rows) <= 230)

    def test_counter_metrics_equal_planted_violations(self):
        res, _ = fixture_result()
        cm = res["counter_metrics"]
        self.assertEqual(cm["stale_hash_acceptances"]["count"], 1)
        self.assertEqual(cm["stale_hash_acceptances"]["ids"], ["cor-0020"])      # decoy cor-0021 was rejected
        self.assertEqual(cm["records_without_audit_item"]["ids"], ["cor-0030"])  # decoys: replay hit, dry_run, grace window
        self.assertEqual(cm["idempotent_replay_receipt_mismatch"]["ids"], ["idem-0040"])
        self.assertEqual(cm["dry_run_writes"]["ids"], ["cor-0050"])
        self.assertEqual(cm["unrecovered_consumer_failures"]["count"], 1)
        self.assertEqual(cm["unrecovered_consumer_failures"]["ids"], ["cor-0061"])
        self.assertEqual(cm["unrecovered_consumer_failures"]["literal_attempt_ge_3_without_done"], 2)  # decoy recovered at attempt 4

    def test_dlq_depth_adds_to_unrecovered(self):
        lines, ws, we = rq.load_fixture(FIXTURE)
        res = rq.compute(lines, [], ws, we, 15, 4)
        self.assertEqual(res["counter_metrics"]["unrecovered_consumer_failures"]["count"], 5)

    def test_grace_window_excludes_recent_writes(self):
        res, _ = fixture_result(grace=0)
        # with no grace, the 3 late writes (no consumer line yet) become orphans too
        self.assertEqual(res["counter_metrics"]["records_without_audit_item"]["count"], 1 + 3)

    def test_receipt_check_not_computable_without_receipt_hash(self):
        lines, ws, we = rq.load_fixture(FIXTURE)
        for ln in lines:
            ln["message"] = ln["message"].replace('"receipt_hash"', '"x_receipt"')
        res = rq.compute(lines, [], ws, we, 15, 0)
        self.assertIsNone(res["counter_metrics"]["idempotent_replay_receipt_mismatch"]["count"])

    def test_percentiles_per_tool_and_surface(self):
        res, lines = fixture_result()
        rows = res["latency_by_tool_surface"]
        pairs = {(r["tool"], r["surface"]) for r in rows}
        self.assertGreaterEqual(len({t for t, _ in pairs}), 4)
        self.assertGreaterEqual(len({s for _, s in pairs}), 4)
        self.assertEqual(sum(r["n"] for r in rows), res["counts"]["write_lines"])
        for r in rows:
            self.assertLessEqual(r["p50"], r["p90"])
            self.assertLessEqual(r["p90"], r["p95"])
            self.assertLessEqual(r["p95"], r["max"])
            self.assertEqual(r["cold_share"], r["cold_n"] / r["n"])
        # independent recomputation for one pair
        tool, surface = rows[0]["tool"], rows[0]["surface"]
        vals = sorted(a["server_total_ms"] for a in
                      (json.loads(l["message"].split("[WRITE-AUDIT]", 1)[1]) for l in lines if "[WRITE-AUDIT]" in l["message"])
                      if a.get("tool") == tool and a.get("surface") == surface and "consumer" not in a)
        self.assertAlmostEqual(rows[0]["p50"], rq.pct(vals, 50))
        self.assertAlmostEqual(rows[0]["max"], vals[-1])

    def test_pct_interpolation(self):
        self.assertEqual(rq.pct([1, 2, 3, 4], 50), 2.5)
        self.assertEqual(rq.pct([5], 95), 5.0)
        self.assertIsNone(rq.pct([], 50))

    def test_report_join_and_cold_fraction(self):
        res, _ = fixture_result()
        self.assertGreater(res["counts"]["report_joined"], 0)  # cold audit lines without init_ms get it from REPORT
        cf = res["cold_fraction"]
        self.assertEqual(cf["sessions"], 12)
        self.assertGreater(cf["max"], 0.4)
        self.assertEqual(sum(cf["buckets"].values()), cf["sessions"])
        self.assertTrue(any(v["n"] for v in res["stage_table"]["init_ms"].values()))

    def test_governed_lag_per_tool(self):
        res, _ = fixture_result()
        self.assertTrue(res["governed_lag"])
        for r in res["governed_lag"]:
            self.assertLessEqual(r["p50"], r["p95"])

    def test_cli_fixture_path_writes_json_and_markdown(self):
        with tempfile.TemporaryDirectory() as d:
            res = rq.main(["--fixture", str(FIXTURE), "--out-dir", d])
            names = sorted(p.suffix for p in Path(d).iterdir())
            self.assertEqual(names, [".json", ".md"])
            md = next(Path(d).glob("*.md")).read_text()
            self.assertIn("Stage budget", md)
            self.assertIn("t_ddb_ms", md)
            self.assertIn("stale_hash_acceptances", md)
            self.assertEqual(res["scanned_bytes"], 0)

    def test_query_files_present(self):
        names = {p.name for p in QDIR.glob("*.query")}
        for n in ("01_server_latency_by_tool_surface.query", "03_stage_p50_p95_by_tool_surface.query",
                  "04_governed_lag_by_tool.query", "06_extract_report_init.query", "cm1_stale_hash_acceptances.query",
                  "cm3_idempotent_replay_receipt_mismatch.query", "cm4_dry_run_writes.query",
                  "cm5_unrecovered_consumer_failures.query"):
            self.assertIn(n, names)
        for p in QDIR.glob("*.query"):
            self.assertIn("[WRITE-AUDIT]", p.read_text().replace("\\[", "[").replace("\\]", "]") if p.name[:2] != "06" else "[WRITE-AUDIT]")


if __name__ == "__main__":
    unittest.main()
