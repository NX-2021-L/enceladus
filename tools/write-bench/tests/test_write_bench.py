"""No-network tests: stats, prod-refusal guard, JSON-RPC payload builders, compare."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import compare  # noqa: E402
import stats  # noqa: E402
import wire  # noqa: E402

GOOD = "https://mcp-gamma.jreese.net/mcp"


class StatsTests(unittest.TestCase):
    def test_percentiles_type7(self):
        d = list(range(1, 101))
        self.assertAlmostEqual(stats.percentile(d, 50), 50.5)
        self.assertAlmostEqual(stats.percentile(d, 95), 95.05)
        self.assertAlmostEqual(stats.percentile(d, 0), 1)
        self.assertAlmostEqual(stats.percentile(d, 100), 100)
        self.assertEqual(stats.percentile([7], 99), 7.0)

    def test_percentile_rejects_bad_input(self):
        with self.assertRaises(ValueError):
            stats.percentile([], 50)
        with self.assertRaises(ValueError):
            stats.percentile([1, 2], 101)

    def test_bootstrap_deterministic_and_contains_point(self):
        data = [float(x % 37) + 0.5 for x in range(120)]
        a = stats.bootstrap_percentile_cis(data, (50, 95), 500, seed=7)
        b = stats.bootstrap_percentile_cis(data, (50, 95), 500, seed=7)
        c = stats.bootstrap_percentile_cis(data, (50, 95), 500, seed=8)
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)
        s = sorted(data)
        self.assertLessEqual(a[50][0], stats.percentile(s, 50))
        self.assertGreaterEqual(a[50][1], stats.percentile(s, 50))

    def test_default_resamples_is_10000(self):
        self.assertEqual(stats.RESAMPLES, 10_000)

    def test_summarize_flags(self):
        s = stats.summarize([float(i) for i in range(1, 31)], "k", resamples=200)
        self.assertEqual(s["n"], 30)
        self.assertTrue(s["p99_information_only"])
        self.assertFalse(s["p95_gating_ok"])
        self.assertEqual(stats.summarize([1.0] * 300, "k", resamples=50)["p95_gating_ok"], True)

    def test_warm_and_cold_never_pooled(self):
        calls = [
            {"operation": "o", "arm": "a", "series": "warm", "client_total_ms": 10.0, "ok": True},
            {"operation": "o", "arm": "a", "series": "cold", "client_total_ms": 900.0, "ok": True},
            {"operation": "o", "arm": "a", "series": "warm", "client_total_ms": 11.0, "ok": True, "warmup": True},
            {"operation": "o", "arm": "a", "series": "warm", "client_total_ms": 12.0, "ok": False},
        ]
        g = stats.group_samples(calls)
        self.assertEqual(g["o|a|warm"], [10.0])
        self.assertEqual(g["o|a|cold"], [900.0])


class GuardTests(unittest.TestCase):
    def test_allows_gamma(self):
        self.assertEqual(wire.assert_gamma_target("gamma", GOOD), GOOD)
        wire.assert_gamma_target("gamma", "https://mcp-gamma.jreese.net/other-path")

    def test_refuses_prod_env_and_hosts(self):
        bad = [("prod", GOOD), ("gamma", "https://mcp.jreese.net/mcp"), ("gamma", "http://mcp-gamma.jreese.net/mcp"),
               ("gamma", "https://mcp-gamma.jreese.net.evil.com/mcp"), ("gamma", "https://evil.com/mcp-gamma.jreese.net"),
               ("gamma", "https://user@mcp-gamma.jreese.net/mcp"), ("gamma", "https://mcp-gamma.jreese.net:8443/mcp"),
               ("gamma", "https://mcp-gamma.jreese.net@evil.com/mcp")]
        for env, url in bad:
            with self.assertRaises(wire.RefusedTarget, msg=(env, url)):
                wire.assert_gamma_target(env, url)

    def test_cli_exits_2(self):
        for argv in (["--env", "prod"], ["--env", "gamma", "--mcp-url", "https://mcp.jreese.net/mcp"]):
            r = subprocess.run([sys.executable, os.path.join(ROOT, "bench.py")] + argv + ["--project", "x", "--dry-run"],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertIn("refused", r.stderr)

    def test_cli_dry_run_ok_no_token_needed(self):
        r = subprocess.run([sys.executable, os.path.join(ROOT, "bench.py"), "--env", "gamma", "--project", "x", "--dry-run"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("execute_20_independent: tool=execute steps=20", r.stdout)


class PayloadTests(unittest.TestCase):
    POOL = [f"BENCH-TSK-{i:03d}" for i in range(1, 11)]

    def test_rpc_shapes(self):
        init = wire.build_initialize(1)
        self.assertEqual((init["jsonrpc"], init["method"], init["id"]), ("2.0", "initialize", 1))
        self.assertEqual(init["params"]["protocolVersion"], "2024-11-05")
        note = wire.build_initialized()
        self.assertNotIn("id", note)
        self.assertEqual(note["method"], "notifications/initialized")
        call = wire.build_tool_call("execute", {"steps": []}, 3)
        self.assertEqual(call["params"], {"name": "execute", "arguments": {"steps": []}})

    def test_headers(self):
        h = wire.build_headers("TOK", "sess-1")
        self.assertEqual(h["Authorization"], "Bearer TOK")
        self.assertEqual(h["Mcp-Session-Id"], "sess-1")
        self.assertNotIn("Mcp-Session-Id", wire.build_headers("TOK"))
        c = wire.client_headers("cid", 1.5, True, 0.0, False, 0.2)
        self.assertEqual(c["X-Enc-Surface"], "write-bench")
        self.assertEqual(c["X-Correlation-Id"], "cid")
        self.assertEqual(c["X-Enc-Client-Session-Reused"], "true")
        self.assertEqual(c["X-Enc-Client-Tls-New"], "false")
        for k in ("X-Enc-T-Client-Start", "X-Enc-Client-Session-Init-Ms", "X-Enc-Client-Serialize-Ms"):
            self.assertIn(k, c)

    def test_every_operation_builds_and_carries_governance_hash(self):
        counts = {"tracker_create": 1, "tracker_set": 1, "documents_put_2kb": 1, "documents_put_60kb": 1,
                  "execute_10_independent": 10, "execute_10_chained": 10, "execute_20_independent": 20}
        for op in wire.OPERATIONS:
            tool, args = wire.build_operation(op, "BENCHSINK", self.POOL, "GH123")
            self.assertEqual(tool, "execute")
            self.assertEqual(len(args["steps"]), counts[op], op)
            for s in args["steps"]:
                self.assertEqual(s["arguments"]["governance_hash"], "GH123")
            json.dumps(wire.build_tool_call(tool, args, 1))

    def test_create_payload(self):
        _, a = wire.build_operation("tracker_create", "BENCHSINK", self.POOL, "GH")
        s = a["steps"][0]
        self.assertEqual(s["action"], "tracker.create")
        x = s["arguments"]
        self.assertTrue(x["title"].startswith("[BENCH]"))
        self.assertEqual((x["record_type"], x["category"], x["priority"], x["transition_type"]),
                         ("task", "implementation", "P3", "no_code"))
        self.assertEqual(len(x["acceptance_criteria"]), 1)
        self.assertEqual(x["project_id"], "BENCHSINK")

    def test_document_sizes(self):
        for op, size in (("documents_put_2kb", 2048), ("documents_put_60kb", 60 * 1024)):
            _, a = wire.build_operation(op, "P", self.POOL, "GH")
            st = a["steps"][0]
            self.assertEqual(st["action"], "documents.put")
            self.assertEqual(len(st["arguments"]["content"].encode()), size)
            self.assertEqual(st["arguments"]["document_subtype"], "doc")

    def test_chained_vs_independent(self):
        _, ind = wire.build_operation("execute_10_independent", "P", self.POOL, "GH")
        self.assertEqual({s["arguments"]["record_id"] for s in ind["steps"]}, set(self.POOL))
        self.assertEqual(len({s["arguments"]["value"] for s in ind["steps"]}), 1)
        _, ch = wire.build_operation("execute_10_chained", "P", self.POOL, "GH")
        self.assertEqual({s["arguments"]["record_id"] for s in ch["steps"]}, {self.POOL[0]})
        vals = [s["arguments"]["value"] for s in ch["steps"]]
        self.assertEqual(len(set(vals)), 10)
        self.assertIn("index 3 after 2", vals[3])
        _, i20 = wire.build_operation("execute_20_independent", "P", self.POOL, "GH")
        self.assertEqual(len(i20["steps"]), 20)

    def test_response_parsing(self):
        inner = {"success": True, "step_results": [{"result": {"record_id": "BENCH-TSK-9"}}]}
        env = {"jsonrpc": "2.0", "id": 2, "result": {"content": [{"type": "text", "text": json.dumps(inner)}]}}
        sse = ("event: message\ndata: " + json.dumps({"x": 1}) + "\n\ndata: " + json.dumps(env) + "\n\n").encode()
        parsed = wire.parse_response("text/event-stream", sse)
        self.assertEqual(wire.unwrap_tool_result(parsed), inner)
        self.assertEqual(wire.find_key(inner, "record_id"), "BENCH-TSK-9")
        self.assertTrue(wire.call_ok(parsed, inner))
        self.assertFalse(wire.call_ok({"error": {"code": -1}}, None))
        self.assertFalse(wire.call_ok(parsed, {"success": False}))


class CompareTests(unittest.TestCase):
    def _run(self, d, base, spread, n=60, p50_shift=0.0):
        calls = [{"operation": "tracker_set", "arm": "long_lived_session", "series": "warm", "ok": True,
                  "client_total_ms": base + p50_shift + (i % spread)} for i in range(n)]
        path = os.path.join(d, f"r{len(os.listdir(d))}.json")
        with open(path, "w") as fh:
            json.dump({"meta": {}, "calls": calls}, fh)
        return path

    def test_improvement_and_divergence(self):
        with tempfile.TemporaryDirectory() as d:
            pre = [self._run(d, 1000, 20), self._run(d, 1000, 20), self._run(d, 1500, 20)]
            post = [self._run(d, 400, 20), self._run(d, 400, 20)]
            res = compare.compare(pre, post, resamples=300)
            cell = res["cells"]["tracker_set|long_lived_session|warm"]
            self.assertTrue(cell["delta_p50"]["improved"])
            self.assertLess(cell["delta_p50"]["ci95"][1], 0)
            self.assertFalse(cell["delta_p95"]["gating_ok"])  # n < 300
            self.assertFalse(cell["pool_consistent"])
            runs = cell["consistency"]["pre"]["runs"]
            self.assertEqual([r["divergent"] for r in runs], [False, False, True])
            self.assertTrue(cell["consistency"]["post"]["checked"])
            self.assertIn("improved", compare.to_markdown(res))

    def test_no_change_ci_spans_zero(self):
        with tempfile.TemporaryDirectory() as d:
            res = compare.compare([self._run(d, 500, 30)], [self._run(d, 500, 30)], resamples=300)
            c = res["cells"]["tracker_set|long_lived_session|warm"]
            self.assertFalse(c["delta_p50"]["excludes_zero"])

    def test_max_three_runs(self):
        with self.assertRaises(ValueError):
            compare.compare(["a"] * 4, ["b"], resamples=10)


class GovernanceHashOverrideTests(unittest.TestCase):
    H = "ab" * 32

    def _args(self, gh=None):
        import bench
        return bench, bench.parse_args(["--env", "gamma", "--project", "x"] + (["--governance-hash", gh] if gh else []))

    def _resolve(self, gh=None, env=None):
        bench, args = self._args(gh)
        calls = []
        orig = bench.fetch_governance_hash
        bench.fetch_governance_hash = lambda s: calls.append(1) or "cd" * 32
        old = os.environ.pop("BENCH_GOVERNANCE_HASH", None)
        if env is not None:
            os.environ["BENCH_GOVERNANCE_HASH"] = env
        try:
            return bench.resolve_governance_hash(args, object()), calls
        finally:
            bench.fetch_governance_hash = orig
            os.environ.pop("BENCH_GOVERNANCE_HASH", None)
            if old is not None:
                os.environ["BENCH_GOVERNANCE_HASH"] = old

    def test_cli_override_skips_fetch(self):
        (gh, src), calls = self._resolve(gh="  " + self.H + "\n")
        self.assertEqual((gh, src, calls), (self.H, "override", []))

    def test_env_override_skips_fetch_and_cli_wins(self):
        (gh, src), calls = self._resolve(env=self.H)
        self.assertEqual((gh, src, calls), (self.H, "override", []))
        (gh, _), _ = self._resolve(gh="ef" * 32, env=self.H)
        self.assertEqual(gh, "ef" * 32)

    def test_default_fetches(self):
        (gh, src), calls = self._resolve()
        self.assertEqual((gh, src, calls), ("cd" * 32, "connection_health", [1]))

    def test_invalid_override_exits_nonzero(self):
        for bad in ("xyz", "AB" * 32, "ab" * 31):
            with self.assertRaises(SystemExit) as cm:
                self._resolve(gh=bad)
            self.assertNotIn(cm.exception.code, (0, None))


if __name__ == "__main__":
    unittest.main()
