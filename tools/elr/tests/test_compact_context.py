"""Offline tests for elr_compact_context.py and elr_lib.context_store
(ENC-TSK-Q50, ENC-FTR-147 / DOC-412AB7081565 FR-1..FR-9, M-3, M-4).

A fake transport stands in for InternalClient: no network, no real
~/.enceladus writes (every run passes --out-dir under a tempdir).
"""

from __future__ import annotations

import ast
import contextlib
import hashlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import elr_compact_context as cc
from elr_lib import context_store
from elr_lib import tls as elr_tls

_ELR_ROOT = Path(__file__).resolve().parent.parent
_RECORD = {
    "item_id": "ENC-TSK-Q33",
    "record_id": "task#ENC-TSK-Q33",
    "project_id": "enceladus",
    "title": "ui-v2 PWA:   stop serving feed corpus",
    "intent": "Remediate   the stale\nfeed corpus",
    "components": ["comp-a", "comp-gone"],
    "history": [{"n": i} for i in range(5)],
}


def _node(i: int, *, title_len: int = 64, id_len: int = 16, final_rank=None, fused_rank=None) -> dict:
    base = f"ENC-TSK-{i:08d}"[:id_len]
    return {
        "record_id": base,
        "title": ("t%d " % i).ljust(title_len, "x")[:title_len],
        "_labels": ["Feature"],
        "_fused_rank": fused_rank if fused_rank is not None else (i * 7) % 50 + 11,
        "_fused_score": 0.0312345678 / (i + 1),
        "_final_rank": final_rank if final_rank is not None else i + 1,
        "_final_score": 0.3312345678 / (i + 1),
        "_per_signal_ranks": {"vector": 12, "graph": 34, "keyword": 56},
        "_corroboration_count": 12,
        "_b_corr": 0.2999999,
    }


def hybrid_body(n_nodes: int = 5, **overrides) -> dict:
    body = {
        "success": True,
        "nodes": [_node(i) for i in range(n_nodes)],
        "edges": [],
        "paths": [],
        "summary": f"Hybrid: {n_nodes} nodes (vector=116, graph=25, keyword=25; graph_algo=cypher_fallback; embedded=15/15)",
        "duration_ms": 1234,
        "signal_availability": {"vector": True, "graph": True, "keyword": True},
        "graph_algorithm": "cypher_fallback",
        "rrf_k": 60,
        "embedding_coverage_sample": {"covered": 15, "total_ranked": 15},
        "per_node_fusion": {},
        "fsrs_t3_threshold": 0.7,
        "include_below_threshold": False,
        "pathway": {"node_sequence": ["ENC-TSK-Q33"], "edge_count": 0, "intent_signature": "sha256:" + "ab" * 32, "wave_id": "unassigned"},
    }
    body.update(overrides)
    return body


class FakeClient:
    """InternalClient stand-in. ``routes`` maps (api, path) -> (status, body)
    or a callable(query) -> (status, body). Every call is recorded and must
    be a GET."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def request(self, method, api, path="", *, payload=None, query=None):
        assert method == "GET", f"non-GET request issued: {method} {api} {path}"
        assert payload is None
        self.calls.append((api, path, dict(query or {})))
        route = self.routes.get((api, path))
        if route is None:
            route = self.routes.get((api, "*"))
        if route is None:
            return 404, {"error": f"no fake route for {api} {path}"}
        return route(query or {}) if callable(route) else route

    def ca_bundle_digest_fields(self):
        return {"ca_bundle": {"source": "fake", "path": "/x"}}


def record_routes(hybrid=None, extra=None):
    routes = {
        ("tracker", "/_/task/ENC-TSK-Q33"): (200, {"success": True, "record": _RECORD}),
        ("coordination", "/components"): (
            200,
            {"components": [{"component_id": "comp-a", "x": 1}, {"component_id": "comp-b"}], "count": 2},
        ),
        ("governance", "/dictionary"): (200, {"entity": "tracker.task", "definition": {}}),
        ("document", "/search"): (200, {"success": True, "documents": [], "count": 0}),
        ("coordination", "/projects/enceladus"): (200, {"project": {"project_id": "enceladus"}}),
        ("graph_query", ""): (200, hybrid if hybrid is not None else hybrid_body()),
        ("health", ""): (200, {"governance_hash": "f" * 64}),
    }
    routes.update(extra or {})
    return routes


def run_verb(argv, client, root):
    args = cc.build_parser().parse_args(list(argv) + ["--out-dir", str(root)])
    return cc.run_compact_context(args, client, profile="prod", key_source="key_file")


def _call(client, api):
    return [c for c in client.calls if c[0] == api]


class ModeInferenceTests(unittest.TestCase):
    def test_inference_matches_the_server_composer(self):
        self.assertEqual(cc.infer_mode(None, "ENC-TSK-1", None, None, None), "record")
        self.assertEqual(cc.infer_mode(None, None, "DOC-1", None, None), "document")
        self.assertEqual(cc.infer_mode(None, None, None, "q", "p"), "topic")
        self.assertEqual(cc.infer_mode(None, None, None, None, "p"), "project")
        self.assertIsNone(cc.infer_mode(None, None, None, None, None))
        self.assertEqual(cc.infer_mode("FEATURE", "ENC-TSK-1", None, None, None), "feature")
        # record_id outranks document_id outranks query outranks project_id
        self.assertEqual(cc.infer_mode(None, "ENC-TSK-1", "DOC-1", "q", "p"), "record")
        self.assertEqual(cc.infer_mode(None, None, "DOC-1", "q", "p"), "document")

    def test_top_n_clamped(self):
        self.assertEqual(cc.clamp_top_n(0), 1)
        self.assertEqual(cc.clamp_top_n(500), 50)
        self.assertEqual(cc.clamp_top_n("x"), 20)
        args = cc.build_parser().parse_args(["--record-id", "ENC-TSK-1", "--top-n", "999"])
        self.assertEqual(args.top_n, 50)
        self.assertEqual(cc.build_parser().parse_args(["--record-id", "ENC-TSK-1"]).top_n, 20)


class DerivedQueryTests(unittest.TestCase):
    def test_title_plus_intent_normalized_and_capped(self):
        self.assertEqual(
            cc.derive_query(_RECORD), "ui-v2 PWA: stop serving feed corpus Remediate the stale feed corpus"
        )
        long = {"title": "T" * 200, "intent": "I" * 200}
        self.assertEqual(len(cc.derive_query(long)), 300)

    def test_fallback_to_title_when_intent_missing(self):
        self.assertEqual(cc.derive_query({"title": " Only  title "}), "Only title")
        self.assertEqual(cc.derive_query({"title": "T" * 400}), "T" * 300)
        self.assertEqual(cc.derive_query({}), "")


class RecordModeRunTests(unittest.TestCase):
    def test_sends_derived_query_and_record_anchor_and_passes_order_through(self):
        # Server nodes deliberately NOT sorted by score: order is passed verbatim.
        nodes = [_node(0, final_rank=1, fused_rank=9), _node(1, final_rank=2, fused_rank=3), _node(2, final_rank=3, fused_rank=1)]
        nodes[0]["_final_score"], nodes[2]["_final_score"] = 0.001, 0.9
        client = FakeClient(record_routes(hybrid_body(3, nodes=nodes)))
        with tempfile.TemporaryDirectory() as tmp:
            digest, code = run_verb(["--mode", "task", "--record-id", "ENC-TSK-Q33", "--top-n", "3"], client, tmp)
            self.assertEqual(code, 0)
            (hybrid_call,) = _call(client, "graph_query")
            q = hybrid_call[2]
            self.assertEqual(q["search_type"], "hybrid")
            self.assertEqual(q["anchor_record_id"], "ENC-TSK-Q33")
            self.assertEqual(q["project_id"], "enceladus")
            self.assertEqual(q["top_n"], 3)
            self.assertEqual(q["query"], "ui-v2 PWA: stop serving feed corpus Remediate the stale feed corpus")
            self.assertEqual([r[0] for r in digest["ranking"]], [n["record_id"] for n in nodes])
            self.assertEqual([r[2] for r in digest["ranking"]], [1, 2, 3])
            self.assertEqual(digest["retrieval"]["signals_present"], ["vector", "graph", "keyword"])
            self.assertEqual(digest["retrieval"]["signals_absent"], {"graph": "gds_unavailable"})
            self.assertEqual(digest["retrieval"]["candidates"], {"v": 116, "g": 25, "k": 25})
            self.assertEqual(digest["retrieval"]["composer"], "elr-1")
            self.assertEqual(digest["retrieval"]["embedding_coverage_sample"], [15, 15])
            self.assertEqual(digest["governance_hash"], "f" * 16)
            self.assertTrue(digest["ok"])
            self.assertNotIn("partial", digest["header"])

            run_dir = Path(digest["header"]["root"]) / digest["header"]["run_id"]
            ids = (run_dir / digest["ids_file"]).read_text().splitlines()
            self.assertEqual(ids, [n["record_id"] for n in nodes])
            self.assertEqual(len(digest["header"]["run_id"]), 26)

    def test_fused_order_uses_server_fused_rank_and_ids_file_follows(self):
        nodes = [_node(0, final_rank=1, fused_rank=9), _node(1, final_rank=2, fused_rank=3), _node(2, final_rank=3, fused_rank=1)]
        client = FakeClient(record_routes(hybrid_body(3, nodes=nodes)))
        with tempfile.TemporaryDirectory() as tmp:
            digest, _ = run_verb(["--record-id", "ENC-TSK-Q33", "--order", "fused"], client, tmp)
            self.assertEqual([r[3] for r in digest["ranking"]], [1, 3, 9])
            run_dir = Path(digest["header"]["root"]) / digest["header"]["run_id"]
            ids = (run_dir / digest["ids_file"]).read_text().splitlines()
            self.assertEqual(ids, [nodes[2]["record_id"], nodes[1]["record_id"], nodes[0]["record_id"]])

    def test_sections_land_with_bytes_and_sha_and_components_are_filtered(self):
        client = FakeClient(record_routes())
        with tempfile.TemporaryDirectory() as tmp:
            digest, _ = run_verb(["--record-id", "ENC-TSK-Q33"], client, tmp)
            run_dir = Path(digest["header"]["root"]) / digest["header"]["run_id"]
            self.assertEqual(
                sorted(digest["sections"]), ["components", "governance", "hybrid", "project", "record", "related_documents"]
            )
            for name, (size, sha) in digest["sections"].items():
                data = (run_dir / f"{name}.json").read_bytes()
                self.assertEqual(len(data), size)
                self.assertEqual(hashlib.sha256(data).hexdigest()[:32], sha)
            comps = json.loads((run_dir / "components.json").read_text())
            self.assertEqual([c["component_id"] for c in comps["components"]], ["comp-a"])
            self.assertEqual(comps["component_resolution"]["unmatched"], ["comp-gone"])
            record = json.loads((run_dir / "record.json").read_text())
            self.assertEqual(len(record["record"]["history"]), 5)  # bodies are never truncated

    def test_no_flags_skip_their_sections_and_history_flags_shape_only_the_landed_record(self):
        client = FakeClient(record_routes())
        with tempfile.TemporaryDirectory() as tmp:
            digest, _ = run_verb(
                [
                    "--record-id", "ENC-TSK-Q33", "--no-components", "--no-governance",
                    "--no-related-documents", "--no-hybrid", "--history-limit", "2",
                ],
                client,
                tmp,
            )
            self.assertEqual(sorted(digest["sections"]), ["project", "record"])
            self.assertNotIn("ranking", digest)
            self.assertFalse(_call(client, "graph_query"))
            run_dir = Path(digest["header"]["root"]) / digest["header"]["run_id"]
            self.assertEqual(len(json.loads((run_dir / "record.json").read_text())["record"]["history"]), 2)

    def test_failed_section_makes_a_partial_composition_that_still_exits_zero(self):
        client = FakeClient(record_routes(extra={("document", "/search"): (500, {"error": "boom"})}))
        with tempfile.TemporaryDirectory() as tmp:
            digest, code = run_verb(["--record-id", "ENC-TSK-Q33"], client, tmp)
        self.assertEqual(code, 0)
        self.assertTrue(digest["header"]["partial"])
        self.assertIn("related_documents_unavailable_http_500", digest["warnings"])
        self.assertNotIn("related_documents", digest["sections"])

    def test_unreadable_record_is_unusable(self):
        client = FakeClient(record_routes(extra={("tracker", "/_/task/ENC-TSK-Q33"): (404, {"error": "nope"})}))
        with tempfile.TemporaryDirectory() as tmp:
            digest, code = run_verb(["--record-id", "ENC-TSK-Q33"], client, tmp)
        self.assertEqual(code, 1)
        self.assertFalse(digest["ok"])
        self.assertIn("record_fetch_failed_http_404", digest["anomalies"])
        self.assertFalse(_call(client, "graph_query"))


class TopicModeTests(unittest.TestCase):
    def test_topic_without_anchor_reports_graph_absent_no_anchor(self):
        body = hybrid_body(
            2,
            signal_availability={"vector": True, "graph": False, "keyword": True},
            graph_algorithm="unavailable",
        )
        routes = {
            ("coordination", "/projects/enceladus"): (200, {"project": {}}),
            ("document", "/search"): (200, {"documents": []}),
            ("graph_query", ""): (200, body),
            ("health", ""): (200, {}),
        }
        client = FakeClient(routes)
        with tempfile.TemporaryDirectory() as tmp:
            digest, code = run_verb(["--query", "elr compact context", "--project-id", "enceladus"], client, tmp)
        self.assertEqual(code, 0)
        self.assertEqual(digest["header"]["mode"], "topic")
        self.assertEqual(digest["retrieval"]["signals_present"], ["vector", "keyword"])
        self.assertEqual(digest["retrieval"]["signals_absent"], {"graph": "no_anchor"})
        self.assertFalse(_call(client, "tracker"))
        (hybrid_call,) = _call(client, "graph_query")
        self.assertNotIn("anchor_record_id", {k: v for k, v in hybrid_call[2].items() if v is not None})

    def test_absent_signal_reasons_follow_inputs_and_server_fields(self):
        body = hybrid_body(1, signal_availability={"vector": False, "graph": False, "keyword": True})
        present, absent = cc.signal_posture(body, query_sent=True, anchor_sent=True)
        self.assertEqual(present, ["keyword"])
        self.assertEqual(absent, {"vector": "embedding_unavailable", "graph": "graph_unavailable"})
        present, absent = cc.signal_posture(
            hybrid_body(1, signal_availability={"vector": False, "graph": True, "keyword": False}, graph_algorithm="gds"),
            query_sent=False,
            anchor_sent=True,
        )
        self.assertEqual(present, ["graph"])
        self.assertEqual(absent, {"vector": "no_query", "keyword": "no_query"})

    def test_reference_section_is_a_plain_grep_of_the_reference_document(self):
        routes = {
            ("coordination", "/projects/enceladus"): (200, {"project": {}}),
            ("document", "/search"): lambda q: (
                (200, {"documents": [{"document_id": "DOC-REF"}]}) if q.get("keyword") == "reference" else (200, {"documents": []})
            ),
            ("document", "/DOC-REF"): (200, {"content": "# Top\nalpha\nElr compact context here\nomega"}),
            ("graph_query", ""): (200, hybrid_body(1)),
            ("health", ""): (200, {}),
        }
        client = FakeClient(routes)
        with tempfile.TemporaryDirectory() as tmp:
            digest, _ = run_verb(["--query", "compact context", "--project-id", "enceladus"], client, tmp)
            run_dir = Path(digest["header"]["root"]) / digest["header"]["run_id"]
            ref = json.loads((run_dir / "reference.json").read_text())
        self.assertEqual(ref["source_document_id"], "DOC-REF")
        self.assertEqual(ref["matches"][0]["line_number"], 3)
        self.assertEqual(ref["matches"][0]["section"], "# Top")


class ProjectAndDocumentModeTests(unittest.TestCase):
    def test_project_mode_keeps_first_page_of_documents_and_sends_no_hybrid(self):
        docs = [{"document_id": f"DOC-{i}"} for i in range(25)]
        routes = {
            ("coordination", "/projects/enceladus"): (200, {"project": {}}),
            ("document", ""): (200, {"documents": docs}),
            ("health", ""): (200, {}),
        }
        client = FakeClient(routes)
        with tempfile.TemporaryDirectory() as tmp:
            digest, code = run_verb(["--project-id", "enceladus"], client, tmp)
            run_dir = Path(digest["header"]["root"]) / digest["header"]["run_id"]
            landed = json.loads((run_dir / "documents.json").read_text())
        self.assertEqual(code, 0)
        self.assertEqual((landed["count"], landed["total"]), (10, 25))
        self.assertEqual(digest["header"]["mode"], "project")
        self.assertFalse(_call(client, "graph_query"))
        self.assertNotIn("ranking", digest)
        self.assertNotIn("ids_file", digest)

    def test_document_mode_lands_the_document(self):
        routes = {("document", "/DOC-X"): (200, {"document_id": "DOC-X", "content": "body"}), ("health", ""): (200, {})}
        client = FakeClient(routes)
        with tempfile.TemporaryDirectory() as tmp:
            digest, code = run_verb(["--document-id", "DOC-X"], client, tmp)
        self.assertEqual(code, 0)
        self.assertEqual(sorted(digest["sections"]), ["document"])


class ExitCodeTests(unittest.TestCase):
    def test_missing_contract_key_exits_8_response_shape_drift(self):
        body = hybrid_body(3)
        del body["rrf_k"]
        client = FakeClient(record_routes(body))
        with tempfile.TemporaryDirectory() as tmp:
            digest, code = run_verb(["--record-id", "ENC-TSK-Q33"], client, tmp)
            self.assertEqual(code, 8)
            self.assertIn("response_shape_drift", digest["anomalies"])
            self.assertIn("response_shape_drift:rrf_k", digest["anomalies"])
            self.assertEqual(list(Path(tmp).iterdir()), [])  # nothing landed on drift

    def test_missing_node_key_names_the_node_field(self):
        body = hybrid_body(2)
        del body["nodes"][1]["_final_rank"]
        client = FakeClient(record_routes(body))
        with tempfile.TemporaryDirectory() as tmp:
            digest, code = run_verb(["--record-id", "ENC-TSK-Q33"], client, tmp)
        self.assertEqual(code, 8)
        self.assertIn("response_shape_drift:nodes[1]._final_rank", digest["anomalies"])

    def test_unknown_additive_key_warns_but_does_not_fail(self):
        client = FakeClient(record_routes(hybrid_body(2, brand_new_key=1)))
        with tempfile.TemporaryDirectory() as tmp:
            digest, code = run_verb(["--record-id", "ENC-TSK-Q33"], client, tmp)
        self.assertEqual(code, 0)
        self.assertIn("unexpected_hybrid_key:brand_new_key", digest["warnings"])

    def test_hybrid_400_or_404_exits_6_hybrid_unsupported(self):
        for status in (400, 404):
            with self.subTest(status=status):
                client = FakeClient(record_routes(extra={("graph_query", ""): (status, {"error": "unsupported search_type"})}))
                with tempfile.TemporaryDirectory() as tmp:
                    digest, code = run_verb(["--record-id", "ENC-TSK-Q33"], client, tmp)
                    self.assertEqual(code, 6)
                    self.assertEqual(digest["anomalies"], ["hybrid_unsupported_by_server"])
                    self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_hybrid_server_error_is_unusable_exit_1(self):
        client = FakeClient(record_routes(extra={("graph_query", ""): (503, {"error": "down"})}))
        with tempfile.TemporaryDirectory() as tmp:
            digest, code = run_verb(["--record-id", "ENC-TSK-Q33"], client, tmp)
        self.assertEqual(code, 1)
        self.assertIn("hybrid_call_failed_http_503", digest["anomalies"])

    def test_tls_unresolved_exits_4(self):
        client = FakeClient({("tracker", "*"): (elr_tls.TLS_UNRESOLVED_STATUS, {"error": "x"})})
        with tempfile.TemporaryDirectory() as tmp:
            digest, code = run_verb(["--record-id", "ENC-TSK-Q33"], client, tmp)
        self.assertEqual(code, elr_tls.EXIT_CODE_TLS_UNRESOLVED)
        self.assertEqual(code, 4)
        self.assertIn("ca_bundle", digest)

    def test_main_exits_7_before_any_request_when_no_credential(self):
        refusal = {"operation": "x", "ok": False, "status": "no_credential"}
        out = io.StringIO()
        with patch.object(cc.elr_identity, "credential_refusal", return_value=refusal), patch.object(
            cc, "InternalClient"
        ) as client_cls, contextlib.redirect_stdout(out):
            code = cc.main(["--record-id", "ENC-TSK-Q33"])
        self.assertEqual(code, 7)
        client_cls.assert_not_called()

    def test_main_requires_a_mode_or_anchor_argument(self):
        with self.assertRaises(SystemExit) as ctx, contextlib.redirect_stderr(io.StringIO()):
            cc.main([])
        self.assertEqual(ctx.exception.code, 2)


class DigestBudgetTests(unittest.TestCase):
    """M-3: digest_bytes <= 1024 + 192 * top_n, with 64-char titles."""

    def _root(self, tmp: str) -> Path:
        # Realistic root length: /Users/<name>/.enceladus/context is ~32 chars;
        # a macOS tempdir would add ~50 and make the bound look worse than it is.
        root = Path(tempfile.mkdtemp(dir="/tmp", prefix="c")) / ".enceladus" / "context"
        self.addCleanup(shutil.rmtree, root.parent, True)
        return root

    def test_budget_holds_for_each_top_n_with_full_width_rows(self):
        for top_n in (5, 10, 20, 50):
            with self.subTest(top_n=top_n):
                client = FakeClient(record_routes(hybrid_body(top_n)))
                with tempfile.TemporaryDirectory() as tmp:
                    digest, code = run_verb(["--record-id", "ENC-TSK-Q33", "--top-n", str(top_n)], client, self._root(tmp))
                    self.assertEqual(code, 0)
                    printed = cc.serialize_digest(digest).encode("utf-8")
                    self.assertEqual(digest["header"]["digest_bytes"], len(printed))
                    self.assertLessEqual(len(printed), 1024 + 192 * top_n)
                    self.assertEqual(len(digest["ranking"]), top_n)  # nothing was dropped to fit
                    self.assertNotIn("truncated", digest["header"])
                    for row in digest["ranking"]:
                        self.assertLessEqual(len(row[-1]), 64)
                        self.assertEqual(len(row[-1]), 64)

    def test_tight_max_tokens_drops_tail_rows_and_sets_truncated(self):
        client = FakeClient(record_routes(hybrid_body(20)))
        with tempfile.TemporaryDirectory() as tmp:
            digest, _ = run_verb(["--record-id", "ENC-TSK-Q33", "--max-tokens", "900"], client, tmp)
        printed = len(cc.serialize_digest(digest).encode("utf-8"))
        self.assertLessEqual(printed, 3600)
        self.assertTrue(digest["header"]["truncated"])
        self.assertLess(len(digest["ranking"]), 20)
        # Head rows are the server's head rows (tail dropped, order untouched).
        self.assertEqual(digest["ranking"][0][0], hybrid_body(20)["nodes"][0]["record_id"])

    def test_digest_fields_are_registered_in_the_strict_allow_list(self):
        from elr_lib import digest as elr_digest

        for field in ("header", "retrieval", "ranking", "sections", "ids_file", "warnings"):
            self.assertIn(field, elr_digest.optional_fields())
        with self.assertRaises(ValueError):
            elr_digest.build_digest("x", True, 200, body={"nodes": []})


class StaticSafetyTests(unittest.TestCase):
    def setUp(self):
        self.source = (_ELR_ROOT / "elr_compact_context.py").read_text(encoding="utf-8")
        self.tree = ast.parse(self.source)

    def test_no_non_get_request_path_exists(self):
        verbs = {"POST", "PUT", "PATCH", "DELETE"}
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                self.assertNotIn(node.value.upper(), verbs, f"non-GET verb literal at line {node.lineno}")
        request_calls = [
            n
            for n in ast.walk(self.tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "request"
        ]
        self.assertTrue(request_calls)
        for call in request_calls:
            first = call.args[0]
            self.assertIsInstance(first, ast.Constant, f"request method not a literal at line {call.lineno}")
            self.assertEqual(first.value, "GET")
        for node in ast.walk(self.tree):
            if isinstance(node, ast.keyword):
                self.assertNotEqual(node.arg, "payload", "payload= implies a write")
            if isinstance(node, ast.Attribute):
                self.assertNotIn(node.attr, {"urlopen", "Request"}, "module must go through InternalClient only")

    def test_only_stdlib_and_elr_imports(self):
        allowed_third_party = {"elr_lib", "elr_batch_get"}
        stdlib = set(sys_stdlib_names())
        for path in ("elr_compact_context.py", "elr_lib/context_store.py"):
            tree = ast.parse((_ELR_ROOT / path).read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [a.name.split(".")[0] for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    names = [(node.module or "").split(".")[0]]
                for name in names:
                    self.assertTrue(name in stdlib or name in allowed_third_party, f"{path}: non-stdlib import {name}")


def sys_stdlib_names():
    import sys

    return sys.stdlib_module_names


class ContextStoreTests(unittest.TestCase):
    def test_ulid_shape_and_time_ordering(self):
        a = context_store.new_ulid(now_ms=1_000_000)
        b = context_store.new_ulid(now_ms=2_000_000)
        self.assertEqual(len(a), 26)
        self.assertRegex(a, r"^[0-9A-HJKMNP-TV-Z]{26}$")
        self.assertLess(a, b)

    def test_root_resolution_order(self):
        with patch.dict("os.environ", {context_store.CONTEXT_DIR_ENV: "/env/dir"}):
            self.assertEqual(str(context_store.context_root("/explicit")), "/explicit")
            self.assertEqual(str(context_store.context_root(None)), "/env/dir")
        with patch.dict("os.environ", {}, clear=False):
            import os

            os.environ.pop(context_store.CONTEXT_DIR_ENV, None)
            self.assertTrue(str(context_store.context_root(None)).endswith(".enceladus/context"))

    def test_ids_file_is_consumable_by_batch_get(self):
        import elr_batch_get

        with tempfile.TemporaryDirectory() as tmp:
            path = context_store.write_ids_file(Path(tmp), "RUN1", ["ENC-TSK-1", "DOC-ABC123", "ENC-ISS-2"])
            self.assertEqual(path.name, "RUN1.ids")
            self.assertEqual(elr_batch_get.load_ids_file(str(path)), ["ENC-TSK-1", "DOC-ABC123", "ENC-ISS-2"])


if __name__ == "__main__":
    unittest.main()
