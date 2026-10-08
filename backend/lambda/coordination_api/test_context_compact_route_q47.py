"""ENC-TSK-Q47: GET /api/v1/coordination/context/compact (single assembler route).

The composer is stubbed; the route must (a) pass the get_compact_context argument
set through, (b) copy ranking from hybrid_retrieval.nodes verbatim (order
preserved, no re-sort), (c) honour fields=digest|full, (d) 400 on bad input.
"""
import importlib.util
import json
import pathlib
import sys
import unittest
from unittest.mock import patch

MODULE_PATH = pathlib.Path(__file__).with_name("lambda_function.py")
SPEC = importlib.util.spec_from_file_location("coordination_lambda_compact_q47", MODULE_PATH)
lf = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = lf
SPEC.loader.exec_module(lf)


class _Text:
    def __init__(self, text):
        self.text = text


def _node(rid, final_rank, fused_rank, fscore, final_score, k_corr, b_corr, title):
    return {
        "record_id": rid, "record_type": rid.split("-")[1].lower(), "title": title,
        "_final_rank": final_rank, "_fused_rank": fused_rank,
        "_fused_score": fscore, "_final_score": final_score,
        "_per_signal_ranks": {"vector": 3, "keyword": 1},
        "_corroboration_count": k_corr, "_b_corr": b_corr, "_below_t3": False,
    }


# Deliberately NOT sorted by any score column: the route must not reorder.
NODES = [
    _node("ENC-TSK-Q33", 1, 21, 0.0123456789, 0.3123456, 1, 0.2999999, "Feed sync fix " + "x" * 80),
    _node("ENC-ISS-830", 2, 30, 0.02, 0.31, 1, 0.29, "Stale feed"),
    _node("DOC-AAAAAAAAAAAA", 3, 1, 0.0492, 0.0492, 0, 0.0, "Exact match doc"),
]
COMPOSED = {
    "success": True, "tool": "get_compact_context", "mode": "task",
    "result": {
        "record_context": {"record": {"id": "ENC-TSK-Q33"}},
        "hybrid_retrieval": {
            "nodes": NODES, "summary": "Hybrid: 3 nodes (vector=116, graph=0, keyword=25; graph_algo=cypher_fallback; embedded=3/3)",
            "signal_availability": {"vector": True, "graph": False, "keyword": True},
            "graph_algorithm": "cypher_fallback", "rrf_k": 60, "fsrs_t3_threshold": 0.7,
            "include_below_threshold": False, "duration_ms": 1029,
            "embedding_coverage_sample": {"covered": 3, "total_ranked": 3},
            "query_source": "derived_from_record", "query_head": "Feed sync fix",
        },
    },
    "partial": True, "warnings": ["code map unavailable: boom"],
    "underlying_calls": [{"tool": "get_issue_context", "status": "success"}],
    "metadata": {"section_count": 2},
}
RAW_HYBRID = {
    "corroboration_weber_k": 0.3,
    "pathway": {"intent_signature": "sig-1", "wave_id": "unassigned", "edge_count": 4},
}


class _FakeServer:
    def __init__(self, payload=COMPOSED):
        self.payload = payload
        self.seen_args = None

    async def get_compact_context_meta(self, args):
        self.seen_args = dict(args)
        cap = args.get("_hybrid_capture")
        if isinstance(cap, dict):
            cap.update(RAW_HYBRID)
        return [_Text(json.dumps(self.payload))]


def _event(**qs):
    return {"queryStringParameters": qs}


def _call(server, **qs):
    with patch.object(lf, "_load_mcp_server_module", return_value=server), \
         patch.object(lf, "_compute_governance_hash_local", return_value="gh123"):
        resp = lf._handle_context_compact(_event(**qs))
    return resp["statusCode"], json.loads(resp["body"])


class TestContextCompactRoute(unittest.TestCase):
    def test_digest_ranking_is_composer_order_verbatim(self):
        server = _FakeServer()
        status, body = _call(server, mode="task", record_id="ENC-TSK-Q33", project_id="enceladus")
        self.assertEqual(status, 200)
        self.assertEqual(body["schema"], "elr.compact_context_digest")
        self.assertEqual([r[0] for r in body["ranking"]], [n["record_id"] for n in NODES])
        row = body["ranking"][0]
        # [record_id, record_type, final_rank, fused_rank, fused_score, final_score, signals, k_corr, b_corr, below_t3, title]
        self.assertEqual(row[2:6], [1, 21, 0.012346, 0.312346])
        self.assertEqual(row[6], {"v": 3, "k": 1})
        self.assertEqual(row[7:10], [1, 0.3, False])
        self.assertEqual(len(row[10]), 64)
        self.assertNotIn("sections", body)  # fields=digest default
        self.assertEqual(body["fields"], "digest")

    def test_digest_header_retrieval_and_sections_summary(self):
        status, body = _call(_FakeServer(), mode="task", record_id="ENC-TSK-Q33")
        self.assertEqual(body["header"]["mode"], "task")
        self.assertEqual(body["header"]["anchor"], "ENC-TSK-Q33")
        self.assertTrue(body["header"]["partial"])
        self.assertEqual(body["header"]["governance_hash"], "gh123")
        self.assertEqual(body["header"]["server_duration_ms"], 1029)
        r = body["retrieval"]
        self.assertEqual((r["rrf_k"], r["weber_k"], r["fsrs_t3_threshold"]), (60, 0.3, 0.7))
        self.assertEqual(r["signals_present"], ["keyword", "vector"])
        self.assertEqual(r["signals_absent"], {"graph": "unavailable"})
        self.assertEqual(r["candidates"], {"vector": 116, "graph": 0, "keyword": 25})
        self.assertEqual((r["intent_signature"], r["pathway_edge_count"]), ("sig-1", 4))
        self.assertEqual(set(body["sections_summary"]), {"record_context", "hybrid_retrieval"})
        for meta in body["sections_summary"].values():
            self.assertEqual(len(meta["sha256"]), 64)
            self.assertGreater(meta["bytes"], 0)
        self.assertEqual(body["warnings"], ["code map unavailable: boom"])

    def test_fields_full_adds_sections_and_legacy_meta(self):
        status, body = _call(_FakeServer(), mode="task", record_id="ENC-TSK-Q33", fields="full")
        self.assertEqual(status, 200)
        self.assertEqual(body["sections"], COMPOSED["result"])
        self.assertEqual(body["underlying_calls"], COMPOSED["underlying_calls"])
        self.assertEqual(body["metadata"], COMPOSED["metadata"])

    def test_query_params_map_to_composer_args_with_types(self):
        server = _FakeServer()
        _call(server, mode="topic", project_id="enceladus", query="q", top_n="7", max_tokens="900",
              include_code_map="false", include_hybrid_retrieval="true", domains="a, b")
        a = server.seen_args
        self.assertEqual((a["top_n"], a["max_tokens"]), (7, 900))
        self.assertIs(a["include_code_map"], False)
        self.assertIs(a["include_hybrid_retrieval"], True)
        self.assertEqual(a["domains"], ["a", "b"])
        self.assertNotIn("include_governance", a)  # unset flags keep composer defaults

    def test_bad_mode_is_400(self):
        status, body = _call(_FakeServer(), mode="bogus")
        self.assertEqual(status, 400)

    def test_bad_fields_and_bad_int_are_400(self):
        self.assertEqual(_call(_FakeServer(), mode="project", fields="x")[0], 400)
        self.assertEqual(_call(_FakeServer(), mode="project", top_n="abc")[0], 400)

    def test_composer_invalid_input_maps_to_400(self):
        payload = {"success": False, "error": {"code": "invalid_input", "message": "mode is required"}}
        status, _ = _call(_FakeServer(payload))
        self.assertEqual(status, 400)

    def test_composer_failure_maps_to_502(self):
        payload = {"success": False, "error": {"code": "tool_error", "message": "boom"}}
        self.assertEqual(_call(_FakeServer(payload), mode="project", project_id="p")[0], 502)

    def test_no_hybrid_yields_empty_ranking(self):
        payload = {**COMPOSED, "result": {"project": {"project_id": "enceladus"}}}
        status, body = _call(_FakeServer(payload), mode="project", project_id="enceladus")
        self.assertEqual(body["ranking"], [])
        self.assertEqual(body["retrieval"], {})

    def test_route_is_dispatched_behind_auth_gate(self):
        event = {"httpMethod": "GET", "rawPath": "/api/v1/coordination/context/compact",
                 "requestContext": {"http": {"method": "GET", "path": "/api/v1/coordination/context/compact"}},
                 "queryStringParameters": {"mode": "bogus"}}
        with patch.object(lf, "_authenticate", return_value=({"sub": "x"}, None)) as auth:
            resp = lf.lambda_handler(event, None)
        auth.assert_called_once()
        self.assertEqual(resp["statusCode"], 400)
        denied = {"statusCode": 401, "headers": {}, "body": "{}"}
        with patch.object(lf, "_authenticate", return_value=(None, denied)):
            self.assertEqual(lf.lambda_handler(event, None)["statusCode"], 401)

    def test_loaded_server_module_is_marked_route_disabled(self):
        src = MODULE_PATH.read_text()
        self.assertIn('setattr(module, "COMPACT_CONTEXT_ROUTE_DISABLED", True)', src)


if __name__ == "__main__":
    unittest.main()
