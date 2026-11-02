"""ENC-TSK-S10 (PLN-103 W1.3 / N14): record mode reuses the anchor node's stored
embedding for the HNSW vector signal; Titan only as fallback or override."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import corroboration  # noqa: E402
import energy_function as ef  # noqa: E402
import lambda_function as lf  # noqa: E402

TITLE, INTENT = "Anchor title", "Anchor intent"
DERIVED = f"{TITLE} {INTENT}"
STORED = [0.5] * 8
NODES = {"ENC-TSK-001": {"record_id": "ENC-TSK-001", "_labels": ["Task"], "project_id": "enceladus",
                         "record_type": "task", "status": "open", "priority": "P1"}}


class _Result:
    def __init__(self, rec):
        self._rec = rec

    def single(self):
        return self._rec


class _Rec(dict):
    pass


class _Session:
    def __init__(self, rec):
        self._rec = rec

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, *a, **k):
        return _Result(self._rec)


class _Driver:
    def __init__(self, embedding=STORED):
        self.rec = _Rec(embedding=embedding, title=TITLE, intent=INTENT)

    def session(self):
        return _Session(self.rec)


def _run(tc, driver, params, titan=None):
    titan = titan or mock.MagicMock(return_value=[0.1] * 8)
    vec = mock.MagicMock(return_value=[{"record_id": "ENC-TSK-001", "score": 0.9, "rank": 1}])
    patchers = [
        mock.patch.object(lf, "_ensure_live_driver", side_effect=lambda d: d),
        mock.patch.object(lf, "_compute_query_embedding", titan),
        mock.patch.object(lf, "_hybrid_vector_ranks", vec),
        mock.patch.object(lf, "_hybrid_graph_ranks_gds_warm", return_value=[]),
        mock.patch.object(lf, "_check_gds_available", return_value=False),
        mock.patch.object(lf, "_hybrid_graph_ranks_cypher_fallback", return_value=[]),
        mock.patch.object(lf, "_hybrid_keyword_ranks", return_value=[]),
        mock.patch.object(lf.opensearch_keyword, "hybrid_keyword_ranks", return_value=([], {}, "down")),
        mock.patch.object(lf, "_fetch_nodes_by_record_ids", return_value=dict(NODES)),
        mock.patch.object(lf, "_reconstruct_pathway_edges", return_value=([], [], [])),
        mock.patch.object(lf, "_emit_pathway_telemetry"),
        mock.patch.object(lf, "_maybe_emit_stigmergic_trace"),
        mock.patch.object(ef, "load_lambda_weights", return_value=(1.0, 0.1)),
        mock.patch.object(corroboration, "load_alpha", return_value=0.02),
    ]
    for p in patchers:
        p.start()
        tc.addCleanup(p.stop)
    result = lf._query_hybrid(driver, "enceladus", dict(params))
    audit = lf._graphsearch_audit_record({}, dict(params), "hybrid", "enceladus", result, 5)
    return titan, vec, audit


REC_PARAMS = {"query": DERIVED, "anchor_record_id": "ENC-TSK-001"}


class TestAnchorEmbeddingReuse(unittest.TestCase):
    def test_anchor_with_embedding_makes_no_bedrock_call(self):
        titan, vec, audit = _run(self, _Driver(), REC_PARAMS)
        titan.assert_not_called()
        self.assertEqual(vec.call_args.args[2], STORED)
        self.assertEqual(audit["vector_source"], "anchor")

    def test_anchor_without_embedding_falls_back_to_titan(self):
        titan, vec, audit = _run(self, _Driver(embedding=None), REC_PARAMS)
        titan.assert_called_once()
        self.assertEqual(vec.call_args.args[2], [0.1] * 8)
        self.assertEqual(audit["vector_source"], "titan_fallback")

    def test_vector_source_titan_forces_titan(self):
        titan, vec, audit = _run(self, _Driver(), {**REC_PARAMS, "vector_source": "titan"})
        titan.assert_called_once()
        self.assertEqual(audit["vector_source"], "titan")

    def test_vector_source_anchor_overrides_text_match(self):
        titan, _vec, audit = _run(self, _Driver(), {**REC_PARAMS, "query": "free text", "vector_source": "anchor"})
        titan.assert_not_called()
        self.assertEqual(audit["vector_source"], "anchor")

    def test_caller_query_not_record_derived_uses_titan(self):
        titan, _vec, audit = _run(self, _Driver(), {**REC_PARAMS, "query": "something else"})
        titan.assert_called_once()
        self.assertEqual(audit["vector_source"], "titan")

    def test_audit_field_present_and_additive(self):
        _t, _v, audit = _run(self, _Driver(), REC_PARAMS)
        self.assertIn("vector_source", audit)
        self.assertIn("vector_ms", audit)


class TestVectorSourceGate(unittest.TestCase):
    def _qs(self, caller_type, value="titan"):
        qs = {"project_id": "enceladus", "search_type": "hybrid", "vector_source": value}
        seen = {}

        def fake_hybrid(driver, pid, params):
            seen.update(params)
            return {"nodes": [], "edges": [], "paths": []}

        with mock.patch.object(lf, "_get_neo4j_driver", return_value=object()), \
                mock.patch.dict(lf.SEARCH_HANDLERS, {"hybrid": fake_hybrid}), \
                mock.patch.object(lf, "_caller_attribution", return_value={"caller_type": caller_type}), \
                mock.patch.object(lf, "_graphsearch_audit_record", return_value={}), \
                mock.patch.object(lf, "_maybe_emit_stigmergic_trace"):
            try:
                lf._handle_search({"queryStringParameters": qs})
            except Exception:
                pass
        return seen

    def test_internal_and_agent_allowed(self):
        self.assertEqual(self._qs("internal").get("vector_source"), "titan")
        self.assertEqual(self._qs("agent", "ANCHOR").get("vector_source"), "anchor")

    def test_user_and_cookie_stripped(self):
        self.assertNotIn("vector_source", self._qs("user"))
        self.assertNotIn("vector_source", self._qs("cookie"))

    def test_invalid_value_stripped(self):
        self.assertNotIn("vector_source", self._qs("internal", "bogus"))


if __name__ == "__main__":
    unittest.main()
