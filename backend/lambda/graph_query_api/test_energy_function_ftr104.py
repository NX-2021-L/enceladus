"""ENC-FTR-104 Phase 1 (ENC-TSK-I98) tests: per-retrieval energy function E(x).

Exercises:
  - energy_function.py pure math: per-component energy, E(x) composition,
    monotonicity in each component, the lambda-weight resolution order
    (AppConfig -> env var -> default), and the documented total_weight()
    normalization convention.
  - graph_algorithm provenance tagging: compute_retrieval_energy must report
    ppr_source_is_gds_pagerank == True only when graph_algorithm ==
    "gds_pagerank" (FTR-104 AC-2: E_PPR must come from the FTR-101 standing
    AGA projection, not the cypher_fallback proxy).
  - Wiring into lambda_function._query_hybrid: each final node carries
    _retrieval_energy, per_node_fusion carries retrieval_energy, the response
    carries a retrieval_records[] list shaped for
    drift_telemetry.compute_spurious_attractor_rate, and the S3
    pathway-telemetry record gains an additive "energy" block.

Pure unit tests — no live Neo4j/AWS/AppConfig. The Neo4j driver, the AppConfig
HTTP extension, and the per-signal helper functions are mocked, mirroring the
existing test_hybrid_retrieval.py / test_pathway_telemetry_ftr082.py /
test_standing_projection_ftr101.py conventions in this package.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import energy_function as ef  # noqa: E402
import lambda_function as lf  # noqa: E402


class TestEnergyComponent(unittest.TestCase):
    def test_already_normalized_uses_score_directly(self):
        self.assertAlmostEqual(ef.energy_component(0.92, None, already_normalized=True), 0.08)

    def test_call_relative_normalization(self):
        # Best-in-call candidate (score == max) always gets zero energy.
        self.assertAlmostEqual(ef.energy_component(10.0, 10.0), 0.0)
        self.assertAlmostEqual(ef.energy_component(8.0, 10.0), 0.2)

    def test_missing_score_is_maximal_energy(self):
        self.assertEqual(ef.energy_component(None, 10.0), 1.0)

    def test_missing_max_is_maximal_energy(self):
        self.assertEqual(ef.energy_component(5.0, None), 1.0)
        self.assertEqual(ef.energy_component(5.0, 0.0), 1.0)

    def test_clamped_to_unit_interval(self):
        # A score exceeding max (numerical edge case) must not produce negative energy.
        self.assertEqual(ef.energy_component(12.0, 10.0), 0.0)


class TestComputeEnergyWorkedExample(unittest.TestCase):
    """Mirrors the module-docstring worked example verbatim."""

    def test_worked_example(self):
        e_vector = ef.energy_component(0.92, None, already_normalized=True)
        e_ppr = ef.energy_component(8.0, 10.0)
        e_keyword = ef.energy_component(3.0, 3.0)
        self.assertAlmostEqual(e_vector, 0.08)
        self.assertAlmostEqual(e_ppr, 0.20)
        self.assertAlmostEqual(e_keyword, 0.00)
        energy = ef.compute_energy(e_vector, e_ppr, e_keyword, lambda_graph=0.5, lambda_kw=0.25)
        self.assertAlmostEqual(energy, 0.18)


class TestMonotonicity(unittest.TestCase):
    """FTR-104 AC-2 test contract: E(x) is strictly monotonic in each
    component, holding the other two fixed."""

    def test_monotonic_in_e_vector(self):
        lo = ef.compute_energy(0.1, 0.4, 0.4, lambda_graph=0.5, lambda_kw=0.25)
        hi = ef.compute_energy(0.5, 0.4, 0.4, lambda_graph=0.5, lambda_kw=0.25)
        self.assertLess(lo, hi)

    def test_monotonic_in_e_ppr(self):
        lo = ef.compute_energy(0.3, 0.1, 0.4, lambda_graph=0.5, lambda_kw=0.25)
        hi = ef.compute_energy(0.3, 0.6, 0.4, lambda_graph=0.5, lambda_kw=0.25)
        self.assertLess(lo, hi)

    def test_monotonic_in_e_keyword(self):
        lo = ef.compute_energy(0.3, 0.4, 0.1, lambda_graph=0.5, lambda_kw=0.25)
        hi = ef.compute_energy(0.3, 0.4, 0.6, lambda_graph=0.5, lambda_kw=0.25)
        self.assertLess(lo, hi)

    def test_zero_lambda_neutralizes_term(self):
        """A zero lambda fully neutralizes that term's influence on E(x)."""
        a = ef.compute_energy(0.3, 0.1, 0.5, lambda_graph=0.0, lambda_kw=0.25)
        b = ef.compute_energy(0.3, 0.9, 0.5, lambda_graph=0.0, lambda_kw=0.25)
        self.assertAlmostEqual(a, b)


class TestLambdaWeightResolution(unittest.TestCase):
    def test_defaults_when_unconfigured(self):
        with mock.patch.object(ef, "_appconfig_energy_config", return_value={}):
            with mock.patch.dict("os.environ", {}, clear=False):
                for var in ("ENERGY_LAMBDA_GRAPH", "ENERGY_LAMBDA_KW"):
                    __import__("os").environ.pop(var, None)
                lambda_graph, lambda_kw = ef.load_lambda_weights()
        self.assertEqual(lambda_graph, ef.DEFAULT_LAMBDA_GRAPH)
        self.assertEqual(lambda_kw, ef.DEFAULT_LAMBDA_KW)

    def test_env_var_overrides_default(self):
        with mock.patch.object(ef, "_appconfig_energy_config", return_value={}):
            with mock.patch.dict("os.environ", {"ENERGY_LAMBDA_GRAPH": "0.9", "ENERGY_LAMBDA_KW": "0.1"}):
                lambda_graph, lambda_kw = ef.load_lambda_weights()
        self.assertEqual(lambda_graph, 0.9)
        self.assertEqual(lambda_kw, 0.1)

    def test_appconfig_overrides_env_var(self):
        with mock.patch.object(
            ef, "_appconfig_energy_config",
            return_value={"lambda_graph": 0.77, "lambda_kw": 0.33},
        ):
            with mock.patch.dict("os.environ", {"ENERGY_LAMBDA_GRAPH": "0.9", "ENERGY_LAMBDA_KW": "0.1"}):
                lambda_graph, lambda_kw = ef.load_lambda_weights()
        self.assertEqual(lambda_graph, 0.77)
        self.assertEqual(lambda_kw, 0.33)

    def test_malformed_env_var_falls_back_to_default(self):
        with mock.patch.object(ef, "_appconfig_energy_config", return_value={}):
            with mock.patch.dict("os.environ", {"ENERGY_LAMBDA_GRAPH": "not-a-number"}):
                lambda_graph, _ = ef.load_lambda_weights()
        self.assertEqual(lambda_graph, ef.DEFAULT_LAMBDA_GRAPH)

    def test_negative_weight_falls_back_to_default(self):
        with mock.patch.object(ef, "_appconfig_energy_config", return_value={}):
            with mock.patch.dict("os.environ", {"ENERGY_LAMBDA_KW": "-1.0"}):
                _, lambda_kw = ef.load_lambda_weights()
        self.assertEqual(lambda_kw, ef.DEFAULT_LAMBDA_KW)

    def test_appconfig_extension_unreachable_degrades_to_empty(self):
        """No localhost:2772 extension in a unit test — must never raise."""
        cfg = ef._appconfig_energy_config()
        self.assertEqual(cfg, {})


class TestTotalWeightConvention(unittest.TestCase):
    """Documented convention: total_weight = 1.0 (implicit E_vector) +
    lambda_graph + lambda_kw — NOT a convex combination normalized to 1.0."""

    def test_default_total_weight(self):
        self.assertAlmostEqual(
            ef.total_weight(ef.DEFAULT_LAMBDA_GRAPH, ef.DEFAULT_LAMBDA_KW),
            1.0 + ef.DEFAULT_LAMBDA_GRAPH + ef.DEFAULT_LAMBDA_KW,
        )

    def test_total_weight_not_normalized_to_one(self):
        # Internal-consistency assertion per the module docstring: this
        # convention deliberately does NOT normalize to 1.0.
        self.assertNotAlmostEqual(
            ef.total_weight(ef.DEFAULT_LAMBDA_GRAPH, ef.DEFAULT_LAMBDA_KW), 1.0,
        )

    def test_total_weight_tracks_inputs(self):
        self.assertAlmostEqual(ef.total_weight(0.0, 0.0), 1.0)
        self.assertAlmostEqual(ef.total_weight(1.0, 1.0), 3.0)


class TestGraphAlgorithmProvenance(unittest.TestCase):
    """FTR-104 AC-2: E_PPR's source must be tagged and verifiable."""

    def test_gds_pagerank_tagged_true(self):
        energy = ef.compute_retrieval_energy(
            vector_score=0.9, graph_score=8.0, keyword_score=2.0,
            max_graph_score=10.0, max_keyword_score=2.0,
            graph_algorithm="gds_pagerank",
            lambda_graph=0.5, lambda_kw=0.25,
        )
        self.assertEqual(energy["graph_algorithm"], "gds_pagerank")
        self.assertTrue(energy["ppr_source_is_gds_pagerank"])

    def test_cypher_fallback_tagged_false(self):
        energy = ef.compute_retrieval_energy(
            vector_score=0.9, graph_score=8.0, keyword_score=2.0,
            max_graph_score=10.0, max_keyword_score=2.0,
            graph_algorithm="cypher_fallback",
            lambda_graph=0.5, lambda_kw=0.25,
        )
        self.assertFalse(energy["ppr_source_is_gds_pagerank"])

    def test_resolves_weights_when_omitted(self):
        with mock.patch.object(ef, "load_lambda_weights", return_value=(0.5, 0.25)):
            energy = ef.compute_retrieval_energy(
                vector_score=0.9, graph_score=None, keyword_score=None,
                max_graph_score=None, max_keyword_score=None,
                graph_algorithm="unavailable",
            )
        self.assertEqual(energy["lambda_graph"], 0.5)
        self.assertEqual(energy["lambda_kw"], 0.25)
        # Missing graph/keyword signal -> maximal energy on both terms.
        self.assertEqual(energy["E_PPR"], 1.0)
        self.assertEqual(energy["E_keyword"], 1.0)


class TestBuildRetrievalRecord(unittest.TestCase):
    def test_shape_matches_spurious_attractor_consumer_contract(self):
        energy = ef.compute_retrieval_energy(
            vector_score=0.9, graph_score=8.0, keyword_score=2.0,
            max_graph_score=10.0, max_keyword_score=2.0,
            graph_algorithm="gds_pagerank", lambda_graph=0.5, lambda_kw=0.25,
        )
        rec = ef.build_retrieval_record("ENC-TSK-001", energy)
        self.assertEqual(rec["record_id"], "ENC-TSK-001")
        self.assertIn("avg_retrieval_energy", rec)
        self.assertIn("retrieval_energy", rec)
        self.assertEqual(rec["avg_retrieval_energy"], rec["retrieval_energy"])
        self.assertEqual(rec["graph_algorithm"], "gds_pagerank")

        # drift_telemetry's consumer must accept this shape directly.
        import drift_telemetry
        rate = drift_telemetry.compute_spurious_attractor_rate([rec])
        self.assertIsNotNone(rate)


class TestHybridEnergyWiring(unittest.TestCase):
    """Integration: lambda_function._query_hybrid populates per-candidate
    energy fields end-to-end, with the Neo4j driver and per-signal helpers
    mocked out (mirrors test_standing_projection_ftr101's fake-driver idiom,
    but at the level of the already-tested per-signal functions rather than
    raw Cypher, since those are independently covered)."""

    def setUp(self):
        self.lambda_graph = 1.0
        self.lambda_kw = 0.1
        patchers = [
            mock.patch.object(lf, "_ensure_live_driver", side_effect=lambda d: d),
            mock.patch.object(lf, "_compute_query_embedding", return_value=[0.1, 0.2, 0.3]),
            mock.patch.object(
                lf, "_hybrid_vector_ranks",
                return_value=[
                    {"record_id": "ENC-TSK-001", "score": 0.92, "rank": 1},
                    {"record_id": "ENC-TSK-002", "score": 0.50, "rank": 2},
                ],
            ),
            mock.patch.object(
                lf, "_hybrid_graph_ranks_gds_warm",
                return_value=[
                    {"record_id": "ENC-TSK-001", "score": 8.0, "rank": 1},
                    {"record_id": "ENC-TSK-002", "score": 4.0, "rank": 2},
                ],
            ),
            mock.patch.object(
                lf, "_hybrid_keyword_ranks",
                return_value=[
                    {"record_id": "ENC-TSK-001", "score": 3.0, "rank": 1},
                ],
            ),
            mock.patch.object(
                lf, "_fetch_nodes_by_record_ids",
                return_value={
                    "ENC-TSK-001": {"record_id": "ENC-TSK-001", "_labels": ["Task"]},
                    "ENC-TSK-002": {"record_id": "ENC-TSK-002", "_labels": ["Task"]},
                },
            ),
            mock.patch.object(
                lf, "_reconstruct_pathway_edges",
                return_value=([], [], ["ENC-FTR-104"]),
            ),
            mock.patch.object(ef, "load_lambda_weights", return_value=(self.lambda_graph, self.lambda_kw)),
        ]
        self._emit_patch = mock.patch.object(lf, "_emit_pathway_telemetry")
        self.mock_emit = self._emit_patch.start()
        for p in patchers:
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(self._emit_patch.stop)

    def test_graph_algorithm_is_gds_pagerank(self):
        result = lf._query_hybrid(
            mock.MagicMock(), "enceladus",
            {"query": "energy function", "anchor_record_id": "ENC-FTR-104", "wave_id": "wave-1"},
        )
        self.assertEqual(result["graph_algorithm"], "gds_pagerank")

    def test_retrieval_records_populated_with_energy(self):
        result = lf._query_hybrid(
            mock.MagicMock(), "enceladus",
            {"query": "energy function", "anchor_record_id": "ENC-FTR-104", "wave_id": "wave-1"},
        )
        self.assertIn("retrieval_records", result)
        self.assertTrue(result["retrieval_records"])
        by_rid = {r["record_id"]: r for r in result["retrieval_records"]}
        self.assertIn("ENC-TSK-001", by_rid)
        top = by_rid["ENC-TSK-001"]
        self.assertIn("retrieval_energy", top)
        self.assertIn("avg_retrieval_energy", top)
        self.assertEqual(top["graph_algorithm"], "gds_pagerank")
        # ENC-TSK-001 is the best candidate on every signal (top score in
        # vector/graph/keyword) so its energy must be strictly lower than
        # ENC-TSK-002's (which is absent from the keyword signal entirely).
        by_rid_002 = by_rid.get("ENC-TSK-002")
        if by_rid_002 is not None:
            self.assertLess(top["retrieval_energy"], by_rid_002["retrieval_energy"])

    def test_nodes_and_per_node_fusion_carry_retrieval_energy(self):
        result = lf._query_hybrid(
            mock.MagicMock(), "enceladus",
            {
                "query": "energy function",
                "anchor_record_id": "ENC-FTR-104",
                "wave_id": "wave-1",
                "include_energy": "true",
            },
        )
        node_001 = next(n for n in result["nodes"] if n["record_id"] == "ENC-TSK-001")
        self.assertIn("_retrieval_energy", node_001)
        self.assertIn("energy_score", node_001)
        self.assertIn("energy_breakdown", node_001)
        self.assertIn("retrieval_energy", result["per_node_fusion"]["ENC-TSK-001"])

    def test_include_energy_false_omits_public_energy_fields(self):
        result = lf._query_hybrid(
            mock.MagicMock(), "enceladus",
            {"query": "energy function", "anchor_record_id": "ENC-FTR-104", "wave_id": "wave-1"},
        )
        node_001 = next(n for n in result["nodes"] if n["record_id"] == "ENC-TSK-001")
        self.assertNotIn("energy_score", node_001)
        self.assertNotIn("energy_breakdown", node_001)
        self.assertNotIn("_retrieval_energy", node_001)
        self.assertNotIn("retrieval_energy", result["per_node_fusion"]["ENC-TSK-001"])

    def test_energy_lambda_weights_echoed(self):
        result = lf._query_hybrid(
            mock.MagicMock(), "enceladus",
            {"query": "energy function", "anchor_record_id": "ENC-FTR-104", "wave_id": "wave-1"},
        )
        self.assertEqual(result["energy_lambda_weights"]["lambda_graph"], self.lambda_graph)
        self.assertEqual(result["energy_lambda_weights"]["lambda_kw"], self.lambda_kw)

    def test_pathway_telemetry_gains_additive_energy_block(self):
        lf._query_hybrid(
            mock.MagicMock(), "enceladus",
            {"query": "energy function", "anchor_record_id": "ENC-FTR-104", "wave_id": "wave-1"},
        )
        self.mock_emit.assert_called_once()
        emitted_record = self.mock_emit.call_args[0][0]
        # Pre-existing FTR-082 fields must still be present (additive-only change).
        for field in ("wave_id", "timestamp", "node_sequence", "edges_traversed",
                      "outcome", "intent_signature", "schema"):
            self.assertIn(field, emitted_record)
        self.assertIn("energy", emitted_record)
        self.assertEqual(emitted_record["energy"]["lambda_graph"], self.lambda_graph)
        self.assertEqual(emitted_record["energy"]["lambda_kw"], self.lambda_kw)
        self.assertTrue(emitted_record["energy"]["records"])

    def test_zero_signal_response_still_carries_empty_retrieval_records(self):
        with mock.patch.object(lf, "_hybrid_vector_ranks", return_value=[]), \
             mock.patch.object(lf, "_hybrid_graph_ranks_gds_warm", return_value=[]), \
             mock.patch.object(lf, "_check_gds_available", return_value=False), \
             mock.patch.object(lf, "_hybrid_graph_ranks_cypher_fallback", return_value=[]), \
             mock.patch.object(lf, "_hybrid_keyword_ranks", return_value=[]), \
             mock.patch.object(lf, "_compute_query_embedding", return_value=None):
            result = lf._query_hybrid(
                mock.MagicMock(), "enceladus",
                {"query": "nothing matches", "anchor_record_id": "ENC-FTR-104", "wave_id": "wave-1"},
            )
        self.assertEqual(result["retrieval_records"], [])
        self.assertEqual(result["energy_lambda_weights"]["lambda_graph"], self.lambda_graph)


if __name__ == "__main__":
    unittest.main()
