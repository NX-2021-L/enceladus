"""ENC-FTR-110 Phase 1 (ENC-TSK-I92) tests: dispersion/corroboration
Weber-law bonus term.

Exercises:
  - corroboration.py pure math: cosine similarity/distance, the dispersion-
    constrained corroborator count (AC-2: near-duplicates must not count as
    corroborating each other), the Weber-Fechner B_corr formula (monotonic,
    diminishing-returns, call-relative normalization), and the Weber_k
    AppConfig -> env var -> default resolution order (mirrors
    test_energy_function_ftr104.TestLambdaWeightResolution).
  - Wiring into lambda_function._query_hybrid: per_node_fusion/nodes gain
    k_corr/b_corr/final_score/final_rank, fused_score/fused_rank stay the
    untouched pure-RRF values, and the AC-4 spurious-attractor hedge holds
    end-to-end — a single zero-corroboration candidate with the best pure-RRF
    score is outranked, by final_score, by a moderately-RRF-scored candidate
    with two genuine (dispersed) corroborators.

Pure unit tests — no live Neo4j/AWS/AppConfig. Mirrors the existing
test_energy_function_ftr104.py / test_hybrid_retrieval.py mocking
conventions in this package.
"""
from __future__ import annotations

import math
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import corroboration as cb  # noqa: E402
import lambda_function as lf  # noqa: E402

# --- Shared geometry fixtures (unit vectors in R^3, exact cosine values by
# construction) --------------------------------------------------------------
# B_CENTER and the two ~30-degree-off corroborators are mutually dispersed
# (pairwise cosine distance 0.375 >= the 0.3 dispersion floor) while each
# stays within the 0.80 similarity floor of B_CENTER.
B_CENTER = [1.0, 0.0, 0.0]
CORROBORATOR_1 = [0.8660254037844387, 0.5, 0.0]
CORROBORATOR_2 = [0.8660254037844387, -0.25, 0.4330127018922194]
# Orthogonal to B_CENTER and well outside the similarity floor of either
# corroborator above -- a record with no genuine support.
UNSUPPORTED = [0.0, 1.0, 0.0]
# Two near-duplicates of each other (cosine sim 0.98 -> distance 0.02), both
# "similar enough" to a candidate but NOT pairwise dispersed from each other.
NEAR_DUP_1 = [1.0, 0.0]
NEAR_DUP_2 = [0.98, math.sqrt(1.0 - 0.98 ** 2)]


class TestCosineSimilarity(unittest.TestCase):
    def test_identical_vectors(self):
        self.assertAlmostEqual(cb.cosine_similarity([1.0, 0.0], [1.0, 0.0]), 1.0)

    def test_orthogonal_vectors(self):
        self.assertAlmostEqual(cb.cosine_similarity([1.0, 0.0], [0.0, 1.0]), 0.0)

    def test_opposite_vectors(self):
        self.assertAlmostEqual(cb.cosine_similarity([1.0, 0.0], [-1.0, 0.0]), -1.0)

    def test_near_duplicate_pair_is_point_98(self):
        self.assertAlmostEqual(cb.cosine_similarity(NEAR_DUP_1, NEAR_DUP_2), 0.98, places=8)

    def test_dimension_mismatch_returns_none(self):
        self.assertIsNone(cb.cosine_similarity([1.0, 0.0], [1.0, 0.0, 0.0]))

    def test_zero_vector_returns_none(self):
        self.assertIsNone(cb.cosine_similarity([0.0, 0.0], [1.0, 0.0]))

    def test_empty_vector_returns_none(self):
        self.assertIsNone(cb.cosine_similarity([], []))

    def test_cosine_distance_is_complement(self):
        sim = cb.cosine_similarity(CORROBORATOR_1, CORROBORATOR_2)
        dist = cb.cosine_distance(CORROBORATOR_1, CORROBORATOR_2)
        self.assertAlmostEqual(sim + dist, 1.0)
        self.assertAlmostEqual(dist, 0.375, places=8)

    def test_cosine_distance_none_propagates(self):
        self.assertIsNone(cb.cosine_distance([1.0, 0.0], [1.0, 0.0, 0.0]))


class TestDispersionConstraint(unittest.TestCase):
    """ENC-FTR-110 AC-2: near-duplicate records must not count as
    corroborating each other."""

    def test_near_duplicates_collapse_to_one_corroborator(self):
        # Both NEAR_DUP_1 and NEAR_DUP_2 are highly similar to the candidate
        # (identical to NEAR_DUP_1, 0.98 to NEAR_DUP_2) but only 0.02 apart
        # from EACH OTHER -- well under the 0.3 dispersion floor. Only one of
        # them may count.
        candidate = list(NEAR_DUP_1)
        pool = {"DUP_A": NEAR_DUP_1, "DUP_B": NEAR_DUP_2}
        k_corr = cb.count_corroborators("CANDIDATE", candidate, pool)
        self.assertEqual(k_corr, 1)

    def test_two_corroborating_near_duplicates_alone_never_count_as_two(self):
        """Direct AC-2 phrasing check: two near-duplicate records (cosine sim
        0.98) must not BOTH count as corroborating a candidate similar to
        both of them."""
        candidate = [0.99, math.sqrt(1.0 - 0.99 ** 2)]  # similar to both dups
        pool = {"DUP_A": NEAR_DUP_1, "DUP_B": NEAR_DUP_2}
        k_corr = cb.count_corroborators("CANDIDATE", candidate, pool)
        self.assertLess(k_corr, 2)
        self.assertEqual(k_corr, 1)

    def test_genuinely_dispersed_pair_both_count(self):
        # CORROBORATOR_1/2 are both similar to B_CENTER (>=0.80) AND pairwise
        # dispersed from each other (distance 0.375 >= 0.3) -- both count.
        pool = {"C1": CORROBORATOR_1, "C2": CORROBORATOR_2}
        k_corr = cb.count_corroborators("B", B_CENTER, pool)
        self.assertEqual(k_corr, 2)

    def test_below_similarity_floor_does_not_count(self):
        pool = {"UNSUPPORTED": UNSUPPORTED}
        k_corr = cb.count_corroborators("B", B_CENTER, pool)
        self.assertEqual(k_corr, 0)

    def test_excludes_self_from_pool(self):
        pool = {"B": B_CENTER, "C1": CORROBORATOR_1}
        k_corr = cb.count_corroborators("B", B_CENTER, pool)
        # "B" must not corroborate itself even though it is keyed in the pool.
        self.assertEqual(k_corr, 1)

    def test_missing_candidate_embedding_is_zero(self):
        pool = {"C1": CORROBORATOR_1, "C2": CORROBORATOR_2}
        self.assertEqual(cb.count_corroborators("X", None, pool), 0)
        self.assertEqual(cb.count_corroborators("X", [], pool), 0)

    def test_pool_member_with_missing_embedding_skipped(self):
        pool = {"C1": CORROBORATOR_1, "GHOST": None, "EMPTY": []}
        k_corr = cb.count_corroborators("B", B_CENTER, pool)
        self.assertEqual(k_corr, 1)

    def test_deterministic_regardless_of_pool_iteration_order(self):
        pool_a = {"C1": CORROBORATOR_1, "C2": CORROBORATOR_2}
        pool_b = {"C2": CORROBORATOR_2, "C1": CORROBORATOR_1}
        self.assertEqual(
            cb.count_corroborators("B", B_CENTER, pool_a),
            cb.count_corroborators("B", B_CENTER, pool_b),
        )


class TestComputeCorroborationCounts(unittest.TestCase):
    def test_every_candidate_present_in_output(self):
        embeddings = {"A": UNSUPPORTED, "B": B_CENTER, "C1": CORROBORATOR_1, "C2": CORROBORATOR_2}
        counts = cb.compute_corroboration_counts(embeddings)
        self.assertEqual(set(counts.keys()), set(embeddings.keys()))
        self.assertEqual(counts["A"], 0)
        self.assertEqual(counts["B"], 2)

    def test_missing_embedding_yields_zero_but_is_present(self):
        embeddings = {"A": None, "B": B_CENTER, "C1": CORROBORATOR_1}
        counts = cb.compute_corroboration_counts(embeddings)
        self.assertEqual(counts["A"], 0)

    def test_empty_input(self):
        self.assertEqual(cb.compute_corroboration_counts({}), {})


class TestWeberBonusFormula(unittest.TestCase):
    """B_corr(x) = Weber_k * ln(1 + k_corr) / ln(1 + k_max)."""

    def test_best_corroborated_candidate_gets_full_weber_k(self):
        self.assertAlmostEqual(cb.weber_bonus(5, 5, weber_k=0.3), 0.3)
        self.assertAlmostEqual(cb.weber_bonus(1, 1, weber_k=0.3), 0.3)

    def test_zero_corroboration_is_zero_bonus(self):
        self.assertEqual(cb.weber_bonus(0, 5, weber_k=0.3), 0.0)

    def test_zero_k_max_never_divides_by_zero(self):
        self.assertEqual(cb.weber_bonus(0, 0, weber_k=0.3), 0.0)

    def test_monotonic_in_k_corr(self):
        # Holding k_max fixed, more corroboration never produces a lower bonus.
        prev = -1.0
        for k in range(0, 11):
            bonus = cb.weber_bonus(k, 10, weber_k=0.3)
            self.assertGreaterEqual(bonus, prev)
            prev = bonus

    def test_diminishing_returns_shape(self):
        """Weber-Fechner: 0->1 corroborator matters more than 5->6."""
        k_max = 20
        delta_0_to_1 = cb.weber_bonus(1, k_max, 0.3) - cb.weber_bonus(0, k_max, 0.3)
        delta_5_to_6 = cb.weber_bonus(6, k_max, 0.3) - cb.weber_bonus(5, k_max, 0.3)
        self.assertGreater(delta_0_to_1, delta_5_to_6)

    def test_worked_example(self):
        # k_corr=2, k_max=2 (B is the best-corroborated candidate in its
        # call) -> full Weber_k bonus, matching the AC-4 integration scenario.
        self.assertAlmostEqual(cb.weber_bonus(2, 2, weber_k=0.3), 0.3)
        # k_corr=1, k_max=2 -> partial, diminished bonus.
        partial = cb.weber_bonus(1, 2, weber_k=0.3)
        self.assertAlmostEqual(partial, 0.3 * math.log(2) / math.log(3))
        self.assertLess(partial, 0.3)
        self.assertGreater(partial, 0.0)


class TestComputeBonuses(unittest.TestCase):
    def test_shape_and_k_max_resolution(self):
        counts = {"A": 0, "B": 2, "C1": 1, "C2": 1}
        bonuses = cb.compute_bonuses(counts, weber_k=0.3)
        self.assertEqual(set(bonuses.keys()), set(counts.keys()))
        for rid, entry in bonuses.items():
            self.assertEqual(entry["schema"], cb.CORROBORATION_SCHEMA)
            self.assertEqual(entry["k_max"], 2)
            self.assertEqual(entry["k_corr"], counts[rid])
            self.assertEqual(entry["weber_k"], 0.3)
        self.assertAlmostEqual(bonuses["A"]["b_corr"], 0.0)
        self.assertAlmostEqual(bonuses["B"]["b_corr"], 0.3)

    def test_empty_counts(self):
        self.assertEqual(cb.compute_bonuses({}, weber_k=0.3), {})

    def test_defaults_weber_k_when_omitted(self):
        with mock.patch.object(cb, "load_weber_k", return_value=0.42):
            bonuses = cb.compute_bonuses({"A": 1})
        self.assertEqual(bonuses["A"]["weber_k"], 0.42)


class TestWeberKResolution(unittest.TestCase):
    """Mirrors test_energy_function_ftr104.TestLambdaWeightResolution for
    Weber_k's AppConfig -> env var -> default resolution order."""

    def test_defaults_when_unconfigured(self):
        with mock.patch.object(cb, "_appconfig_corroboration_config", return_value={}):
            with mock.patch.dict("os.environ", {}, clear=False):
                import os
                os.environ.pop("CORROBORATION_WEBER_K", None)
                weber_k = cb.load_weber_k()
        self.assertEqual(weber_k, cb.DEFAULT_WEBER_K)

    def test_env_var_overrides_default(self):
        with mock.patch.object(cb, "_appconfig_corroboration_config", return_value={}):
            with mock.patch.dict("os.environ", {"CORROBORATION_WEBER_K": "0.5"}):
                weber_k = cb.load_weber_k()
        self.assertEqual(weber_k, 0.5)

    def test_appconfig_overrides_env_var(self):
        with mock.patch.object(cb, "_appconfig_corroboration_config", return_value={"weber_k": 0.77}):
            with mock.patch.dict("os.environ", {"CORROBORATION_WEBER_K": "0.5"}):
                weber_k = cb.load_weber_k()
        self.assertEqual(weber_k, 0.77)

    def test_malformed_env_var_falls_back_to_default(self):
        with mock.patch.object(cb, "_appconfig_corroboration_config", return_value={}):
            with mock.patch.dict("os.environ", {"CORROBORATION_WEBER_K": "not-a-number"}):
                weber_k = cb.load_weber_k()
        self.assertEqual(weber_k, cb.DEFAULT_WEBER_K)

    def test_negative_weight_falls_back_to_default(self):
        with mock.patch.object(cb, "_appconfig_corroboration_config", return_value={}):
            with mock.patch.dict("os.environ", {"CORROBORATION_WEBER_K": "-1.0"}):
                weber_k = cb.load_weber_k()
        self.assertEqual(weber_k, cb.DEFAULT_WEBER_K)

    def test_appconfig_extension_unreachable_degrades_to_empty(self):
        """No localhost:2772 extension in a unit test -- must never raise."""
        cfg = cb._appconfig_corroboration_config()
        self.assertEqual(cfg, {})


class TestOgtmByConstruction(unittest.TestCase):
    """ENC-FTR-110 AC-5: pure compute + a config read. No new tracker record
    type, relational field, edge type, graph node, DDB table, or Neo4j write."""

    def test_no_aws_or_graph_imports(self):
        source = Path(cb.__file__).read_text()
        for forbidden in ("import boto3", "import neo4j", "dynamodb", "gds.", "CREATE (", "MERGE ("):
            self.assertNotIn(forbidden, source)

    def test_module_is_pure_functions_no_side_effecting_classes(self):
        import inspect
        for name in cb.__all__:
            obj = getattr(cb, name)
            if inspect.isfunction(obj):
                continue
            # Constants (floats/strings) are the only non-function exports.
            self.assertIsInstance(obj, (int, float, str))


class TestHybridCorroborationWiring(unittest.TestCase):
    """Integration: lambda_function._query_hybrid wires B_corr into
    final_score, and the AC-4 spurious-attractor hedge holds end-to-end.

    Scenario: ENC-TSK-AAA is the #1 candidate on the (only) vector signal --
    the single best, most "spurious-attractor"-shaped candidate -- but its
    embedding ([0,1,0]) has zero genuine corroborators in this result set.
    ENC-TSK-BBB ranks #2 on pure RRF, but its embedding ([1,0,0]) is
    genuinely corroborated by two dispersed (pairwise distance 0.375 >= 0.3)
    records also present in the result set. Despite AAA's strictly higher
    fused_score, BBB's corroboration bonus must push it ahead on final_score.
    """

    def setUp(self):
        self.weber_k = 0.3
        patchers = [
            mock.patch.object(lf, "_ensure_live_driver", side_effect=lambda d: d),
            mock.patch.object(lf, "_compute_query_embedding", return_value=[0.1, 0.2, 0.3]),
            mock.patch.object(
                lf, "_hybrid_vector_ranks",
                return_value=[
                    {"record_id": "ENC-TSK-AAA", "score": 0.95, "rank": 1},
                    {"record_id": "ENC-TSK-BBB", "score": 0.85, "rank": 2},
                    {"record_id": "ENC-TSK-C01", "score": 0.50, "rank": 3},
                    {"record_id": "ENC-TSK-C02", "score": 0.40, "rank": 4},
                ],
            ),
            mock.patch.object(lf, "_hybrid_keyword_ranks", return_value=[]),
            mock.patch.object(
                lf, "_fetch_nodes_by_record_ids",
                return_value={
                    "ENC-TSK-AAA": {"record_id": "ENC-TSK-AAA", "_labels": ["Task"], "embedding": UNSUPPORTED},
                    "ENC-TSK-BBB": {"record_id": "ENC-TSK-BBB", "_labels": ["Task"], "embedding": B_CENTER},
                    "ENC-TSK-C01": {"record_id": "ENC-TSK-C01", "_labels": ["Task"], "embedding": CORROBORATOR_1},
                    "ENC-TSK-C02": {"record_id": "ENC-TSK-C02", "_labels": ["Task"], "embedding": CORROBORATOR_2},
                },
            ),
            mock.patch.object(lf, "_reconstruct_pathway_edges", return_value=([], [], [])),
            mock.patch.object(cb, "load_weber_k", return_value=self.weber_k),
        ]
        self._emit_patch = mock.patch.object(lf, "_emit_pathway_telemetry")
        self.mock_emit = self._emit_patch.start()
        for p in patchers:
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(self._emit_patch.stop)

    def _run(self):
        return lf._query_hybrid(
            mock.MagicMock(), "enceladus",
            {"query": "dispersion corroboration", "top_n": 20},
        )

    def test_corroboration_counts_match_dispersion_geometry(self):
        result = self._run()
        fusion = result["per_node_fusion"]
        self.assertEqual(fusion["ENC-TSK-AAA"]["k_corr"], 0)
        self.assertEqual(fusion["ENC-TSK-BBB"]["k_corr"], 2)

    def test_fused_score_unaffected_by_corroboration(self):
        """fused_score/fused_rank must remain the pure-RRF values: AAA is
        rank 1 on the only signal, BBB is rank 2 -- AAA's fused_score must
        stay strictly higher (the "very-high-RRF, zero-corroboration"
        half of the AC-4 scenario)."""
        result = self._run()
        fusion = result["per_node_fusion"]
        self.assertGreater(fusion["ENC-TSK-AAA"]["fused_score"], fusion["ENC-TSK-BBB"]["fused_score"])
        self.assertEqual(fusion["ENC-TSK-AAA"]["fused_rank"], 1)

    def test_ac4_spurious_attractor_hedge(self):
        """The core AC-4 assertion: despite AAA's strictly higher fused_score,
        BBB's two genuine corroborators flip the final_score ordering."""
        result = self._run()
        fusion = result["per_node_fusion"]
        self.assertAlmostEqual(fusion["ENC-TSK-BBB"]["b_corr"], self.weber_k)
        self.assertEqual(fusion["ENC-TSK-AAA"]["b_corr"], 0.0)
        self.assertLess(
            fusion["ENC-TSK-AAA"]["final_score"],
            fusion["ENC-TSK-BBB"]["final_score"],
        )
        # And the presentation order (nodes / final_rank) reflects the hedge.
        self.assertEqual(fusion["ENC-TSK-BBB"]["final_rank"], 1)
        self.assertEqual(result["nodes"][0]["record_id"], "ENC-TSK-BBB")

    def test_nodes_carry_corroboration_fields(self):
        result = self._run()
        node_bbb = next(n for n in result["nodes"] if n["record_id"] == "ENC-TSK-BBB")
        self.assertEqual(node_bbb["_corroboration_count"], 2)
        self.assertAlmostEqual(node_bbb["_b_corr"], self.weber_k)
        self.assertAlmostEqual(node_bbb["_final_score"], node_bbb["_fused_score"] + self.weber_k)

    def test_corroboration_weber_k_echoed_in_response(self):
        result = self._run()
        self.assertEqual(result["corroboration_weber_k"], self.weber_k)

    def test_embedding_blob_still_stripped_from_response_nodes(self):
        result = self._run()
        for node in result["nodes"]:
            self.assertNotIn("embedding", node)

    def test_no_corroboration_is_a_no_op_when_embeddings_absent(self):
        """Backward compatibility: when no candidate carries an embedding
        (e.g. the pre-I92 mocking convention in test_energy_function_ftr104),
        final_score must equal fused_score and ordering must be unchanged."""
        with mock.patch.object(
            lf, "_fetch_nodes_by_record_ids",
            return_value={
                "ENC-TSK-AAA": {"record_id": "ENC-TSK-AAA", "_labels": ["Task"]},
                "ENC-TSK-BBB": {"record_id": "ENC-TSK-BBB", "_labels": ["Task"]},
                "ENC-TSK-C01": {"record_id": "ENC-TSK-C01", "_labels": ["Task"]},
                "ENC-TSK-C02": {"record_id": "ENC-TSK-C02", "_labels": ["Task"]},
            },
        ):
            result = self._run()
        fusion = result["per_node_fusion"]
        for rid in fusion:
            self.assertEqual(fusion[rid]["b_corr"], 0.0)
            self.assertEqual(fusion[rid]["final_score"], fusion[rid]["fused_score"])
        self.assertEqual(result["nodes"][0]["record_id"], "ENC-TSK-AAA")


if __name__ == "__main__":
    unittest.main()
