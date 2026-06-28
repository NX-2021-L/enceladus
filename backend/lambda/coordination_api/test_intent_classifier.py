"""Tests for intent_classifier (ENC-FTR-084 Phase 1 / ENC-TSK-I93).

Covers:
  AC-1: classifier returns predicted_entelechy {node_ids: list[str], confidence: float}
        via Titan V2 nearest-neighbor inference — verified with 3 synthetic
        session-init payloads.
  AC-2: applied_entelechy_override wins; the classifier prediction is still
        computed and logged.
  AC-5: scope guard — module is inference-only (no training / weight-write path).

Pure-function tests: no AWS, no network (providers + embeddings injected).
"""

import importlib.util
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
_SPEC = importlib.util.spec_from_file_location(
    "intent_classifier",
    os.path.join(os.path.dirname(__file__), "intent_classifier.py"),
)
ic = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
sys.modules[_SPEC.name] = ic
_SPEC.loader.exec_module(ic)


# A tiny synthetic 4-dim corpus with clearly separable directions so cosine
# nearest-neighbor is deterministic. Titan V2 produces normalized 256-dim
# vectors in production; the math is dimension-agnostic.
_CORPUS = [
    {"record_id": "ENC-TSK-A", "embedding": [1.0, 0.0, 0.0, 0.0]},
    {"record_id": "ENC-TSK-B", "embedding": [0.0, 1.0, 0.0, 0.0]},
    {"record_id": "ENC-TSK-C", "embedding": [0.0, 0.0, 1.0, 0.0]},
    {"record_id": "ENC-DOC-D", "embedding": [0.0, 0.0, 0.0, 1.0]},
]


class CosineTests(unittest.TestCase):
    def test_identical_vectors_similarity_one(self):
        self.assertAlmostEqual(ic.cosine_similarity([1.0, 2.0, 3.0], [1.0, 2.0, 3.0]), 1.0, places=6)

    def test_orthogonal_vectors_similarity_zero(self):
        self.assertAlmostEqual(ic.cosine_similarity([1.0, 0.0], [0.0, 1.0]), 0.0, places=6)

    def test_degenerate_inputs(self):
        self.assertEqual(ic.cosine_similarity([], [1.0]), 0.0)
        self.assertEqual(ic.cosine_similarity([0.0, 0.0], [0.0, 0.0]), 0.0)
        self.assertEqual(ic.cosine_similarity([1.0, 2.0], [1.0]), 0.0)


class RankNeighborsTests(unittest.TestCase):
    def test_ranks_by_similarity_descending(self):
        q = [0.9, 0.1, 0.0, 0.0]  # closest to ENC-TSK-A
        ranked = ic.rank_neighbors(q, _CORPUS, top_k=4)
        self.assertEqual(ranked[0]["record_id"], "ENC-TSK-A")
        sims = [r["similarity"] for r in ranked]
        self.assertEqual(sims, sorted(sims, reverse=True))
        # calibrated score in [0, 1]
        for r in ranked:
            self.assertGreaterEqual(r["score"], 0.0)
            self.assertLessEqual(r["score"], 1.0)

    def test_top_k_limits_results(self):
        ranked = ic.rank_neighbors([1.0, 0.0, 0.0, 0.0], _CORPUS, top_k=2)
        self.assertEqual(len(ranked), 2)

    def test_empty_query_returns_empty(self):
        self.assertEqual(ic.rank_neighbors([], _CORPUS, top_k=3), [])


class ClassifyAC1Tests(unittest.TestCase):
    """AC-1: predicted_entelechy shape + 3 synthetic session-init payloads."""

    def _embed(self, text):
        # Deterministic synthetic embedding keyed on the dominant token so each
        # payload resolves to a distinct nearest neighbor.
        mapping = {
            "alpha": [1.0, 0.0, 0.0, 0.0],
            "beta": [0.0, 1.0, 0.0, 0.0],
            "gamma": [0.0, 0.0, 1.0, 0.0],
        }
        for token, vec in mapping.items():
            if token in text.lower():
                return vec
        return [0.0, 0.0, 0.0, 1.0]

    def _provider(self):
        return ic.make_corpus_neighbor_provider(_CORPUS)

    def test_predicted_entelechy_shape(self):
        result = ic.classify_session_intent(
            "please work on the alpha refactor",
            {"surface": "cursor-cloud-agent"},
            embed_fn=self._embed,
            neighbor_provider=self._provider(),
            top_k=3,
        )
        pe = result["predicted_entelechy"]
        self.assertIn("node_ids", pe)
        self.assertIn("confidence", pe)
        self.assertIsInstance(pe["node_ids"], list)
        self.assertTrue(all(isinstance(x, str) for x in pe["node_ids"]))
        self.assertIsInstance(pe["confidence"], float)
        self.assertGreaterEqual(pe["confidence"], 0.0)
        self.assertLessEqual(pe["confidence"], 1.0)
        self.assertEqual(pe["node_ids"][0], "ENC-TSK-A")
        self.assertEqual(result["model_id"], ic.TITAN_MODEL_ID)
        self.assertTrue(result["inference_only"])

    def test_three_synthetic_session_init_payloads(self):
        payloads = [
            ("kick off the alpha migration", "ENC-TSK-A"),
            ("investigate the beta regression", "ENC-TSK-B"),
            ("document the gamma rollout", "ENC-TSK-C"),
        ]
        for text, expected_top in payloads:
            with self.subTest(text=text):
                result = ic.classify_session_intent(
                    text,
                    {"surface": "claude.ai-webui"},
                    embed_fn=self._embed,
                    neighbor_provider=self._provider(),
                    top_k=2,
                )
                pe = result["predicted_entelechy"]
                self.assertEqual(pe["node_ids"][0], expected_top)
                self.assertGreater(pe["confidence"], 0.5)
                self.assertFalse(result["override_applied"])

    def test_missing_text_yields_empty_prediction(self):
        result = ic.classify_session_intent(
            "",
            {},
            embed_fn=self._embed,
            neighbor_provider=self._provider(),
        )
        self.assertEqual(result["predicted_entelechy"]["node_ids"], [])
        self.assertEqual(result["predicted_entelechy"]["confidence"], 0.0)


class OverrideAC2Tests(unittest.TestCase):
    """AC-2: io override wins; classifier prediction still computed + logged."""

    def _embed(self, text):
        return [1.0, 0.0, 0.0, 0.0]  # always nearest to ENC-TSK-A

    def _provider(self):
        return ic.make_corpus_neighbor_provider(_CORPUS)

    def test_override_wins_over_prediction(self):
        result = ic.classify_session_intent(
            "alpha work",
            {},
            applied_entelechy_override=["ENC-TSK-OVERRIDE-1", "ENC-TSK-OVERRIDE-2"],
            embed_fn=self._embed,
            neighbor_provider=self._provider(),
        )
        # Applied value is the io override.
        self.assertTrue(result["override_applied"])
        self.assertEqual(
            result["applied_entelechy"]["node_ids"],
            ["ENC-TSK-OVERRIDE-1", "ENC-TSK-OVERRIDE-2"],
        )
        self.assertEqual(result["applied_entelechy"]["source"], "io_override")
        # The classifier prediction is STILL computed (logged), and differs.
        self.assertEqual(result["predicted_entelechy"]["node_ids"][0], "ENC-TSK-A")
        self.assertNotEqual(
            result["applied_entelechy"]["node_ids"],
            result["predicted_entelechy"]["node_ids"],
        )

    def test_override_accepts_dict_and_string_forms(self):
        as_dict = ic.classify_session_intent(
            "alpha", {}, applied_entelechy_override={"node_ids": ["X-1"]},
            embed_fn=self._embed, neighbor_provider=self._provider(),
        )
        self.assertEqual(as_dict["applied_entelechy"]["node_ids"], ["X-1"])

        as_str = ic.classify_session_intent(
            "alpha", {}, applied_entelechy_override="X-9",
            embed_fn=self._embed, neighbor_provider=self._provider(),
        )
        self.assertEqual(as_str["applied_entelechy"]["node_ids"], ["X-9"])

    def test_empty_override_falls_back_to_classifier(self):
        for empty in ([], "", {}, {"node_ids": []}, None):
            with self.subTest(empty=empty):
                result = ic.classify_session_intent(
                    "alpha", {}, applied_entelechy_override=empty,
                    embed_fn=self._embed, neighbor_provider=self._provider(),
                )
                self.assertFalse(result["override_applied"])
                self.assertEqual(result["applied_entelechy"]["source"], "classifier")
                self.assertEqual(
                    result["applied_entelechy"]["node_ids"],
                    result["predicted_entelechy"]["node_ids"],
                )

    def test_normalize_override_helper(self):
        self.assertIsNone(ic.normalize_override(None))
        self.assertIsNone(ic.normalize_override([]))
        self.assertIsNone(ic.normalize_override("  "))
        self.assertEqual(ic.normalize_override("ENC-TSK-1"), ["ENC-TSK-1"])
        self.assertEqual(ic.normalize_override(["a", " b ", ""]), ["a", "b"])
        self.assertEqual(ic.normalize_override({"node_ids": ["z"]}), ["z"])


class ScopeGuardAC5Tests(unittest.TestCase):
    """AC-5: the classifier is inference-only — no training / weight writes."""

    def test_inference_only_markers(self):
        self.assertTrue(ic.INFERENCE_ONLY)
        self.assertFalse(ic.TRAINING_ENABLED)

    def test_no_training_or_weight_write_callables(self):
        # Inspect callable (function) symbols only; the TRAINING_ENABLED marker
        # constant is intentionally present (and asserted False above).
        forbidden = ("train", "fit", "backprop", "gradient", "save_weight", "update_weight")
        callables = [
            n.lower()
            for n in dir(ic)
            if callable(getattr(ic, n)) and not n.startswith("__")
        ]
        for bad in forbidden:
            self.assertFalse(
                any(bad in n for n in callables),
                msg=f"intent_classifier must not expose a '{bad}' callable (inference-only)",
            )

    def test_classify_performs_no_aws_calls(self):
        # With injected providers the classifier must not touch boto3 at all.
        sentinel = {"called": False}

        def _embed(_text):
            return [1.0, 0.0, 0.0, 0.0]

        def _provider(_t, _e, _k, _p):
            return [{"record_id": "ENC-TSK-A", "score": 0.9}]

        orig = ic._get_bedrock_runtime

        def _boom():
            sentinel["called"] = True
            raise AssertionError("bedrock must not be invoked when providers are injected")

        ic._get_bedrock_runtime = _boom
        try:
            result = ic.classify_session_intent(
                "alpha", {}, embed_fn=_embed, neighbor_provider=_provider
            )
        finally:
            ic._get_bedrock_runtime = orig
        self.assertFalse(sentinel["called"])
        self.assertEqual(result["predicted_entelechy"]["node_ids"], ["ENC-TSK-A"])


class HybridProviderDegradationTests(unittest.TestCase):
    def test_unset_url_returns_no_neighbors(self):
        orig = ic.GRAPH_QUERY_API_URL
        ic.GRAPH_QUERY_API_URL = ""
        try:
            self.assertEqual(
                ic.graph_query_hybrid_provider("alpha", [1.0, 0.0], 5, "enceladus"), []
            )
        finally:
            ic.GRAPH_QUERY_API_URL = orig


if __name__ == "__main__":
    unittest.main()
