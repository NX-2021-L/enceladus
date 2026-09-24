"""Tests for intent_training (FTR-084 Ph2 / ENC-TSK-K02)."""

from __future__ import annotations

import importlib.util
import json
import os
import unittest
from unittest import mock

_IT_PATH = os.path.join(os.path.dirname(__file__), "intent_training.py")
_IC_PATH = os.path.join(os.path.dirname(__file__), "intent_classifier.py")

_it = importlib.util.spec_from_file_location("intent_training", _IT_PATH)
intent_training = importlib.util.module_from_spec(_it)  # type: ignore[arg-type]
_it.loader.exec_module(intent_training)  # type: ignore[union-attr]

_ic = importlib.util.spec_from_file_location("intent_classifier", _IC_PATH)
ic = importlib.util.module_from_spec(_ic)  # type: ignore[arg-type]
_ic.loader.exec_module(ic)  # type: ignore[union-attr]

_CORPUS = [
    {"record_id": "ENC-TSK-A", "embedding": [1.0, 0.0, 0.0, 0.0]},
    {"record_id": "ENC-TSK-B", "embedding": [0.0, 1.0, 0.0, 0.0]},
    {"record_id": "ENC-TSK-C", "embedding": [0.0, 0.0, 1.0, 0.0]},
]


def _rank_fn_factory():
    def _rank(row):
        emb = row.get("embedding")
        if not isinstance(emb, list):
            return []
        neighbors = ic.rank_neighbors(emb, _CORPUS, top_k=3)
        boosted = intent_training.apply_record_boosts_to_neighbors(
            [{"record_id": n["record_id"], "score": n["score"]} for n in neighbors],
            row.get("record_boosts") or {},
        )
        return [n["record_id"] for n in boosted]

    return _rank


class KillSwitchTests(unittest.TestCase):
    def test_training_hard_disabled_helper(self):
        with mock.patch.object(intent_training, "TRAINING_HARD_DISABLED", True):
            self.assertTrue(intent_training.is_training_hard_disabled())
        with mock.patch.object(intent_training, "TRAINING_HARD_DISABLED", False):
            self.assertFalse(intent_training.is_training_hard_disabled())

    def test_run_training_cycle_respects_kill_switch(self):
        store: dict[str, str] = {}

        def _get(key):
            return store[key]

        def _put(key, body):
            store[key] = body

        with mock.patch.object(intent_training, "TRAINING_HARD_DISABLED", True):
            out = intent_training.run_training_cycle(
                get_object=_get, put_object=_put, rank_fn=_rank_fn_factory()
            )
        self.assertFalse(out["enabled"])
        self.assertEqual(out["reason"], "TRAINING_HARD_DISABLED")


class TrainingLoopTests(unittest.TestCase):
    def setUp(self):
        self.labels = [
            {
                "first_turn_text": "alpha",
                "label_node_ids": ["ENC-TSK-A"],
                "embedding": [1.0, 0.0, 0.0, 0.0],
            },
            {
                "first_turn_text": "beta",
                "label_node_ids": ["ENC-TSK-B"],
                "embedding": [0.0, 1.0, 0.0, 0.0],
            },
            {
                "first_turn_text": "gamma",
                "label_node_ids": ["ENC-TSK-C"],
                "embedding": [0.0, 0.0, 1.0, 0.0],
            },
            {
                "first_turn_text": "alpha2",
                "label_node_ids": ["ENC-TSK-A"],
                "embedding": [0.99, 0.01, 0.0, 0.0],
            },
            {
                "first_turn_text": "beta2",
                "label_node_ids": ["ENC-TSK-B"],
                "embedding": [0.01, 0.99, 0.0, 0.0],
            },
        ]

    def test_train_improves_boosts(self):
        with mock.patch.object(intent_training, "TRAINING_HARD_DISABLED", False):
            result = intent_training.train_record_boosts(
                self.labels,
                {},
                rank_fn=_rank_fn_factory(),
                seed=1,
            )
        self.assertTrue(result["trained"])
        self.assertIn("ENC-TSK-A", result["record_boosts"])
        self.assertGreater(result["record_boosts"]["ENC-TSK-A"], 1.0)

    def test_versioned_snapshot_retains_previous(self):
        snap = intent_training.build_weight_snapshot(
            {"ENC-TSK-A": 1.1},
            previous_version_id="20260101T000000Z",
            accuracy_holdout=0.9,
        )
        self.assertEqual(snap["previous_version_id"], "20260101T000000Z")
        self.assertIn("version_id", snap)

    def test_rollback_repoints_active_pointer(self):
        store = {
            intent_training._prefix_key("weights/active.json"): json.dumps({"version_id": "v2"}),
            intent_training._prefix_key("weights/versions/v2.json"): json.dumps(
                {
                    "version_id": "v2",
                    "previous_version_id": "v1",
                    "record_boosts": {"ENC-TSK-A": 1.2},
                    "training_disabled": False,
                }
            ),
            intent_training._prefix_key("weights/versions/v1.json"): json.dumps(
                {
                    "version_id": "v1",
                    "record_boosts": {"ENC-TSK-A": 1.0},
                    "training_disabled": False,
                }
            ),
        }

        def _get(key):
            return store[key]

        def _put(key, body):
            store[key] = body

        out = intent_training.run_rollback(get_object=_get, put_object=_put)
        self.assertTrue(out["rolled_back"])
        self.assertEqual(out["version_id"], "v1")
        pointer = json.loads(store[intent_training._prefix_key("weights/active.json")])
        self.assertEqual(pointer["version_id"], "v1")


class DegradationKillSwitchTests(unittest.TestCase):
    def test_holdout_degradation_disables_training(self):
        labels = [
            {
                "label_node_ids": ["ENC-TSK-A"],
                "embedding": [1.0, 0.0, 0.0, 0.0],
            }
            for _ in range(10)
        ]

        with mock.patch.object(intent_training, "TRAINING_HARD_DISABLED", False):
            with mock.patch.object(
                intent_training,
                "measure_top1_accuracy",
                side_effect=[0.8, 0.5],
            ):
                result = intent_training.train_record_boosts(
                    labels,
                    {},
                    rank_fn=_rank_fn_factory(),
                    seed=0,
                )
        self.assertFalse(result["trained"])
        self.assertTrue(result["training_disabled"])


class OverrideRegressionTests(unittest.TestCase):
    """AC: applied_entelechy_override still wins when trained boosts are active."""

    def test_override_wins_with_record_boosts(self):
        def _embed(_text):
            return [1.0, 0.0, 0.0, 0.0]

        provider = ic.make_corpus_neighbor_provider(_CORPUS)
        boosts = {"ENC-TSK-B": 5.0}  # would flip ranking without override

        result = ic.classify_session_intent(
            "alpha work",
            {},
            applied_entelechy_override=["ENC-TSK-OVERRIDE"],
            embed_fn=_embed,
            neighbor_provider=provider,
            record_boosts=boosts,
            load_trained_boosts=False,
        )
        self.assertTrue(result["override_applied"])
        self.assertEqual(result["applied_entelechy"]["node_ids"], ["ENC-TSK-OVERRIDE"])
        self.assertEqual(result["applied_entelechy"]["source"], "io_override")
        self.assertNotEqual(
            result["predicted_entelechy"]["node_ids"],
            result["applied_entelechy"]["node_ids"],
        )


class CostPreflightTests(unittest.TestCase):
    def test_cost_preflight_documented(self):
        self.assertLess(intent_training.COST_PREFLIGHT_MONTHLY_USD, 1.0)
        self.assertIn("COST-PREFLIGHT", intent_training.__doc__ or "")


if __name__ == "__main__":
    unittest.main()
