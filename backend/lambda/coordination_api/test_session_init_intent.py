"""Handler/route tests for the session-init intent classifier (ENC-TSK-I93).

Exercises the coordination_api HTTP handlers end-to-end (request validation,
override passthrough, drift persistence wiring) with the classifier/drift
modules stubbed so no AWS/network is touched.
"""

import importlib.util
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared_layer", "python"))

_SPEC = importlib.util.spec_from_file_location(
    "coordination_lambda",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
cl = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
sys.modules[_SPEC.name] = cl
_SPEC.loader.exec_module(cl)


def _event(body):
    return {"body": json.dumps(body), "headers": {}, "requestContext": {}}


class ClassifyIntentHandlerTests(unittest.TestCase):
    def test_missing_text_returns_400(self):
        resp = cl._handle_session_init_classify_intent(_event({"session_metadata": {}}), {})
        self.assertEqual(resp["statusCode"], 400)

    def test_bad_session_metadata_returns_400(self):
        resp = cl._handle_session_init_classify_intent(
            _event({"first_turn_text": "hi", "session_metadata": "nope"}), {}
        )
        self.assertEqual(resp["statusCode"], 400)

    def test_happy_path_passes_through_and_returns_200(self):
        fake = {
            "predicted_entelechy": {"node_ids": ["ENC-TSK-A"], "confidence": 0.9},
            "applied_entelechy": {"node_ids": ["ENC-TSK-A"], "confidence": 0.9, "source": "classifier"},
            "override_applied": False,
            "neighbors": [{"record_id": "ENC-TSK-A", "score": 0.9}],
            "query_embedding_dim": 256,
            "model_id": "amazon.titan-embed-text-v2:0",
            "inference_only": True,
        }
        with mock.patch.object(
            cl._intent_classifier, "classify_session_intent", return_value=fake
        ) as m:
            resp = cl._handle_session_init_classify_intent(
                _event(
                    {
                        "first_turn_text": "work on the alpha migration",
                        "session_metadata": {"surface": "cursor-cloud-agent"},
                        "applied_entelechy_override": ["ENC-TSK-Z"],
                        "top_k": 4,
                        "project_id": "enceladus",
                    }
                ),
                {},
            )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertTrue(body["success"])
        self.assertEqual(body["predicted_entelechy"]["node_ids"], ["ENC-TSK-A"])
        # Handler forwards override + top_k + project_id to the classifier.
        _, kwargs = m.call_args
        self.assertEqual(kwargs["applied_entelechy_override"], ["ENC-TSK-Z"])
        self.assertEqual(kwargs["top_k"], 4)
        self.assertEqual(kwargs["project_id"], "enceladus")


class IntentDriftHandlerTests(unittest.TestCase):
    def test_missing_wave_id_returns_400(self):
        resp = cl._handle_session_init_intent_drift(_event({"embeddings": [[1.0, 0.0]]}), {})
        self.assertEqual(resp["statusCode"], 400)

    def test_computes_drift_and_persists(self):
        captured = {}

        def _fake_persist(wave_id, drift, *, now_iso, table_name=None, ddb=None):
            captured["wave_id"] = wave_id
            captured["drift"] = drift
            return {"persisted": True, "table": "t", "wave_id": wave_id, "intent_centroid_drift": drift}

        with mock.patch.object(cl._intent_drift, "persist_intent_centroid_drift", _fake_persist), \
             mock.patch.object(cl, "_get_ddb", return_value=object()):
            resp = cl._handle_session_init_intent_drift(
                _event(
                    {
                        "wave_id": "WAVE-42",
                        "embeddings": [[1.0, 0.0], [1.0, 0.0]],
                        "previous_centroid": [0.0, 1.0],
                        "persist": True,
                    }
                ),
                {},
            )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["wave_id"], "WAVE-42")
        self.assertEqual(body["record_count"], 2)
        # current centroid [1,0] vs previous [0,1] => cosine 0 => drift 1.0
        self.assertAlmostEqual(body["intent_centroid_drift"], 1.0, places=6)
        self.assertTrue(body["persistence"]["persisted"])
        self.assertEqual(captured["wave_id"], "WAVE-42")

    def test_persist_disabled_skips_write(self):
        with mock.patch.object(cl._intent_drift, "persist_intent_centroid_drift") as m:
            resp = cl._handle_session_init_intent_drift(
                _event({"wave_id": "WAVE-1", "embeddings": [[1.0, 0.0]], "persist": False}), {}
            )
        self.assertEqual(resp["statusCode"], 200)
        m.assert_not_called()
        body = json.loads(resp["body"])
        # First wave (no previous centroid) => nullable drift.
        self.assertIsNone(body["intent_centroid_drift"])
        self.assertFalse(body["persistence"]["persisted"])


if __name__ == "__main__":
    unittest.main()
