"""Tests for intent_drift (ENC-FTR-084 Phase 1, AC-3 / ENC-TSK-I93).

Covers:
  AC-3: rolling intent vector per wave = mean of FTR-089 embeddings; scalar
        intent_centroid_drift; best-effort persistence of the new nullable
        column into enceladus-drift-telemetry (no-op when table absent;
        FTR-087 d_centroid never touched).
"""

import importlib.util
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
_SPEC = importlib.util.spec_from_file_location(
    "intent_drift",
    os.path.join(os.path.dirname(__file__), "intent_drift.py"),
)
idr = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
sys.modules[_SPEC.name] = idr
_SPEC.loader.exec_module(idr)


class CentroidTests(unittest.TestCase):
    def test_mean_of_embeddings(self):
        c = idr.compute_intent_centroid([[1.0, 0.0], [0.0, 2.0], [2.0, 4.0]])
        self.assertEqual(c, [1.0, 2.0])

    def test_empty_returns_none(self):
        self.assertIsNone(idr.compute_intent_centroid([]))
        self.assertIsNone(idr.compute_intent_centroid([[], None]))

    def test_mismatched_dims_skipped(self):
        # First valid embedding sets width=2; the 3-dim entry is skipped.
        c = idr.compute_intent_centroid([[2.0, 2.0], [1.0, 2.0, 3.0], [4.0, 6.0]])
        self.assertEqual(c, [3.0, 4.0])


class DriftTests(unittest.TestCase):
    def test_none_when_previous_missing(self):
        self.assertIsNone(idr.compute_intent_centroid_drift(None, [1.0, 0.0]))
        self.assertIsNone(idr.compute_intent_centroid_drift([], [1.0, 0.0]))

    def test_identical_centroids_zero_drift(self):
        self.assertAlmostEqual(
            idr.compute_intent_centroid_drift([1.0, 2.0, 3.0], [1.0, 2.0, 3.0]), 0.0, places=6
        )

    def test_orthogonal_centroids_unit_drift(self):
        self.assertAlmostEqual(
            idr.compute_intent_centroid_drift([1.0, 0.0], [0.0, 1.0]), 1.0, places=6
        )

    def test_mismatched_dims_returns_none(self):
        self.assertIsNone(idr.compute_intent_centroid_drift([1.0, 0.0], [1.0, 0.0, 0.0]))


class _FakeDDB:
    def __init__(self, raises=None):
        self.calls = []
        self._raises = raises

    def update_item(self, **kwargs):
        self.calls.append(kwargs)
        if self._raises:
            raise self._raises
        return {"Attributes": {}}


class PersistTests(unittest.TestCase):
    def test_noop_when_table_not_configured(self):
        out = idr.persist_intent_centroid_drift(
            "WAVE-1", 0.25, now_iso="2026-06-28T00:00:00Z", table_name="", ddb=_FakeDDB()
        )
        self.assertFalse(out["persisted"])
        self.assertEqual(out["reason"], "drift_telemetry_table_not_configured")

    def test_noop_when_wave_id_missing(self):
        out = idr.persist_intent_centroid_drift(
            "", 0.25, now_iso="2026-06-28T00:00:00Z", table_name="t", ddb=_FakeDDB()
        )
        self.assertFalse(out["persisted"])
        self.assertEqual(out["reason"], "missing_wave_id")

    def test_writes_only_new_column_with_numeric_value(self):
        ddb = _FakeDDB()
        out = idr.persist_intent_centroid_drift(
            "WAVE-7", 0.5, now_iso="2026-06-28T00:00:00Z",
            table_name="enceladus-drift-telemetry-gamma", ddb=ddb,
        )
        self.assertTrue(out["persisted"])
        self.assertEqual(len(ddb.calls), 1)
        call = ddb.calls[0]
        # Only the new column + its timestamp are written; FTR-087 fields untouched.
        self.assertIn("intent_centroid_drift", call["ExpressionAttributeNames"].values())
        self.assertEqual(call["ExpressionAttributeValues"][":d"], {"N": repr(0.5)})
        self.assertEqual(call["Key"], {"wave_id": {"S": "WAVE-7"}})
        self.assertNotIn("d_centroid", str(call["UpdateExpression"]))

    def test_null_value_when_drift_none(self):
        ddb = _FakeDDB()
        out = idr.persist_intent_centroid_drift(
            "WAVE-8", None, now_iso="2026-06-28T00:00:00Z", table_name="t", ddb=ddb,
        )
        self.assertTrue(out["persisted"])
        self.assertEqual(ddb.calls[0]["ExpressionAttributeValues"][":d"], {"NULL": True})

    def test_persist_failure_is_best_effort(self):
        ddb = _FakeDDB(raises=RuntimeError("ResourceNotFoundException"))
        out = idr.persist_intent_centroid_drift(
            "WAVE-9", 0.1, now_iso="2026-06-28T00:00:00Z", table_name="missing", ddb=ddb,
        )
        self.assertFalse(out["persisted"])
        self.assertEqual(out["reason"], "persist_failed")


if __name__ == "__main__":
    unittest.main()
