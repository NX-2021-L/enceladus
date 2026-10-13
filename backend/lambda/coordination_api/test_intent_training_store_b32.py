"""DVP-TSK-B32 (isolation W4j): intent-training/ goes through content_store in coordination_api (no AWS).

Writes go dual into the PER-ENVIRONMENT content bucket (key without the legacy-only gamma/ prefix) and
INTENT_TRAINING_BUCKET; reads (labels, active pointer, versions, inference boosts) stay on INTENT_TRAINING_BUCKET while
CONTENT_STORE_READ=legacy. coordination_api is already dual for governance/ (B22), so an unset CONTENT_BUCKET must
mean legacy, not a config error. The governance store keeps its own GOVERNANCE_CONTENT_BUCKET.
"""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import re
import sys
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "shared_layer" / "python"))
sys.path.insert(0, str(HERE))

_spec = importlib.util.spec_from_file_location("coordination_lambda_b32", HERE / "lambda_function.py")
coordination_lambda = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
sys.modules[_spec.name] = coordination_lambda
_spec.loader.exec_module(coordination_lambda)

from test_governance_store_b22 import FakeS3  # noqa: E402

it = coordination_lambda._intent_training
LEGACY = "jreese-net"
GAMMA_CONTENT = "enceladus-content-gamma-356364570033-us-west-2"
PROD_CONTENT = "enceladus-content-356364570033-us-west-2"
ENV_GAMMA_DUAL = {
    "CONTENT_STORE_MODE": "dual",
    "CONTENT_STORE_READ": "legacy",
    "GOVERNANCE_CONTENT_BUCKET": PROD_CONTENT,
    "CONTENT_BUCKET": GAMMA_CONTENT,
    "S3_ENV_PREFIX": "gamma/",
}
POINTER = "gamma/intent-training/weights/active.json"


class _Base(unittest.TestCase):
    env = ENV_GAMMA_DUAL

    def setUp(self):
        self.s3 = FakeS3()
        clean = {k: v for k, v in os.environ.items()
                 if k not in ("CONTENT_STORE_MODE", "CONTENT_STORE_READ", "GOVERNANCE_CONTENT_BUCKET",
                              "CONTENT_BUCKET", "S3_ENV_PREFIX")}
        clean.update(self.env)
        patches = [
            mock.patch.dict(os.environ, clean, clear=True),
            mock.patch.object(coordination_lambda, "_get_s3", return_value=self.s3),
            mock.patch.object(it, "_s3_client", return_value=self.s3),
            mock.patch.object(it, "INTENT_TRAINING_BUCKET", LEGACY),
            mock.patch.object(it, "INTENT_TRAINING_PREFIX", "gamma/intent-training"),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        for attr in ("_STORE", "_STORE_KEY"):
            setattr(it, attr, None)
            self.addCleanup(setattr, it, attr, None)
        coordination_lambda._GOVERNANCE_STORE = None
        self.addCleanup(setattr, coordination_lambda, "_GOVERNANCE_STORE", None)


class WriterFirstTests(_Base):
    def test_put_writes_gamma_content_unprefixed_then_legacy_prefixed(self):
        coordination_lambda._intent_training_s3_put(POINTER, '{"version_id":"v1"}')
        self.assertEqual(self.s3.touched("put"), [
            (GAMMA_CONTENT, "intent-training/weights/active.json"),
            (LEGACY, POINTER),
        ])
        for call in self.s3.calls:
            self.assertEqual(call[3], {"ContentType": "application/json"})
        self.assertEqual(self.s3.objects[(GAMMA_CONTENT, "intent-training/weights/active.json")],
                         self.s3.objects[(LEGACY, POINTER)])

    def test_get_is_legacy_pinned(self):
        self.s3.objects[(LEGACY, POINTER)] = b'{"version_id": "legacy"}'
        self.s3.objects[(GAMMA_CONTENT, "intent-training/weights/active.json")] = b'{"version_id": "content"}'
        self.assertEqual(json.loads(coordination_lambda._intent_training_s3_get(POINTER))["version_id"], "legacy")
        self.assertEqual(self.s3.touched("get"), [(LEGACY, POINTER)])

    def test_training_cycle_persists_snapshot_and_pointer_in_both_buckets(self):
        snap = {"version_id": "v2", "created_at": "2026-10-13T00:00:00Z", "record_boosts": {"R1": 1.2}}
        it.persist_weight_snapshot(snap, coordination_lambda._intent_training_s3_put)
        puts = self.s3.touched("put")
        self.assertIn((GAMMA_CONTENT, "intent-training/weights/versions/v2.json"), puts)
        self.assertIn((LEGACY, "gamma/intent-training/weights/versions/v2.json"), puts)
        self.assertIn((GAMMA_CONTENT, "intent-training/weights/active.json"), puts)
        self.assertIn((LEGACY, POINTER), puts)

    def test_inference_boosts_default_getter_reads_legacy_through_the_store(self):
        self.s3.objects[(LEGACY, POINTER)] = b'{"version_id": "v1"}'
        self.s3.objects[(LEGACY, "gamma/intent-training/weights/versions/v1.json")] = b'{"record_boosts": {"R1": 1.5}}'
        with mock.patch.object(it, "TRAINING_HARD_DISABLED", False):
            self.assertEqual(it.load_inference_record_boosts(), {"R1": 1.5})
        self.assertEqual({b for b, _ in self.s3.touched("get")}, {LEGACY})

    def test_governance_store_is_unaffected_by_the_per_environment_content_bucket(self):
        store = coordination_lambda._governance_store(self.s3)
        self.assertEqual(store.content_bucket, PROD_CONTENT)
        self.assertEqual(store.legacy_key_prefix, "")
        self.assertEqual(it.content_store(self.s3).content_bucket, GAMMA_CONTENT)


class NoContentBucketTests(_Base):
    env = {"CONTENT_STORE_MODE": "dual", "CONTENT_STORE_READ": "legacy", "GOVERNANCE_CONTENT_BUCKET": PROD_CONTENT}

    def test_dual_without_content_bucket_stays_legacy_and_does_not_raise(self):
        coordination_lambda._intent_training_s3_put(POINTER, "{}")
        self.assertEqual(self.s3.touched("put"), [(LEGACY, POINTER)])


class ReadFlipTests(_Base):
    env = {k: v for k, v in ENV_GAMMA_DUAL.items() if k != "CONTENT_STORE_READ"}

    def test_after_the_flip_reads_are_content_first_with_a_legacy_fallback(self):
        self.s3.objects[(GAMMA_CONTENT, "intent-training/weights/active.json")] = b'{"version_id": "content"}'
        self.assertEqual(json.loads(coordination_lambda._intent_training_s3_get(POINTER))["version_id"], "content")
        self.assertEqual(self.s3.touched("get"), [(GAMMA_CONTENT, "intent-training/weights/active.json")])
        self.s3.calls.clear()
        self.s3.objects[(LEGACY, "gamma/intent-training/labels/session_outcomes.jsonl")] = b"{}\n"
        coordination_lambda._intent_training_s3_get("gamma/intent-training/labels/session_outcomes.jsonl")
        self.assertEqual(self.s3.touched("get"), [
            (GAMMA_CONTENT, "intent-training/labels/session_outcomes.jsonl"),
            (LEGACY, "gamma/intent-training/labels/session_outcomes.jsonl"),
        ])


class CloudFormationTests(unittest.TestCase):
    def test_coordination_api_env_adds_the_per_environment_content_bucket(self):
        text = (HERE.parents[2] / "infrastructure" / "cloudformation" / "02-compute.yaml").read_text(encoding="utf-8")
        m = re.search(r"(?ms)^  CoordinationApiFunction:\n(.*?)(?=^  [A-Za-z0-9]+:\n)", text)
        self.assertIsNotNone(m)
        fn = m.group(1)
        self.assertIn("CONTENT_STORE_MODE: dual", fn)
        self.assertIn("CONTENT_STORE_READ: legacy", fn)
        self.assertIn('GOVERNANCE_CONTENT_BUCKET: !Sub "enceladus-content-${AWS::AccountId}-${AWS::Region}"', fn)
        self.assertIn('CONTENT_BUCKET: !Sub "enceladus-content${EnvironmentSuffix}-${AWS::AccountId}-${AWS::Region}"', fn)
        self.assertIn("S3_ENV_PREFIX: !Ref S3EnvPrefix", fn)


if __name__ == "__main__":
    unittest.main()
