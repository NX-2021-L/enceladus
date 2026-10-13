"""DVP-TSK-B22 (isolation W4h): governance_update writes governance/ dual into the SHARED prod content bucket (no AWS).

governance/ is ONE shared corpus held only in the PROD content bucket on BOTH planes (io, DOC-EF4BC758CCC9,
2026-10-13). The store takes GOVERNANCE_CONTENT_BUCKET and unprefixed keys, never CONTENT_BUCKET / S3_ENV_PREFIX.
Reads stay legacy (CONTENT_STORE_READ=legacy).
"""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import sys
import unittest
from unittest import mock

from botocore.exceptions import ClientError

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "shared_layer" / "python"))

_spec = importlib.util.spec_from_file_location("coordination_lambda_b22", HERE / "lambda_function.py")
coordination_lambda = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
sys.modules[_spec.name] = coordination_lambda
_spec.loader.exec_module(coordination_lambda)

LEGACY = coordination_lambda.S3_BUCKET
PROD_CONTENT = "enceladus-content-356364570033-us-west-2"
GAMMA_CONTENT = "enceladus-content-gamma-356364570033-us-west-2"
HASH = "a" * 64
ENV_DUAL = {
    "CONTENT_STORE_MODE": "dual",
    "CONTENT_STORE_READ": "legacy",
    "GOVERNANCE_CONTENT_BUCKET": PROD_CONTENT,
}


class _NoSuchKey(ClientError):
    """Like boto3's modeled s3.exceptions.NoSuchKey: a ClientError subclass named NoSuchKey, code NoSuchKey."""

    def __init__(self):
        super().__init__({"Error": {"Code": "NoSuchKey", "Message": "missing"}}, "GetObject")


_NoSuchKey.__name__ = "NoSuchKey"


class _Body:
    def __init__(self, data):
        self._d = data

    def read(self):
        return self._d


class FakeS3:
    class exceptions:
        NoSuchKey = _NoSuchKey

    def __init__(self):
        self.objects = {}
        self.calls = []

    def put_object(self, Bucket, Key, Body, **kw):
        self.calls.append(("put", Bucket, Key, kw))
        self.objects[(Bucket, Key)] = Body
        return {"Bucket": Bucket}

    def get_object(self, Bucket, Key, **kw):
        self.calls.append(("get", Bucket, Key, kw))
        if (Bucket, Key) not in self.objects:
            raise _NoSuchKey()
        return {"Body": _Body(self.objects[(Bucket, Key)])}

    def touched(self, op):
        return [(c[1], c[2]) for c in self.calls if c[0] == op]


def _event(file_name="agents.md", content="# agents v2\n"):
    return {
        "rawPath": f"/api/v1/governance/{file_name}",
        "body": json.dumps({
            "file_name": file_name,
            "content": content,
            "change_summary": "b22 test",
            "governance_hash": HASH,
        }),
    }


class _Base(unittest.TestCase):
    env = ENV_DUAL

    def setUp(self):
        self.s3 = FakeS3()
        # Isolate from whatever the host environment carries.
        clean = {k: v for k, v in os.environ.items()
                 if k not in ("CONTENT_STORE_MODE", "CONTENT_STORE_READ", "GOVERNANCE_CONTENT_BUCKET",
                              "CONTENT_BUCKET", "S3_ENV_PREFIX")}
        clean.update(self.env)
        patches = [
            mock.patch.dict(os.environ, clean, clear=True),
            mock.patch.object(coordination_lambda, "_get_s3", return_value=self.s3),
            mock.patch.object(coordination_lambda, "_trigger_governance_recompute_push"),
            mock.patch.object(coordination_lambda, "_trigger_governance_doc_sync_push"),
            mock.patch.object(coordination_lambda, "_compute_governance_hash_local", return_value=HASH),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        coordination_lambda._GOVERNANCE_STORE = None
        self.addCleanup(setattr, coordination_lambda, "_GOVERNANCE_STORE", None)

    def update(self, **kw):
        return coordination_lambda._handle_governance_update(_event(**kw))


class DualWriteLegacyReadTests(_Base):
    def test_first_write_puts_live_to_both_buckets_with_identical_unprefixed_keys(self):
        resp = self.update()
        self.assertEqual(resp["statusCode"], 200)
        self.assertEqual(
            sorted(self.s3.touched("put")),
            sorted([(PROD_CONTENT, "governance/live/agents.md"), (LEGACY, "governance/live/agents.md")]),
        )
        self.assertEqual(self.s3.objects[(PROD_CONTENT, "governance/live/agents.md")], b"# agents v2\n")
        self.assertEqual(self.s3.objects[(LEGACY, "governance/live/agents.md")], b"# agents v2\n")

    def test_update_archives_and_writes_live_to_both_and_reads_legacy_only(self):
        self.s3.objects[(LEGACY, "governance/live/agents.md")] = b"# agents v1\n"
        resp = self.update()
        self.assertEqual(resp["statusCode"], 200)
        # The existing file is read from legacy only; the content bucket is never read.
        self.assertEqual(self.s3.touched("get"), [(LEGACY, "governance/live/agents.md")])
        puts = self.s3.touched("put")
        self.assertEqual(len(puts), 4)  # archive x2 + live x2
        by_bucket = {b: sorted(k for bb, k in puts if bb == b) for b in (PROD_CONTENT, LEGACY)}
        self.assertEqual(by_bucket[PROD_CONTENT], by_bucket[LEGACY])  # identical keys on both
        keys = by_bucket[LEGACY]
        self.assertEqual(len([k for k in keys if k.startswith("governance/history/agents.md/")]), 1)
        self.assertIn("governance/live/agents.md", keys)
        for k in keys:
            self.assertTrue(k.startswith("governance/"), k)
        # The archive carries the previous content, the live key the new one, in both buckets.
        archive = next(k for k in keys if k.startswith("governance/history/"))
        for bucket in (PROD_CONTENT, LEGACY):
            self.assertEqual(self.s3.objects[(bucket, archive)], b"# agents v1\n")
            self.assertEqual(self.s3.objects[(bucket, "governance/live/agents.md")], b"# agents v2\n")
        self.assertEqual(json.loads(resp["body"])["archived_to"], f"s3://{LEGACY}/{archive}")

    def test_put_kwargs_survive_on_both_targets(self):
        self.s3.objects[(LEGACY, "governance/live/agents.md")] = b"# agents v1\n"
        self.update()
        for _op, _bucket, _key, kw in [c for c in self.s3.calls if c[0] == "put"]:
            self.assertEqual(kw.get("ChecksumAlgorithm"), "SHA256")
            self.assertEqual(kw.get("ContentType"), "text/markdown; charset=utf-8")
            self.assertIn("change_summary", kw.get("Metadata", {}))

    def test_nested_file_name_keys_match_on_both_buckets(self):
        self.update(file_name="agents/lifecycle-primer.md")
        self.assertEqual(
            sorted(self.s3.touched("put")),
            sorted([(PROD_CONTENT, "governance/live/agents/lifecycle-primer.md"),
                    (LEGACY, "governance/live/agents/lifecycle-primer.md")]),
        )

    def test_missing_existing_file_is_a_normal_first_write(self):
        # NoSuchKey from the legacy read must keep taking the except s3.exceptions.NoSuchKey branch.
        resp = self.update()
        self.assertEqual(resp["statusCode"], 200)
        self.assertNotIn("archived_to", json.loads(resp["body"]))


class GammaLikeEnvTests(_Base):
    env = dict(ENV_DUAL, S3_ENV_PREFIX="gamma/", CONTENT_BUCKET="content-gamma")

    def test_gamma_env_still_writes_the_prod_content_bucket_with_unprefixed_keys(self):
        self.s3.objects[(LEGACY, "governance/live/agents.md")] = b"# agents v1\n"
        resp = self.update()
        self.assertEqual(resp["statusCode"], 200)
        buckets = {b for b, _k in self.s3.touched("put")}
        self.assertEqual(buckets, {PROD_CONTENT, LEGACY})
        self.assertNotIn("content-gamma", buckets)
        for _b, k in self.s3.touched("put"):
            self.assertTrue(k.startswith("governance/"), k)  # no gamma/ prefix anywhere
        self.assertNotIn("content-gamma", {b for b, _k in self.s3.touched("get")})


class UnsetBucketTests(_Base):
    env = {"CONTENT_STORE_MODE": "dual", "CONTENT_STORE_READ": "legacy"}  # no GOVERNANCE_CONTENT_BUCKET

    def test_unset_bucket_writes_legacy_only_and_does_not_raise(self):
        self.s3.objects[(LEGACY, "governance/live/agents.md")] = b"# agents v1\n"
        resp = self.update()
        self.assertEqual(resp["statusCode"], 200)
        self.assertEqual({b for b, _k in self.s3.touched("put")}, {LEGACY})
        self.assertEqual(len(self.s3.touched("put")), 2)
        self.assertEqual({b for b, _k in self.s3.touched("get")}, {LEGACY})


class LegacyModeTests(_Base):
    env = {"CONTENT_STORE_MODE": "legacy", "GOVERNANCE_CONTENT_BUCKET": PROD_CONTENT}

    def test_legacy_mode_writes_legacy_only_even_with_the_bucket_set(self):
        resp = self.update()
        self.assertEqual(resp["statusCode"], 200)
        self.assertEqual({b for b, _k in self.s3.touched("put")}, {LEGACY})


class DefaultModeTests(_Base):
    env = {}  # nothing set at all: today's behaviour

    def test_no_env_is_byte_identical_to_a_raw_legacy_call(self):
        self.s3.objects[(LEGACY, "governance/live/agents.md")] = b"# agents v1\n"
        resp = self.update()
        self.assertEqual(resp["statusCode"], 200)
        self.assertEqual({b for b, _k in self.s3.touched("put")}, {LEGACY})
        self.assertEqual(self.s3.touched("get"), [(LEGACY, "governance/live/agents.md")])


class FactoryTests(_Base):
    def test_rebuilds_when_the_client_changes(self):
        first = coordination_lambda._governance_store(self.s3)
        self.assertIs(coordination_lambda._governance_store(self.s3), first)
        other = FakeS3()
        second = coordination_lambda._governance_store(other)
        self.assertIsNot(second, first)
        self.assertIs(second.s3, other)

    def test_builds_from_governance_bucket_not_content_bucket(self):
        store = coordination_lambda._governance_store(self.s3)
        self.assertEqual(store.mode, "dual")
        self.assertEqual(store.read_mode, "legacy")
        self.assertEqual(store.content_bucket, PROD_CONTENT)
        self.assertEqual(store.legacy_bucket, LEGACY)
        self.assertEqual(store.legacy_key_prefix, "")
        self.assertEqual(store.content_key("governance/live/agents.md"), "governance/live/agents.md")


if __name__ == "__main__":
    unittest.main()
