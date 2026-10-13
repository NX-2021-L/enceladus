"""DVP-TSK-B44 (isolation W4i-2): document_api governance/live reads go through the governance store (no AWS).

Env under test mirrors the deployed function: CONTENT_STORE_MODE=dual with NO CONTENT_STORE_READ (agent-documents reads
are content-first since B17), GOVERNANCE_CONTENT_BUCKET = the PROD content bucket, GOVERNANCE_STORE_READ=legacy, and an
UNPREFIXED S3_GOVERNANCE_PREFIX on gamma too. The governance reads must stay on S3_BUCKET at governance/live/...
"""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "shared_layer", "python")))

_spec = importlib.util.spec_from_file_location("document_api_b44", os.path.join(HERE, "lambda_function.py"))
document_api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(document_api)

LEGACY = document_api.S3_BUCKET
PROD_CONTENT = "enceladus-content-356364570033-us-west-2"
GAMMA_CONTENT = "enceladus-content-gamma-356364570033-us-west-2"


class _Body:
    def __init__(self, data):
        self._d = data

    def read(self):
        return self._d


class _Pager:
    def __init__(self, s3):
        self.s3 = s3

    def paginate(self, Bucket, Prefix):
        self.s3.calls.append(("list", Bucket, Prefix))
        yield {"Contents": [{"Key": k} for (b, k) in sorted(self.s3.objects) if b == Bucket and k.startswith(Prefix)]}


class FakeS3:
    def __init__(self):
        self.objects = {}
        self.calls = []

    def get_paginator(self, name):
        assert name == "list_objects_v2"
        return _Pager(self)

    def head_object(self, Bucket, Key, **kw):
        self.calls.append(("head", Bucket, Key))
        return {"Metadata": {}}

    def get_object(self, Bucket, Key, **kw):
        self.calls.append(("get", Bucket, Key))
        return {"Body": _Body(self.objects[(Bucket, Key)])}

    def touched(self, op):
        return [c[1] for c in self.calls if c[0] == op]


class _Base(unittest.TestCase):
    governance_prefix = "governance/live"
    store_read = "legacy"

    def setUp(self):
        self.s3 = FakeS3()
        for k in ("agents.md", "agents/a.md", "governance_data_dictionary.json"):
            self.s3.objects[(LEGACY, f"governance/live/{k}")] = b"legacy-" + k.encode()
            self.s3.objects[(PROD_CONTENT, f"governance/live/{k}")] = b"content-" + k.encode()
        self.s3.objects[(LEGACY, "gamma/governance/live/agents.md")] = b"stale-gamma"
        env = {"CONTENT_STORE_MODE": "dual", "CONTENT_BUCKET": self.content_bucket, "S3_ENV_PREFIX": self.env_prefix,
               "GOVERNANCE_CONTENT_BUCKET": PROD_CONTENT}
        if self.store_read:
            env["GOVERNANCE_STORE_READ"] = self.store_read
        patches = [
            mock.patch.dict(os.environ, env),
            mock.patch.object(document_api, "_get_s3", return_value=self.s3),
            mock.patch.object(document_api, "S3_GOVERNANCE_PREFIX", self.governance_prefix),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        os.environ.pop("CONTENT_STORE_READ", None)  # unset in the deployed function
        if not self.store_read:
            os.environ.pop("GOVERNANCE_STORE_READ", None)


class TestProdPlane(_Base):
    content_bucket = PROD_CONTENT
    env_prefix = ""

    def test_governance_store_is_legacy_pinned_although_content_store_read_is_unset(self):
        st = document_api._governance_store()
        self.assertEqual((st.mode, st.read_mode, st.content_bucket, st.legacy_bucket, st.legacy_key_prefix),
                         ("dual", "legacy", PROD_CONTENT, LEGACY, ""))
        self.assertNotIn("CONTENT_STORE_READ", os.environ)

    def test_list_reads_only_the_legacy_bucket_at_the_unprefixed_prefix(self):
        self.assertEqual(document_api._list_governance_live_files(),
                         ["agents.md", "agents/a.md", "governance_data_dictionary.json"])
        self.assertEqual(self.s3.calls, [("list", LEGACY, "governance/live/")])

    def test_sync_head_and_get_stay_on_the_legacy_bucket(self):
        with mock.patch.object(document_api, "_query_project_documents", return_value=[]), \
                mock.patch.object(document_api, "_upsert_synced_document") as upsert:
            document_api._sync_governance_documents()
        self.assertEqual(set(self.s3.touched("head")), {LEGACY})
        self.assertEqual(set(self.s3.touched("get")), {LEGACY})
        self.assertEqual(sorted(c[2] for c in self.s3.calls if c[0] == "get"),
                         ["governance/live/agents.md", "governance/live/agents/a.md",
                          "governance/live/governance_data_dictionary.json"])
        bodies = sorted(kw["content_bytes"] for _, kw in (c for c in upsert.call_args_list))
        self.assertEqual(bodies, [b"legacy-agents.md", b"legacy-agents/a.md", b"legacy-governance_data_dictionary.json"])
        self.assertNotIn(PROD_CONTENT, [c[1] for c in self.s3.calls])


class TestGammaPlane(_Base):
    """gamma: per-environment content bucket, S3_ENV_PREFIX=gamma/, but governance/ is the shared unprefixed corpus."""

    content_bucket = GAMMA_CONTENT
    env_prefix = "gamma/"

    def test_governance_keys_are_unprefixed_and_never_the_gamma_bucket(self):
        st = document_api._governance_store()
        self.assertEqual((st.content_bucket, st.legacy_key_prefix, st.read_mode), (PROD_CONTENT, "", "legacy"))
        self.assertEqual(document_api._list_governance_live_files(),
                         ["agents.md", "agents/a.md", "governance_data_dictionary.json"])
        self.assertEqual(self.s3.calls, [("list", LEGACY, "governance/live/")])
        with mock.patch.object(document_api, "_query_project_documents", return_value=[]), \
                mock.patch.object(document_api, "_upsert_synced_document"):
            document_api._sync_governance_documents()
        keys = [c[2] for c in self.s3.calls if c[0] in ("head", "get")]
        self.assertTrue(keys and all(k.startswith("governance/live/") for k in keys), keys)
        self.assertEqual({c[1] for c in self.s3.calls}, {LEGACY})


class TestUnpinnedContrastAndNoBucket(_Base):
    """Without the pin the same env WOULD read content-first -- the reason GOVERNANCE_STORE_READ exists."""

    content_bucket = PROD_CONTENT
    env_prefix = ""
    store_read = ""

    def test_without_the_pin_governance_would_flip_to_content_first(self):
        st = document_api._governance_store()
        self.assertEqual(st.read_mode, "auto")
        self.assertEqual(st.read_bytes("governance/live/agents.md"), b"content-agents.md")

    def test_without_the_governance_bucket_it_is_a_raw_legacy_call(self):
        os.environ.pop("GOVERNANCE_CONTENT_BUCKET", None)
        self.assertEqual(document_api._governance_store().mode, "legacy")
        self.assertEqual(document_api._governance_store().read_bytes("governance/live/agents.md"), b"legacy-agents.md")


if __name__ == "__main__":
    unittest.main()
