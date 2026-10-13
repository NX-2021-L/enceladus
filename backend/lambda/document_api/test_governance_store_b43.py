"""DVP-TSK-B43 (isolation W4l): document_api's governance sync reads the ONE shared governance/live corpus (no AWS).

governance/ is a single corpus with unprefixed keys on both planes, held in the PROD content bucket (io,
DOC-EF4BC758CCC9, 2026-10-13). The sync used to read gamma/governance/live on gamma, a copy with no writer. Now both
planes list/head/get governance/live through the governance store: raw jreese-net calls while GOVERNANCE_CONTENT_BUCKET
is unset (how 02-compute ships it), content-first from the prod bucket once it is set (the later read flip).
"""

from __future__ import annotations

import importlib.util
import io
import os
import re
import sys
import unittest
from unittest import mock

from botocore.exceptions import ClientError

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "shared_layer", "python")))

_spec = importlib.util.spec_from_file_location("document_api_b43", os.path.join(HERE, "lambda_function.py"))
document_api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(document_api)

LEGACY = document_api.S3_BUCKET
PROD_CONTENT = "enceladus-content-356364570033-us-west-2"
GAMMA_CONTENT = "enceladus-content-gamma-356364570033-us-west-2"
FILES = {"governance/live/agents.md": b"# agents\n", "governance/live/agents/primer.md": b"# primer\n"}
STORE_ENV = ("CONTENT_STORE_MODE", "CONTENT_STORE_READ", "CONTENT_BUCKET", "S3_ENV_PREFIX", "GOVERNANCE_CONTENT_BUCKET")


class FakeS3:
    def __init__(self, objects):
        self.objects = dict(objects)
        self.calls = []

    def head_object(self, Bucket, Key, **kw):
        self.calls.append(("head", Bucket, Key))
        if (Bucket, Key) not in self.objects:
            raise ClientError({"Error": {"Code": "404", "Message": "Not Found"}}, "HeadObject")
        return {"Metadata": {}}

    def get_object(self, Bucket, Key, **kw):
        self.calls.append(("get", Bucket, Key))
        if (Bucket, Key) not in self.objects:
            raise ClientError({"Error": {"Code": "NoSuchKey", "Message": "missing"}}, "GetObject")
        return {"Body": io.BytesIO(self.objects[(Bucket, Key)])}

    def get_paginator(self, name):
        assert name == "list_objects_v2"
        return self

    def paginate(self, Bucket, Prefix):
        self.calls.append(("list", Bucket, Prefix))
        yield {"Contents": [{"Key": k} for (b, k) in sorted(self.objects) if b == Bucket and k.startswith(Prefix)]}


def _sync(s3, env):
    """Run _sync_governance_documents against ``s3`` with only ``env`` set among the store variables."""
    upserts = []
    clean = {k: v for k, v in os.environ.items() if k not in STORE_ENV}
    clean.update(env)
    with mock.patch.dict(os.environ, clean, clear=True), \
            mock.patch.object(document_api, "_get_s3", return_value=s3), \
            mock.patch.object(document_api, "_query_project_documents", return_value=[]), \
            mock.patch.object(document_api, "_upsert_synced_document",
                              side_effect=lambda **kw: upserts.append((kw["file_name"], kw["content_bytes"]))):
        document_api._sync_governance_documents()
    return sorted(upserts)


EXPECTED = [("agents.md", b"# agents\n"), ("agents/primer.md", b"# primer\n")]


class GovernanceSyncStoreTests(unittest.TestCase):
    def test_default_prefix_is_the_unprefixed_shared_corpus(self):
        self.assertEqual(document_api.S3_GOVERNANCE_PREFIX, "governance/live")

    def test_without_governance_bucket_reads_stay_raw_on_legacy(self):
        objs = {(LEGACY, k): v for k, v in FILES.items()}
        objs[(LEGACY, "gamma/governance/live/agents.md")] = b"# stale gamma copy\n"
        s3 = FakeS3(objs)
        # gamma's document_api env: dual for agent-documents/, but no GOVERNANCE_CONTENT_BUCKET yet
        env = {"CONTENT_STORE_MODE": "dual", "CONTENT_BUCKET": GAMMA_CONTENT, "S3_ENV_PREFIX": "gamma/"}
        self.assertEqual(_sync(s3, env), EXPECTED)
        self.assertEqual({c[1] for c in s3.calls}, {LEGACY})
        self.assertIn(("list", LEGACY, "governance/live/"), s3.calls)
        self.assertFalse(any(c[2].startswith("gamma/") for c in s3.calls))

    def test_after_the_flip_reads_the_shared_prod_bucket_never_the_gamma_one(self):
        objs = {(PROD_CONTENT, k): v for k, v in FILES.items()}
        objs.update({(LEGACY, k): v for k, v in FILES.items()})
        s3 = FakeS3(objs)
        env = {"CONTENT_STORE_MODE": "dual", "CONTENT_BUCKET": GAMMA_CONTENT, "S3_ENV_PREFIX": "gamma/",
               "GOVERNANCE_CONTENT_BUCKET": PROD_CONTENT}
        self.assertEqual(_sync(s3, env), EXPECTED)
        self.assertTrue(all(c[1] == PROD_CONTENT for c in s3.calls if c[0] in ("head", "get")))
        self.assertNotIn(GAMMA_CONTENT, {c[1] for c in s3.calls})
        self.assertFalse(any(c[2].startswith("gamma/") for c in s3.calls))

    def test_after_the_flip_a_file_missing_from_content_falls_back_to_legacy(self):
        objs = {(LEGACY, k): v for k, v in FILES.items()}
        objs[(PROD_CONTENT, "governance/live/agents.md")] = FILES["governance/live/agents.md"]
        s3 = FakeS3(objs)
        env = {"CONTENT_STORE_MODE": "dual", "GOVERNANCE_CONTENT_BUCKET": PROD_CONTENT}
        self.assertEqual(_sync(s3, env), EXPECTED)
        self.assertIn(("get", LEGACY, "governance/live/agents/primer.md"), s3.calls)


def _block(text, name):
    """The resource's body with comment lines dropped."""
    m = re.search(r"(?ms)^  " + name + r":\n(.*?)(?=^  [A-Za-z0-9]+:\n|\Z)", text)
    assert m, name
    return "".join(ln for ln in m.group(1).splitlines(True) if not ln.lstrip().startswith("#"))


class GovernanceSyncCloudFormationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(REPO, "infrastructure", "cloudformation", "02-compute.yaml"), encoding="utf-8") as fh:
            cls.text = fh.read()

    def test_function_reads_the_unprefixed_corpus_and_stays_legacy(self):
        b = _block(self.text, "DocumentApiFunction")
        self.assertIn("S3_GOVERNANCE_PREFIX: governance/live\n", b)
        self.assertNotIn("${S3EnvPrefix}governance/live", b)
        self.assertNotIn("GOVERNANCE_CONTENT_BUCKET", b)  # setting it is the later read flip

    def test_role_reads_the_shared_corpus_on_both_planes(self):
        b = _block(self.text, "DocumentApiRole")
        self.assertNotIn("governance/live", b.split("Sid: S3ReferenceRead", 1)[1].split("- Sid:", 1)[0])
        read = b.split("Sid: S3GovernanceLiveSharedRead", 1)[1].split("- Sid:", 1)[0]
        self.assertIn('"arn:aws:s3:::jreese-net/governance/live/*"', read)
        self.assertIn('!Sub "arn:aws:s3:::enceladus-content-${AWS::AccountId}-${AWS::Region}/governance/live/*"', read)
        lst = b.split("Sid: S3ListGovernanceSharedProdContent", 1)[1].split("- Sid:", 1)[0]
        self.assertIn('!Sub "arn:aws:s3:::enceladus-content-${AWS::AccountId}-${AWS::Region}"', lst)
        self.assertNotIn("Condition", lst)  # a content miss must answer 404 (legacy fallback), not 403


if __name__ == "__main__":
    unittest.main()
