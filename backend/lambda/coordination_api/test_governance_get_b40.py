"""DVP-TSK-B40 (isolation W4i): GET /api/v1/governance/{file} reads through the B22 governance store (no AWS).

coordination_api is dual with CONTENT_STORE_READ=legacy, so the read stays on the legacy bucket until the flip; after
it, the shared PROD content bucket (unprefixed keys) answers first and a miss falls back to legacy.
"""

from __future__ import annotations

import json
import os
import unittest
from unittest import mock

from test_governance_store_b22 import FakeS3, LEGACY, PROD_CONTENT, coordination_lambda  # noqa: F401


def _get(file_name="agents.md"):
    return coordination_lambda._handle_governance_get({"rawPath": f"/api/v1/governance/{file_name}"})


class _Base(unittest.TestCase):
    env = {"CONTENT_STORE_MODE": "dual", "CONTENT_STORE_READ": "legacy", "GOVERNANCE_CONTENT_BUCKET": PROD_CONTENT,
           "CONTENT_BUCKET": "enceladus-content-gamma-356364570033-us-west-2", "S3_ENV_PREFIX": "gamma/"}

    def setUp(self):
        self.s3 = FakeS3()
        clean = {k: v for k, v in os.environ.items()
                 if k not in ("CONTENT_STORE_MODE", "CONTENT_STORE_READ", "GOVERNANCE_CONTENT_BUCKET",
                              "CONTENT_BUCKET", "S3_ENV_PREFIX")}
        clean.update(self.env)
        for p in (mock.patch.dict(os.environ, clean, clear=True),
                  mock.patch.object(coordination_lambda, "_get_s3", return_value=self.s3)):
            p.start()
            self.addCleanup(p.stop)
        coordination_lambda._GOVERNANCE_STORE = None
        self.addCleanup(setattr, coordination_lambda, "_GOVERNANCE_STORE", None)
        self.s3.objects[(LEGACY, "governance/live/agents.md")] = b"# legacy"
        self.s3.objects[(PROD_CONTENT, "governance/live/agents.md")] = b"# content"

    def body(self, resp):
        return json.loads(resp["body"])


class PinnedReadTests(_Base):
    def test_read_stays_on_the_legacy_bucket(self):
        resp = _get()
        self.assertEqual(resp["statusCode"], 200)
        self.assertEqual(self.body(resp)["content"], "# legacy")
        self.assertEqual(self.s3.touched("get"), [(LEGACY, "governance/live/agents.md")])

    def test_missing_file_is_still_a_404(self):
        self.assertEqual(_get("agents/missing.md")["statusCode"], 404)


class FlippedReadTests(_Base):
    env = {k: v for k, v in _Base.env.items() if k != "CONTENT_STORE_READ"}

    def test_shared_prod_bucket_first_with_unprefixed_keys_even_on_gamma(self):
        self.assertEqual(self.body(_get())["content"], "# content")
        self.assertEqual(self.s3.touched("get"), [(PROD_CONTENT, "governance/live/agents.md")])

    def test_content_miss_falls_back_to_legacy_and_a_double_miss_is_404(self):
        self.s3.objects[(LEGACY, "governance/live/agents/only-legacy.md")] = b"# l"
        self.assertEqual(self.body(_get("agents/only-legacy.md"))["content"], "# l")
        self.assertEqual(_get("agents/nowhere.md")["statusCode"], 404)


if __name__ == "__main__":
    unittest.main()
