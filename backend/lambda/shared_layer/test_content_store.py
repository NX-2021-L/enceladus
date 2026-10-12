"""DVP-TSK-A78 (isolation W4): enceladus_shared.content_store mode semantics (no AWS)."""

import io
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "python"))

from enceladus_shared.content_store import ContentStore, ContentStoreConfigError  # noqa: E402

LEGACY, CONTENT = "jreese-net", "enceladus-content-gamma-1-us-west-2"


class NoSuchKey(Exception):
    def __init__(self):
        super().__init__("missing")
        self.response = {"Error": {"Code": "NoSuchKey"}}


class AccessDenied(Exception):
    def __init__(self):
        super().__init__("denied")
        self.response = {"Error": {"Code": "AccessDenied"}}


class FakeS3:
    def __init__(self):
        self.objects = {}  # (bucket, key) -> (bytes, kwargs)
        self.calls = []
        self.deny = set()

    def _check(self, bucket, key):
        if (bucket, key) in self.deny:
            raise AccessDenied()

    def put_object(self, Bucket, Key, Body, **kw):
        self.calls.append(("put", Bucket, Key, kw))
        self.objects[(Bucket, Key)] = (Body if isinstance(Body, bytes) else Body.encode(), kw)
        return {"Bucket": Bucket, "Key": Key}

    def get_object(self, Bucket, Key, **kw):
        self.calls.append(("get", Bucket, Key, kw))
        self._check(Bucket, Key)
        if (Bucket, Key) not in self.objects:
            raise NoSuchKey()
        return {"Body": io.BytesIO(self.objects[(Bucket, Key)][0]), "Bucket": Bucket}

    def head_object(self, Bucket, Key, **kw):
        self.calls.append(("head", Bucket, Key, kw))
        if (Bucket, Key) not in self.objects:
            raise NoSuchKey()
        return {"Bucket": Bucket}

    def delete_object(self, Bucket, Key):
        self.calls.append(("delete", Bucket, Key, {}))
        self.objects.pop((Bucket, Key), None)

    def generate_presigned_url(self, op, Params, ExpiresIn):
        return f"https://{Params['Bucket']}/{Params['Key']}?e={ExpiresIn}"

    def get_paginator(self, name):
        s3 = self

        class P:
            def paginate(self, Bucket, Prefix):
                yield {"Contents": [{"Key": k} for (b, k) in sorted(s3.objects) if b == Bucket and k.startswith(Prefix)]}
        return P()


def store(s3, mode):
    return ContentStore.from_env(s3, {"CONTENT_STORE_MODE": mode, "CONTENT_BUCKET": CONTENT, "S3_BUCKET": LEGACY,
                                      "S3_ENV_PREFIX": "gamma/"})


class TestModes(unittest.TestCase):
    def test_default_is_legacy_and_needs_no_content_bucket(self):
        s3 = FakeS3()
        st = ContentStore.from_env(s3, {})
        self.assertEqual((st.mode, st.legacy_bucket), ("legacy", "jreese-net"))
        st.put_object("agent-documents/a.md", b"x")
        self.assertEqual(list(s3.objects), [("jreese-net", "agent-documents/a.md")])

    def test_bad_mode_and_missing_content_bucket_fail_fast(self):
        with self.assertRaises(ContentStoreConfigError):
            ContentStore.from_env(FakeS3(), {"CONTENT_STORE_MODE": "both"})
        with self.assertRaises(ContentStoreConfigError):
            ContentStore.from_env(FakeS3(), {"CONTENT_STORE_MODE": "dual"})

    def test_key_mapping_drops_the_legacy_env_prefix(self):
        st = store(FakeS3(), "dual")
        self.assertEqual(st.content_key("gamma/agent-documents/a.md"), "agent-documents/a.md")
        self.assertEqual(st.content_key("agent-documents/a.md"), "agent-documents/a.md")

    def test_dual_writes_both_and_strips_legacy_encryption_args_for_content(self):
        s3 = FakeS3()
        st = store(s3, "dual")
        resp = st.put_object("gamma/agent-documents/a.md", b"x", ContentType="text/markdown", ServerSideEncryption="AES256")
        self.assertEqual(resp["Bucket"], CONTENT)
        puts = [(b, k, kw) for op, b, k, kw in s3.calls if op == "put"]
        self.assertEqual([(b, k) for b, k, _ in puts], [(CONTENT, "agent-documents/a.md"), (LEGACY, "gamma/agent-documents/a.md")])
        self.assertNotIn("ServerSideEncryption", puts[0][2])
        self.assertEqual(puts[1][2]["ServerSideEncryption"], "AES256")
        self.assertEqual(puts[0][2]["ContentType"], "text/markdown")

    def test_dual_reads_content_then_falls_back_to_legacy_on_a_miss_only(self):
        s3 = FakeS3()
        s3.objects[(LEGACY, "gamma/agent-documents/old.md")] = (b"old", {})
        s3.objects[(CONTENT, "agent-documents/new.md")] = (b"new", {})
        st = store(s3, "dual")
        self.assertEqual(st.read_bytes("gamma/agent-documents/new.md"), b"new")
        self.assertEqual(st.read_bytes("gamma/agent-documents/old.md"), b"old")
        s3.deny.add((CONTENT, "agent-documents/denied.md"))
        with self.assertRaises(AccessDenied):  # a non-miss error never silently falls back
            st.read_bytes("gamma/agent-documents/denied.md")

    def test_content_mode_never_touches_legacy(self):
        s3 = FakeS3()
        s3.objects[(LEGACY, "gamma/agent-documents/old.md")] = (b"old", {})
        st = store(s3, "content")
        with self.assertRaises(NoSuchKey):
            st.read_bytes("gamma/agent-documents/old.md")
        st.put_object("gamma/agent-documents/n.md", b"n")
        st.delete_object("gamma/agent-documents/n.md")
        self.assertTrue(all(b == CONTENT for _, b, _, _ in s3.calls))

    def test_dual_list_merges_both_in_legacy_key_form(self):
        s3 = FakeS3()
        s3.objects[(LEGACY, "gamma/agent-documents/a.md")] = (b"", {})
        s3.objects[(CONTENT, "agent-documents/a.md")] = (b"", {})
        s3.objects[(CONTENT, "agent-documents/b.md")] = (b"", {})
        keys = store(s3, "dual").list_keys("gamma/agent-documents/")
        self.assertEqual(sorted(keys), ["gamma/agent-documents/a.md", "gamma/agent-documents/b.md"])

    def test_dual_delete_removes_both(self):
        s3 = FakeS3()
        s3.objects[(LEGACY, "gamma/x/a")] = (b"", {})
        s3.objects[(CONTENT, "x/a")] = (b"", {})
        store(s3, "dual").delete_object("gamma/x/a")
        self.assertEqual(s3.objects, {})

    def test_presigned_url_points_at_the_bucket_that_has_the_object(self):
        s3 = FakeS3()
        s3.objects[(LEGACY, "gamma/d/old.md")] = (b"", {})
        s3.objects[(CONTENT, "d/new.md")] = (b"", {})
        st = store(s3, "dual")
        self.assertIn(f"{CONTENT}/d/new.md", st.presigned_get_url("gamma/d/new.md"))
        self.assertIn(f"{LEGACY}/gamma/d/old.md", st.presigned_get_url("gamma/d/old.md"))


if __name__ == "__main__":
    unittest.main()
