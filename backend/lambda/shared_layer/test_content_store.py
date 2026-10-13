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


class PreconditionFailed(Exception):
    def __init__(self):
        super().__init__("exists")
        self.response = {"Error": {"Code": "PreconditionFailed"}}


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
        if kw.get("IfNoneMatch") == "*" and (Bucket, Key) in self.objects:
            raise PreconditionFailed()
        self.objects[(Bucket, Key)] = (Body if isinstance(Body, bytes) else Body.encode(), kw)
        return {"Bucket": Bucket, "Key": Key}

    def get_object(self, Bucket, Key, **kw):
        self.calls.append(("get", Bucket, Key, kw))
        self._check(Bucket, Key)
        if (Bucket, Key) not in self.objects:
            raise NoSuchKey()
        return {"Body": io.BytesIO(self.objects[(Bucket, Key)][0]), "Bucket": Bucket}

    def copy_object(self, Bucket, Key, CopySource, **kw):
        self.calls.append(("copy", Bucket, Key, dict(kw, CopySource=CopySource)))
        src = (CopySource["Bucket"], CopySource["Key"])
        if src not in self.objects:
            raise NoSuchKey()
        self.objects[(Bucket, Key)] = (self.objects[src][0], kw)
        return {"Bucket": Bucket, "Key": Key}

    def head_object(self, Bucket, Key, **kw):
        self.calls.append(("head", Bucket, Key, kw))
        if (Bucket, Key) not in self.objects:
            raise NoSuchKey()
        return {"Bucket": Bucket}

    def delete_object(self, Bucket, Key):
        self.calls.append(("delete", Bucket, Key, {}))
        self.objects.pop((Bucket, Key), None)

    def upload_file(self, path, Bucket, Key, ExtraArgs=None):
        self.calls.append(("upload", Bucket, Key, ExtraArgs or {}))
        self.objects[(Bucket, Key)] = (open(path, "rb").read(), ExtraArgs or {})

    def generate_presigned_url(self, op, Params, ExpiresIn):
        return f"https://{Params['Bucket']}/{Params['Key']}?e={ExpiresIn}"

    def get_paginator(self, name):
        s3 = self

        class P:
            def paginate(self, Bucket, Prefix):
                yield {"Contents": [{"Key": k} for (b, k) in sorted(s3.objects) if b == Bucket and k.startswith(Prefix)]}
        return P()


def store(s3, mode, read="auto"):
    return ContentStore.from_env(s3, {"CONTENT_STORE_MODE": mode, "CONTENT_BUCKET": CONTENT, "S3_BUCKET": LEGACY,
                                      "S3_ENV_PREFIX": "gamma/", "CONTENT_STORE_READ": read})


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


class TestWriterFirstPhase(unittest.TestCase):
    """DVP-TSK-B09: dual writes with legacy reads, so a function never regenerates from a stale content snapshot."""

    def test_dual_with_legacy_reads_writes_both_but_reads_legacy_only(self):
        s3 = FakeS3()
        s3.objects[(LEGACY, "gamma/mobile/v1/reference/p.md")] = (b"fresh", {})
        s3.objects[(CONTENT, "mobile/v1/reference/p.md")] = (b"stale-snapshot", {})
        st = store(s3, "dual", read="legacy")
        self.assertEqual(st.read_bytes("gamma/mobile/v1/reference/p.md"), b"fresh")
        st.put_object("gamma/mobile/v1/reference/p.md", b"new")
        self.assertEqual(s3.objects[(CONTENT, "mobile/v1/reference/p.md")][0], b"new")
        self.assertEqual(s3.objects[(LEGACY, "gamma/mobile/v1/reference/p.md")][0], b"new")
        self.assertEqual(st.list_keys("gamma/mobile/"), ["gamma/mobile/v1/reference/p.md"])

    def test_upload_file_goes_to_every_write_target_without_legacy_sse_on_content(self):
        import tempfile
        s3 = FakeS3()
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(b"feed")
        st = store(s3, "dual", read="legacy")
        st.upload_file(f.name, "gamma/mobile/v1/tasks.json", {"ContentType": "application/json", "ServerSideEncryption": "AES256"})
        ups = [(b, k, a) for op, b, k, a in s3.calls if op == "upload"]
        self.assertEqual([(b, k) for b, k, _ in ups], [(CONTENT, "mobile/v1/tasks.json"), (LEGACY, "gamma/mobile/v1/tasks.json")])
        self.assertNotIn("ServerSideEncryption", ups[0][2])
        self.assertEqual(ups[1][2]["ServerSideEncryption"], "AES256")
        os.unlink(f.name)

    def test_read_override_validation(self):
        with self.assertRaises(ContentStoreConfigError):
            store(FakeS3(), "dual", read="sometimes")
        with self.assertRaises(ContentStoreConfigError):
            store(FakeS3(), "content", read="legacy")
        self.assertEqual(store(FakeS3(), "dual").read_mode, "auto")


class TestCopyAndConditionalPuts(unittest.TestCase):
    """DVP-TSK-B14 (isolation W4d): copy_object and legacy-first conditional puts."""

    def _copy_kw(self):
        return dict(ContentType="text/markdown", MetadataDirective="REPLACE", ServerSideEncryption="AES256")

    def test_dual_copy_hits_both_targets_from_their_own_bucket(self):
        s3 = FakeS3()
        s3.objects[(CONTENT, "agent-documents/p/versions/D/2.md")] = (b"v2", {})
        s3.objects[(LEGACY, "gamma/agent-documents/p/versions/D/2.md")] = (b"v2", {})
        store(s3, "dual", read="legacy").copy_object(
            "gamma/agent-documents/p/versions/D/2.md", "gamma/agent-documents/p/D.md", **self._copy_kw())
        copies = [c for c in s3.calls if c[0] == "copy"]
        self.assertEqual([(c[1], c[2], c[3]["CopySource"]) for c in copies], [
            (CONTENT, "agent-documents/p/D.md", {"Bucket": CONTENT, "Key": "agent-documents/p/versions/D/2.md"}),
            (LEGACY, "gamma/agent-documents/p/D.md", {"Bucket": LEGACY, "Key": "gamma/agent-documents/p/versions/D/2.md"})])
        self.assertNotIn("ServerSideEncryption", copies[0][3])
        self.assertEqual(copies[1][3]["ServerSideEncryption"], "AES256")
        self.assertEqual(copies[0][3]["MetadataDirective"], "REPLACE")

    def test_dual_copy_content_source_miss_falls_back_to_the_legacy_source(self):
        s3 = FakeS3()
        s3.objects[(LEGACY, "gamma/agent-documents/p/versions/D/3.md")] = (b"v3", {})  # created after the W3 snapshot
        store(s3, "dual", read="legacy").copy_object(
            "gamma/agent-documents/p/versions/D/3.md", "gamma/agent-documents/p/D.md")
        copies = [(c[1], c[2], c[3]["CopySource"]) for c in s3.calls if c[0] == "copy"]
        self.assertEqual(copies, [
            (CONTENT, "agent-documents/p/D.md", {"Bucket": CONTENT, "Key": "agent-documents/p/versions/D/3.md"}),
            (CONTENT, "agent-documents/p/D.md", {"Bucket": LEGACY, "Key": "gamma/agent-documents/p/versions/D/3.md"}),
            (LEGACY, "gamma/agent-documents/p/D.md", {"Bucket": LEGACY, "Key": "gamma/agent-documents/p/versions/D/3.md"})])
        self.assertIn((CONTENT, "agent-documents/p/D.md"), s3.objects)

    def test_copy_non_miss_error_on_the_content_source_is_not_retried(self):
        s3 = FakeS3()
        s3.copy_object = lambda **kw: (_ for _ in ()).throw(AccessDenied())
        with self.assertRaises(AccessDenied):
            store(s3, "dual").copy_object("a", "b")

    def test_content_mode_copy_uses_the_content_bucket_only(self):
        s3 = FakeS3()
        s3.objects[(CONTENT, "agent-documents/x.md")] = (b"x", {})
        store(s3, "content").copy_object("gamma/agent-documents/x.md", "gamma/agent-documents/y.md")
        self.assertEqual([(c[1], c[2], c[3]["CopySource"]) for c in s3.calls if c[0] == "copy"],
                         [(CONTENT, "agent-documents/y.md", {"Bucket": CONTENT, "Key": "agent-documents/x.md"})])

    def test_content_mode_copy_miss_does_not_fall_back(self):
        with self.assertRaises(NoSuchKey):
            store(FakeS3(), "content").copy_object("gamma/agent-documents/x.md", "gamma/agent-documents/y.md")

    def test_legacy_mode_copy_is_legacy_only(self):
        s3 = FakeS3()
        s3.objects[(LEGACY, "gamma/a")] = (b"a", {})
        store(s3, "legacy").copy_object("gamma/a", "gamma/b")
        self.assertEqual([(c[1], c[2]) for c in s3.calls if c[0] == "copy"], [(LEGACY, "gamma/b")])

    def test_conditional_put_writes_legacy_first_then_content(self):
        s3 = FakeS3()
        resp = store(s3, "dual", read="legacy").put_object(
            "gamma/agent-documents/v/1.md", b"v", IfNoneMatch="*", ServerSideEncryption="AES256")
        self.assertEqual([(c[1], c[2]) for c in s3.calls if c[0] == "put"],
                         [(LEGACY, "gamma/agent-documents/v/1.md"), (CONTENT, "agent-documents/v/1.md")])
        self.assertEqual(resp["Bucket"], LEGACY)
        content_call = [c for c in s3.calls if c[1] == CONTENT][0]
        self.assertEqual(content_call[3]["IfNoneMatch"], "*")
        self.assertNotIn("ServerSideEncryption", content_call[3])

    def test_conditional_put_drops_if_match_for_content(self):
        # ETags differ across buckets (SSE-KMS); legacy arbitrates IfMatch, content is written unconditionally.
        s3 = FakeS3()
        store(s3, "dual", read="legacy").put_object("gamma/agent-documents/v/1.md", b"v", IfMatch='"abc"')
        content_call = [c for c in s3.calls if c[1] == CONTENT][0]
        legacy_call = [c for c in s3.calls if c[1] == LEGACY][0]
        self.assertNotIn("IfMatch", content_call[3])
        self.assertEqual(legacy_call[3]["IfMatch"], '"abc"')
        self.assertIn((CONTENT, "agent-documents/v/1.md"), s3.objects)

    def test_conditional_put_legacy_precondition_failed_never_touches_content(self):
        s3 = FakeS3()
        s3.objects[(LEGACY, "gamma/agent-documents/v/1.md")] = (b"old", {})
        with self.assertRaises(PreconditionFailed):
            store(s3, "dual", read="legacy").put_object("gamma/agent-documents/v/1.md", b"new", IfNoneMatch="*")
        self.assertEqual([c[1] for c in s3.calls], [LEGACY])
        self.assertNotIn((CONTENT, "agent-documents/v/1.md"), s3.objects)

    def test_conditional_put_content_precondition_failed_is_swallowed(self):
        s3 = FakeS3()
        s3.objects[(CONTENT, "agent-documents/v/1.md")] = (b"snapshot", {})  # the W3 snapshot holds it
        resp = store(s3, "dual", read="legacy").put_object("gamma/agent-documents/v/1.md", b"v", IfNoneMatch="*")
        self.assertEqual(resp["Bucket"], LEGACY)
        self.assertEqual(s3.objects[(CONTENT, "agent-documents/v/1.md")][0], b"snapshot")
        self.assertEqual(s3.objects[(LEGACY, "gamma/agent-documents/v/1.md")][0], b"v")

    def test_conditional_put_content_non_precondition_error_propagates(self):
        s3 = FakeS3()
        s3.deny = set()
        real = s3.put_object

        def put(Bucket, Key, Body, **kw):
            if Bucket == CONTENT:
                raise AccessDenied()
            return real(Bucket=Bucket, Key=Key, Body=Body, **kw)
        s3.put_object = put
        with self.assertRaises(AccessDenied):
            store(s3, "dual").put_object("gamma/k", b"v", IfNoneMatch="*")

    def test_unconditional_put_order_is_unchanged_content_then_legacy(self):
        s3 = FakeS3()
        resp = store(s3, "dual", read="legacy").put_object("gamma/agent-documents/d.md", b"d", ContentType="text/markdown")
        self.assertEqual([(c[1], c[2]) for c in s3.calls if c[0] == "put"],
                         [(CONTENT, "agent-documents/d.md"), (LEGACY, "gamma/agent-documents/d.md")])
        self.assertEqual(resp["Bucket"], CONTENT)

    def test_conditional_put_outside_dual_mode_is_a_plain_single_target_write(self):
        for mode, bucket, key in (("legacy", LEGACY, "gamma/k"), ("content", CONTENT, "k")):
            s3 = FakeS3()
            store(s3, mode).put_object("gamma/k", b"v", IfNoneMatch="*")
            self.assertEqual([(c[1], c[2]) for c in s3.calls], [(bucket, key)])


if __name__ == "__main__":
    unittest.main()
