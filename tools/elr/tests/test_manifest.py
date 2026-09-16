"""Unit tests for elr_lib.manifest -- the on-disk digest side-file cache
(ENC-TSK-P78, T-B5, FR-B4-11). No real ~/.enceladus writes -- every test
passes an explicit docs_dir under a tempdir.
"""

from __future__ import annotations

import datetime
import json
import tempfile
import unittest
from pathlib import Path

from elr_lib import manifest as elr_manifest


class SideFilePathTests(unittest.TestCase):
    def test_side_file_path_shape(self):
        path = elr_manifest.side_file_path("DOC-ABC", docs_dir="/tmp/x")
        self.assertEqual(str(path), "/tmp/x/DOC-ABC.digest.json")

    def test_body_cache_path_shape(self):
        path = elr_manifest.body_cache_path("DOC-ABC", "/tmp/x")
        self.assertEqual(str(path), "/tmp/x/DOC-ABC.md")

    def test_paths_expand_user(self):
        path = elr_manifest.side_file_path("DOC-ABC")
        self.assertNotIn("~", str(path))


class WriteReadSideFileTests(unittest.TestCase):
    def test_write_then_read_round_trips(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = {"document_id": "DOC-X", "version": 3, "content_hash": "a" * 64, "size_bytes": 10, "outline": []}
            path, written = elr_manifest.write_side_file("DOC-X", manifest, docs_dir=tmp)
            self.assertTrue(Path(path).is_file())
            self.assertEqual(written["document_id"], "DOC-X")
            self.assertIn("fetched_at", written)

            loaded = elr_manifest.read_side_file("DOC-X", docs_dir=tmp)
            self.assertEqual(loaded, written)

    def test_write_full_manifest_response_preserved_verbatim(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = {"document_id": "DOC-X", "version": 1, "extra_field": "kept-too"}
            _, written = elr_manifest.write_side_file("DOC-X", manifest, docs_dir=tmp)
            self.assertEqual(written["extra_field"], "kept-too")

    def test_read_missing_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(elr_manifest.read_side_file("DOC-NOPE", docs_dir=tmp))

    def test_read_corrupt_json_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = elr_manifest.side_file_path("DOC-X", tmp)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{not json", encoding="utf-8")
            self.assertIsNone(elr_manifest.read_side_file("DOC-X", docs_dir=tmp))

    def test_write_creates_parent_dirs(self):
        with tempfile.TemporaryDirectory() as tmp:
            nested = str(Path(tmp) / "a" / "b" / "c")
            path, _ = elr_manifest.write_side_file("DOC-X", {"document_id": "DOC-X"}, docs_dir=nested)
            self.assertTrue(Path(path).is_file())

    def test_explicit_fetched_at_is_used_verbatim(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, written = elr_manifest.write_side_file(
                "DOC-X", {"document_id": "DOC-X"}, docs_dir=tmp, fetched_at="2020-01-01T00:00:00Z"
            )
            self.assertEqual(written["fetched_at"], "2020-01-01T00:00:00Z")


class UpdateSideFileTests(unittest.TestCase):
    def test_update_merges_into_existing(self):
        with tempfile.TemporaryDirectory() as tmp:
            elr_manifest.write_side_file(
                "DOC-X", {"document_id": "DOC-X", "version": 1, "content_hash": "a" * 64, "size_bytes": 5}, docs_dir=tmp
            )
            _, merged = elr_manifest.update_side_file("DOC-X", {"version": 2, "content_hash": "b" * 64}, docs_dir=tmp)
            self.assertEqual(merged["version"], 2)
            self.assertEqual(merged["content_hash"], "b" * 64)
            self.assertEqual(merged["size_bytes"], 5)  # preserved from the prior write

    def test_update_with_no_existing_file_starts_fresh(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, written = elr_manifest.update_side_file("DOC-NEW", {"version": 1}, docs_dir=tmp)
            self.assertEqual(written["version"], 1)
            self.assertIn("fetched_at", written)


class StalenessTests(unittest.TestCase):
    def test_missing_fetched_at_is_stale(self):
        self.assertTrue(elr_manifest.is_stale(None))
        self.assertTrue(elr_manifest.is_stale(""))

    def test_unparsable_fetched_at_is_stale(self):
        self.assertTrue(elr_manifest.is_stale("not-a-timestamp"))

    def test_fresh_timestamp_is_not_stale(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        fresh = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        self.assertFalse(elr_manifest.is_stale(fresh, now=now))

    def test_just_under_boundary_is_not_stale(self):
        # 23h59m rather than an exact 24h edge -- is_stale()'s `fetched_at`
        # format has no sub-second precision, so an exact-24h `now` minus
        # 24h can round to a hair over the boundary; a full minute of
        # margin keeps this assertion meaningful without being flaky.
        now = datetime.datetime.now(datetime.timezone.utc)
        just_under = (now - datetime.timedelta(hours=23, minutes=59)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.assertFalse(elr_manifest.is_stale(just_under, now=now))

    def test_older_than_24h_is_stale(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        old = (now - datetime.timedelta(hours=25)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.assertTrue(elr_manifest.is_stale(old, now=now))

    def test_custom_max_age(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        two_hours_ago = (now - datetime.timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.assertTrue(elr_manifest.is_stale(two_hours_ago, max_age_hours=1, now=now))
        self.assertFalse(elr_manifest.is_stale(two_hours_ago, max_age_hours=3, now=now))


class NowIsoTests(unittest.TestCase):
    def test_now_iso_shape(self):
        value = elr_manifest.now_iso()
        # Round-trips through strptime with the same format string.
        parsed = datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        self.assertIsNotNone(parsed)
        self.assertTrue(value.endswith("Z"))


if __name__ == "__main__":
    unittest.main()
