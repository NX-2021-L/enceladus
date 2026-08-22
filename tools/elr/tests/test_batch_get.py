"""Offline tests for elr_batch_get.py -- ID classification, per-ID failure
partitioning, the no-list-route HARD RULE, the lower_bound-labeled digest
shape, and the CLI parser contract. No network access -- urlopen is
mocked via unittest.mock.patch.
"""

import contextlib
import io
import json
import unittest
import urllib.error
from unittest.mock import patch

import elr_batch_get


class _FakeHttpResponse:
    def __init__(self, status, body):
        self._status = status
        self._body = body

    def getcode(self):
        return self._status

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


def _http_error(code, body=b""):
    return urllib.error.HTTPError(
        url="https://jreese.net/api/v1/tracker",
        code=code,
        msg="error",
        hdrs=None,
        fp=io.BytesIO(body),
    )


def _tracker_ok(record):
    return _FakeHttpResponse(200, json.dumps({"record": record}).encode("utf-8"))


def _document_ok(record):
    return _FakeHttpResponse(200, json.dumps(record).encode("utf-8"))


# ---------------------------------------------------------------------------
# ID classification
# ---------------------------------------------------------------------------


class ClassifyIdTests(unittest.TestCase):
    def test_tsk_id_classified_as_tracker_task(self):
        c = elr_batch_get.classify_id("ENC-TSK-O52")
        self.assertEqual(c.kind, elr_batch_get.KIND_TRACKER)
        self.assertEqual(c.project_id, "enceladus")
        self.assertEqual(c.record_type, "task")
        self.assertEqual(c.normalized, "ENC-TSK-O52")

    def test_iss_id_classified_as_tracker_issue(self):
        c = elr_batch_get.classify_id("ENC-ISS-1")
        self.assertEqual(c.kind, elr_batch_get.KIND_TRACKER)
        self.assertEqual(c.record_type, "issue")

    def test_ftr_id_classified_as_tracker_feature(self):
        c = elr_batch_get.classify_id("ENC-FTR-134")
        self.assertEqual(c.kind, elr_batch_get.KIND_TRACKER)
        self.assertEqual(c.record_type, "feature")

    def test_pln_id_classified_as_tracker_plan(self):
        c = elr_batch_get.classify_id("ENC-PLN-085")
        self.assertEqual(c.kind, elr_batch_get.KIND_TRACKER)
        self.assertEqual(c.record_type, "plan")

    def test_lsn_id_classified_as_tracker_lesson(self):
        c = elr_batch_get.classify_id("ENC-LSN-53")
        self.assertEqual(c.kind, elr_batch_get.KIND_TRACKER)
        self.assertEqual(c.record_type, "lesson")

    def test_lowercase_input_is_normalized(self):
        c = elr_batch_get.classify_id("enc-tsk-o52")
        self.assertEqual(c.kind, elr_batch_get.KIND_TRACKER)
        self.assertEqual(c.normalized, "ENC-TSK-O52")

    def test_whitespace_is_stripped(self):
        c = elr_batch_get.classify_id("  ENC-TSK-1  ")
        self.assertEqual(c.normalized, "ENC-TSK-1")

    def test_doc_id_classified_as_document(self):
        c = elr_batch_get.classify_id("DOC-87EC08ECF51A")
        self.assertEqual(c.kind, elr_batch_get.KIND_DOCUMENT)
        self.assertIsNone(c.project_id)
        self.assertIsNone(c.record_type)

    def test_unknown_project_prefix_is_unclassified_not_guessed(self):
        # DVP is a real prefix elsewhere in the org, but this tool has no
        # static mapping for it (see _PREFIX_TO_PROJECT_ID) and must never
        # guess or fall back to a list call to resolve it.
        c = elr_batch_get.classify_id("DVP-TSK-100")
        self.assertEqual(c.kind, elr_batch_get.KIND_UNCLASSIFIED)
        self.assertIsNone(c.project_id)

    def test_unknown_type_segment_is_unclassified(self):
        c = elr_batch_get.classify_id("ENC-XYZ-1")
        self.assertEqual(c.kind, elr_batch_get.KIND_UNCLASSIFIED)

    def test_garbage_input_is_unclassified(self):
        c = elr_batch_get.classify_id("not-an-id-at-all")
        self.assertEqual(c.kind, elr_batch_get.KIND_UNCLASSIFIED)

    def test_empty_string_is_unclassified(self):
        c = elr_batch_get.classify_id("")
        self.assertEqual(c.kind, elr_batch_get.KIND_UNCLASSIFIED)


# ---------------------------------------------------------------------------
# HARD RULE: never construct a list/scan/query/search route
# ---------------------------------------------------------------------------


class NoListRouteTests(unittest.TestCase):
    def test_tracker_path_is_entity_specific(self):
        path = elr_batch_get.tracker_path("enceladus", "task", "ENC-TSK-O52")
        self.assertEqual(path, "/enceladus/task/ENC-TSK-O52")

    def test_document_path_is_entity_specific(self):
        path = elr_batch_get.document_path("DOC-87EC08ECF51A")
        self.assertEqual(path, "/DOC-87EC08ECF51A")

    def test_assert_helper_rejects_list_token(self):
        with self.assertRaises(AssertionError):
            elr_batch_get._assert_not_a_list_route("/enceladus/task_list")

    def test_assert_helper_rejects_scan_query_search_tokens(self):
        for bad in ("/enceladus/task/scan", "/enceladus/task?query=1", "/enceladus/search"):
            with self.assertRaises(AssertionError):
                elr_batch_get._assert_not_a_list_route(bad)

    def test_assert_helper_accepts_entity_specific_path(self):
        # Must not raise.
        self.assertEqual(
            elr_batch_get._assert_not_a_list_route("/enceladus/task/ENC-TSK-1"),
            "/enceladus/task/ENC-TSK-1",
        )

    def test_no_urlopen_call_ever_targets_a_list_route(self):
        """End-to-end: run a mixed tracker+document batch and inspect every
        Request actually handed to urlopen -- none of their URLs may
        contain a list/scan/query/search token.
        """
        responses = [
            _tracker_ok({"status": "open", "title": "T"}),
            _document_ok({"version": 1, "title": "D"}),
        ]
        with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses) as mock_urlopen:
            elr_batch_get.run_batch_get(["ENC-TSK-1", "DOC-ABCDEF"], "internal", 5)

        self.assertEqual(mock_urlopen.call_count, 2)
        for call in mock_urlopen.call_args_list:
            req = call[0][0]
            url_lower = req.full_url.lower()
            for token in ("list", "scan", "query", "search"):
                self.assertNotIn(token, url_lower, f"forbidden token {token!r} in {req.full_url!r}")

    def test_unclassified_id_never_triggers_a_network_call(self):
        with patch("elr_lib.transport.urllib.request.urlopen") as mock_urlopen:
            digest = elr_batch_get.run_batch_get(["TOTALLY-BOGUS"], "internal", 5)
        mock_urlopen.assert_not_called()
        self.assertEqual(digest["counts"]["unclassified"], 1)


# ---------------------------------------------------------------------------
# Per-ID failure partitioning
# ---------------------------------------------------------------------------


class FailurePartitioningTests(unittest.TestCase):
    def test_one_404_does_not_fail_the_whole_batch(self):
        responses = [
            _tracker_ok({"status": "open", "title": "Found task"}),
            _http_error(404, json.dumps({"error": "not found"}).encode("utf-8")),
            _document_ok({"version": 2, "title": "Found doc"}),
        ]
        with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses):
            digest = elr_batch_get.run_batch_get(
                ["ENC-TSK-1", "ENC-TSK-MISSING", "DOC-ABCDEF"], "internal", 5
            )

        rows = {r["id"]: r for r in digest["rows"]}
        self.assertTrue(rows["ENC-TSK-1"]["ok"])
        self.assertFalse(rows["ENC-TSK-MISSING"]["ok"])
        self.assertTrue(rows["DOC-ABCDEF"]["ok"])

        self.assertEqual(digest["counts"]["requested"], 3)
        self.assertEqual(digest["counts"]["fetched"], 2)
        self.assertEqual(digest["counts"]["failed"], 1)
        self.assertEqual(digest["counts"]["unclassified"], 0)
        self.assertFalse(digest["ok"])
        self.assertTrue(any("ENC-TSK-MISSING" in a for a in digest["anomalies"]))

    def test_all_succeed_gives_overall_ok(self):
        responses = [
            _tracker_ok({"status": "open", "title": "A"}),
            _tracker_ok({"status": "closed", "title": "B"}),
        ]
        with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses):
            digest = elr_batch_get.run_batch_get(["ENC-TSK-1", "ENC-TSK-2"], "internal", 5)
        self.assertTrue(digest["ok"])
        self.assertEqual(digest["status"], 200)

    def test_all_fail_gives_502_and_not_ok(self):
        responses = [_http_error(500, b""), _http_error(404, b"")]
        with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses):
            digest = elr_batch_get.run_batch_get(["ENC-TSK-1", "ENC-TSK-2"], "internal", 5)
        self.assertFalse(digest["ok"])
        self.assertEqual(digest["status"], 502)

    def test_mixed_classified_and_unclassified_partitions_correctly(self):
        responses = [_tracker_ok({"status": "open", "title": "A"})]
        with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses):
            digest = elr_batch_get.run_batch_get(["ENC-TSK-1", "GARBAGE-ID"], "internal", 5)
        self.assertEqual(digest["counts"]["fetched"], 1)
        self.assertEqual(digest["counts"]["unclassified"], 1)
        self.assertEqual(digest["counts"]["failed"], 0)
        self.assertFalse(digest["ok"])

    def test_empty_id_list_does_not_crash_and_is_not_ok(self):
        digest = elr_batch_get.run_batch_get([], "internal", 5)
        self.assertFalse(digest["ok"])
        self.assertEqual(digest["counts"]["requested"], 0)
        self.assertIn("no_ids_supplied", digest["anomalies"])


# ---------------------------------------------------------------------------
# lower_bound labeling
# ---------------------------------------------------------------------------


class LowerBoundLabelingTests(unittest.TestCase):
    def test_lower_bound_true_on_success(self):
        responses = [_tracker_ok({"status": "open", "title": "A"})]
        with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses):
            digest = elr_batch_get.run_batch_get(["ENC-TSK-1"], "internal", 5)
        self.assertIs(digest["counts"]["lower_bound"], True)

    def test_lower_bound_true_on_partial_failure(self):
        responses = [_http_error(404, b"")]
        with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses):
            digest = elr_batch_get.run_batch_get(["ENC-TSK-1"], "internal", 5)
        self.assertIs(digest["counts"]["lower_bound"], True)

    def test_lower_bound_true_on_empty_request(self):
        digest = elr_batch_get.run_batch_get([], "internal", 5)
        self.assertIs(digest["counts"]["lower_bound"], True)


# ---------------------------------------------------------------------------
# Digest shape
# ---------------------------------------------------------------------------


class DigestShapeTests(unittest.TestCase):
    def test_top_level_keys(self):
        responses = [_tracker_ok({"status": "open", "title": "A"}), _document_ok({"version": 1, "title": "B"})]
        with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses):
            digest = elr_batch_get.run_batch_get(["ENC-TSK-1", "DOC-ABCDEF"], "internal", 5)
        for key in ("operation", "ok", "status", "identity_posture", "anomalies", "counts", "rows"):
            self.assertIn(key, digest)
        self.assertEqual(digest["operation"], "elr_batch_get.batch")

    def test_row_shape(self):
        responses = [_tracker_ok({"status": "open", "title": "A task"})]
        with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses):
            digest = elr_batch_get.run_batch_get(["ENC-TSK-1"], "internal", 5)
        row = digest["rows"][0]
        self.assertEqual(set(row.keys()), {"id", "kind", "ok", "status_or_version", "title"})
        self.assertEqual(row["id"], "ENC-TSK-1")
        self.assertEqual(row["kind"], "tracker")
        self.assertTrue(row["ok"])
        self.assertEqual(row["status_or_version"], "open")
        self.assertEqual(row["title"], "A task")

    def test_document_row_uses_version_for_status_or_version(self):
        responses = [_document_ok({"version": 7, "title": "A doc"})]
        with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses):
            digest = elr_batch_get.run_batch_get(["DOC-ABCDEF"], "internal", 5)
        row = digest["rows"][0]
        self.assertEqual(row["status_or_version"], 7)

    def test_digest_never_contains_full_record_bodies(self):
        """digest-first contract: no verbatim record body may leak into
        the digest, only the compact row projection.
        """
        big_body = {"status": "open", "title": "A", "history": ["huge"] * 500, "secret_field": "leak-me"}
        responses = [_tracker_ok(big_body)]
        with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses):
            digest = elr_batch_get.run_batch_get(["ENC-TSK-1"], "internal", 5)
        serialized = json.dumps(digest)
        self.assertNotIn("secret_field", serialized)
        self.assertNotIn("leak-me", serialized)

    def test_digest_is_json_serializable_and_stable_across_calls(self):
        responses = [_tracker_ok({"status": "open", "title": "A"})]
        with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses):
            digest = elr_batch_get.run_batch_get(["ENC-TSK-1"], "internal", 5)
        serialized = json.dumps(digest, sort_keys=True)
        self.assertEqual(json.loads(serialized), digest)

    def test_title_truncated_to_60_chars(self):
        long_title = "X" * 200
        responses = [_tracker_ok({"status": "open", "title": long_title})]
        with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses):
            digest = elr_batch_get.run_batch_get(["ENC-TSK-1"], "internal", 5)
        row_title = digest["rows"][0]["title"]
        self.assertEqual(len(row_title), 60)
        self.assertTrue(row_title.endswith("..."))

    def test_short_title_not_truncated(self):
        self.assertEqual(elr_batch_get.truncate_title("short"), "short")

    def test_none_title_becomes_empty_string(self):
        self.assertEqual(elr_batch_get.truncate_title(None), "")


# ---------------------------------------------------------------------------
# CLI parser contract (allow_abbrev=False + id-source flags)
# ---------------------------------------------------------------------------


class AllowAbbrevTests(unittest.TestCase):
    def test_parser_has_allow_abbrev_false(self):
        parser = elr_batch_get.build_parser()
        self.assertFalse(parser.allow_abbrev)

    def test_abbreviated_flag_is_rejected(self):
        parser = elr_batch_get.build_parser()
        stderr = io.StringIO()
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(stderr):
                # "--id" is an unambiguous prefix of both --ids and
                # --ids-file -- with allow_abbrev=True this would either
                # be silently accepted or raise an ambiguity error instead
                # of the flat "unrecognized arguments" we require.
                parser.parse_args(["--id", "ENC-TSK-1"])

    def test_full_flag_names_accepted(self):
        parser = elr_batch_get.build_parser()
        args = parser.parse_args(["--ids", "ENC-TSK-1,DOC-ABCDEF", "--timeout", "9", "--json"])
        self.assertEqual(args.ids, "ENC-TSK-1,DOC-ABCDEF")
        self.assertEqual(args.timeout, 9)
        self.assertTrue(args.json)

    def test_defaults(self):
        parser = elr_batch_get.build_parser()
        args = parser.parse_args([])
        self.assertIsNone(args.ids)
        self.assertIsNone(args.ids_file)
        self.assertEqual(args.profile, "internal")
        self.assertEqual(args.timeout, 15)
        self.assertFalse(args.json)


# ---------------------------------------------------------------------------
# ID collection: --ids / --ids-file merge, dedupe, comments
# ---------------------------------------------------------------------------


class CollectIdsTests(unittest.TestCase):
    def test_parse_ids_arg_splits_and_strips(self):
        self.assertEqual(
            elr_batch_get.parse_ids_arg("ENC-TSK-1, ENC-TSK-2 ,ENC-TSK-3"),
            ["ENC-TSK-1", "ENC-TSK-2", "ENC-TSK-3"],
        )

    def test_collect_ids_dedupes_case_insensitively_preserving_first_seen(self):
        ids = elr_batch_get.collect_ids("ENC-TSK-1,enc-tsk-1,ENC-TSK-2", None)
        self.assertEqual(ids, ["ENC-TSK-1", "ENC-TSK-2"])

    def test_collect_ids_merges_ids_and_file(self, tmp_path=None):
        import tempfile
        import os

        fd, path = tempfile.mkstemp()
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write("# comment\nENC-TSK-2\n\nDOC-ABCDEF\n")
            ids = elr_batch_get.collect_ids("ENC-TSK-1", path)
        finally:
            os.remove(path)
        self.assertEqual(ids, ["ENC-TSK-1", "ENC-TSK-2", "DOC-ABCDEF"])


# ---------------------------------------------------------------------------
# main() output contract
# ---------------------------------------------------------------------------


class MainOutputTests(unittest.TestCase):
    def test_main_json_flag_prints_single_line(self):
        responses = [_tracker_ok({"status": "open", "title": "A"})]
        stdout = io.StringIO()
        with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses):
            with contextlib.redirect_stdout(stdout):
                exit_code = elr_batch_get.main(["--ids", "ENC-TSK-1", "--json"])
        self.assertEqual(exit_code, 0)
        lines = [line for line in stdout.getvalue().splitlines() if line.strip()]
        self.assertEqual(len(lines), 1)
        parsed = json.loads(lines[0])
        self.assertTrue(parsed["ok"])

    def test_main_default_output_is_still_valid_json(self):
        responses = [_http_error(404, b"")]
        stdout = io.StringIO()
        with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses):
            with contextlib.redirect_stdout(stdout):
                exit_code = elr_batch_get.main(["--ids", "ENC-TSK-1"])
        self.assertEqual(exit_code, 1)
        parsed = json.loads(stdout.getvalue())
        self.assertFalse(parsed["ok"])

    def test_main_with_no_ids_exits_nonzero(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = elr_batch_get.main([])
        self.assertEqual(exit_code, 1)


if __name__ == "__main__":
    unittest.main()
