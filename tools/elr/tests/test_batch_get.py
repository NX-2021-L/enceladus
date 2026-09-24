"""Offline tests for elr_batch_get.py -- shape-only ID classification, the
project-agnostic tracker sentinel route (ENC-TSK-Q10 / ENC-ISS-791), the
per-ID outcome contract (found / not_found / forbidden / error), per-ID
failure partitioning, the no-list-route HARD RULE, the lower_bound-labeled
digest shape, and the CLI parser contract. No network access -- urlopen is
mocked via unittest.mock.patch.
"""

import contextlib
import importlib
import inspect
import io
import json
import os
import unittest
import urllib.error
import urllib.parse
from pathlib import Path
from unittest.mock import patch

import elr_batch_get

_ELR_ROOT = Path(__file__).resolve().parent.parent
_URLOPEN = "elr_lib.transport.urllib.request.urlopen"


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
    return _FakeHttpResponse(200, json.dumps({"success": True, "record": record}).encode("utf-8"))


def _document_ok(record):
    return _FakeHttpResponse(200, json.dumps(record).encode("utf-8"))


def _not_found(record_id="ENC-TSK-MISSING"):
    """The sentinel route's 404 for an id the server cannot resolve --
    unknown prefix or unknown record (ENC-TSK-Q10 contract)."""
    body = {
        "success": False,
        "error": f"Record not found: {record_id}",
        "error_envelope": {"code": "NOT_FOUND", "message": f"Record not found: {record_id}"},
    }
    return _http_error(404, json.dumps(body).encode("utf-8"))


def _sentinel_unsupported():
    """The 404 a plane that predates the sentinel route answers with: it
    treats "_" as an ordinary, unregistered project name."""
    body = {"success": False, "error": "Project '_' is not registered."}
    return _http_error(404, json.dumps(body).encode("utf-8"))


def _run(ids, responses):
    with patch(_URLOPEN, side_effect=responses) as mock_urlopen:
        digest = elr_batch_get.run_batch_get(ids, "prod", 5)
    return digest, mock_urlopen


def _rows_by_id(digest):
    return {r["id"]: r for r in digest["rows"]}


# ---------------------------------------------------------------------------
# ID classification -- SHAPE only, never project
# ---------------------------------------------------------------------------


class ClassifyIdTests(unittest.TestCase):
    def test_tsk_id_classified_as_tracker_task(self):
        c = elr_batch_get.classify_id("ENC-TSK-O52")
        self.assertEqual(c.kind, elr_batch_get.KIND_TRACKER)
        self.assertIsNone(c.project_id)
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

    def test_any_prefix_is_tracker_with_no_project_inferred(self):
        # ENC-TSK-Q10 / ENC-ISS-791: ELR holds no prefix->project map, so a
        # well-formed id with ANY prefix -- known, new, or bogus -- is a
        # tracker id by shape alone, with nothing inferred client-side.
        # Whether ZZZ resolves is the server's call (a 404 -> not_found).
        for record_id, expected_type in (
            ("INT-TSK-1", "task"),
            ("DVP-TSK-100", "task"),
            ("ZZZ-TSK-1", "task"),
            ("INT-ISS-42", "issue"),
            ("ABCDEFGH-PLN-7", "plan"),
        ):
            with self.subTest(record_id=record_id):
                c = elr_batch_get.classify_id(record_id)
                self.assertEqual(c.kind, elr_batch_get.KIND_TRACKER)
                self.assertIsNone(c.project_id)
                self.assertEqual(c.record_type, expected_type)

    def test_classify_id_takes_only_the_raw_id(self):
        # No resolver / map parameter -- there is nothing to resolve with.
        params = list(inspect.signature(elr_batch_get.classify_id).parameters)
        self.assertEqual(params, ["raw_id"])

    def test_unknown_type_segment_is_unsupported(self):
        c = elr_batch_get.classify_id("ENC-XYZ-1")
        self.assertEqual(c.kind, elr_batch_get.KIND_UNSUPPORTED)
        self.assertIsNone(c.record_type)

    def test_garbage_input_is_unsupported(self):
        for raw in ("garbage", "not-an-id-at-all", "TOTALLY-BOGUS", "ENC-TSK", "-TSK-1"):
            with self.subTest(raw=raw):
                self.assertEqual(elr_batch_get.classify_id(raw).kind, elr_batch_get.KIND_UNSUPPORTED)

    def test_empty_string_is_unsupported(self):
        c = elr_batch_get.classify_id("")
        self.assertEqual(c.kind, elr_batch_get.KIND_UNSUPPORTED)


# ---------------------------------------------------------------------------
# HARD RULE: never construct a list/scan/query/search route; and the
# ENC-TSK-Q10 rule: never construct a project segment either.
# ---------------------------------------------------------------------------


class NoListRouteTests(unittest.TestCase):
    def test_tracker_path_uses_the_sentinel_project_segment(self):
        self.assertEqual(elr_batch_get.PROJECT_SENTINEL, "_")
        path = elr_batch_get.tracker_path("task", "ENC-TSK-O52")
        self.assertEqual(path, "/_/task/ENC-TSK-O52")

    def test_tracker_path_takes_no_project_argument(self):
        params = list(inspect.signature(elr_batch_get.tracker_path).parameters)
        self.assertEqual(params, ["record_type", "record_id"])

    def test_tracker_path_requires_both_parts(self):
        with self.assertRaises(ValueError):
            elr_batch_get.tracker_path("", "ENC-TSK-1")
        with self.assertRaises(ValueError):
            elr_batch_get.tracker_path("task", "")

    def test_document_path_is_entity_specific(self):
        path = elr_batch_get.document_path("DOC-87EC08ECF51A")
        self.assertEqual(path, "/DOC-87EC08ECF51A")

    def test_assert_helper_rejects_list_token(self):
        with self.assertRaises(AssertionError):
            elr_batch_get._assert_not_a_list_route("/_/task_list")

    def test_assert_helper_rejects_scan_query_search_tokens(self):
        for bad in ("/_/task/scan", "/_/task?query=1", "/_/search"):
            with self.assertRaises(AssertionError):
                elr_batch_get._assert_not_a_list_route(bad)

    def test_assert_helper_accepts_entity_specific_path(self):
        # Must not raise.
        self.assertEqual(
            elr_batch_get._assert_not_a_list_route("/_/task/ENC-TSK-1"),
            "/_/task/ENC-TSK-1",
        )

    def test_no_urlopen_call_ever_targets_a_list_route(self):
        """End-to-end: run a mixed tracker+document batch and inspect every
        Request actually handed to urlopen -- none of their URLs may
        contain a list/scan/query/search token.
        """
        responses = [
            _tracker_ok({"status": "open", "title": "T", "project_id": "enceladus"}),
            _document_ok({"version": 1, "title": "D"}),
        ]
        digest, mock_urlopen = _run(["ENC-TSK-1", "DOC-ABCDEF"], responses)

        self.assertTrue(digest["ok"], digest)
        self.assertEqual(mock_urlopen.call_count, 2)
        for call in mock_urlopen.call_args_list:
            req = call[0][0]
            url_lower = req.full_url.lower()
            for token in ("list", "scan", "query", "search"):
                self.assertNotIn(token, url_lower, f"forbidden token {token!r} in {req.full_url!r}")

    def test_no_project_inference(self):
        """ENC-TSK-Q10 / ENC-ISS-791: for ANY prefix, the only thing ELR
        sends is the raw record id on the sentinel route. No project id
        (real or guessed) and no prefix-map lookup ever hits the wire,
        and the resolver module that used to do that no longer exists.
        """
        ids = ["ENC-TSK-P90", "INT-TSK-1", "DVP-TSK-100", "ZZZ-TSK-1"]
        responses = [
            _tracker_ok({"status": "closed", "title": "A", "project_id": "enceladus"}),
            _tracker_ok({"status": "open", "title": "B", "project_id": "intelligence"}),
            _tracker_ok({"status": "open", "title": "C", "project_id": "devops"}),
            _not_found("ZZZ-TSK-1"),
        ]
        # Pin the default prod profile: strip any ENCELADUS_* base-URL /
        # profile overrides from the ambient environment for this run.
        ambient = {k: v for k, v in os.environ.items() if not k.startswith("ENCELADUS_")}
        with patch.dict(os.environ, ambient, clear=True):
            with patch(_URLOPEN, side_effect=responses) as mock_urlopen:
                digest = elr_batch_get.run_batch_get(ids, "prod", 5)

        self.assertEqual(mock_urlopen.call_count, 4)
        for raw_id, call in zip(ids, mock_urlopen.call_args_list):
            req = call[0][0]
            with self.subTest(record_id=raw_id, url=req.full_url):
                self.assertEqual(req.get_method(), "GET")
                parts = urllib.parse.urlsplit(req.full_url)
                self.assertEqual(f"{parts.scheme}://{parts.netloc}", "https://jreese.net")
                self.assertEqual(parts.path, f"/api/v1/tracker/_/task/{raw_id}")
                self.assertEqual(parts.query, "")
                self.assertIn(raw_id, req.full_url)
                lowered = req.full_url.lower()
                for forbidden in ("enceladus", "intelligence", "devops", "/mcp", "prefix_map"):
                    self.assertNotIn(forbidden, lowered, f"{forbidden!r} leaked into {req.full_url!r}")

        # The server's own project verdicts flow through verbatim; the id
        # the server could not resolve is a plain not_found, no guess.
        rows = _rows_by_id(digest)
        self.assertEqual(rows["ENC-TSK-P90"]["project_id"], "enceladus")
        self.assertEqual(rows["INT-TSK-1"]["project_id"], "intelligence")
        self.assertEqual(rows["DVP-TSK-100"]["project_id"], "devops")
        self.assertEqual(rows["ZZZ-TSK-1"]["outcome"], "not_found")
        self.assertIsNone(rows["ZZZ-TSK-1"]["project_id"])

        # The P90 client-side resolver is gone -- module and file.
        with self.assertRaises(ModuleNotFoundError):
            importlib.import_module("elr_lib.prefix")
        self.assertFalse((_ELR_ROOT / "elr_lib" / "prefix.py").exists())

    def test_unsupported_id_never_triggers_a_network_call(self):
        with patch(_URLOPEN) as mock_urlopen:
            digest = elr_batch_get.run_batch_get(["TOTALLY-BOGUS"], "prod", 5)
        mock_urlopen.assert_not_called()
        self.assertEqual(digest["counts"]["failed"], 1)
        self.assertEqual(digest["rows"][0]["kind"], "unsupported")


# ---------------------------------------------------------------------------
# Per-ID outcome contract: found / not_found / forbidden / error
# ---------------------------------------------------------------------------


class OutcomeContractTests(unittest.TestCase):
    def test_classify_outcome_table(self):
        co = elr_batch_get.classify_outcome
        self.assertEqual(co(200, {"record": {"status": "open"}}), "found")
        self.assertEqual(co(201, {}), "found")
        self.assertEqual(co(200, {"error": "shape mismatch"}), "error")
        self.assertEqual(co(404, {"error": "Record not found: ZZZ-TSK-1"}), "not_found")
        self.assertEqual(co(404, {}), "not_found")
        self.assertEqual(co(404, {"error": "Project '_' is not registered."}), "error")
        self.assertEqual(co(404, {"error": "PROJECT '_' IS NOT REGISTERED"}), "error")
        self.assertEqual(co(401, {}), "forbidden")
        self.assertEqual(co(403, {"error": "forbidden"}), "forbidden")
        for status in (0, 301, 400, 409, 418, 500, 502, 503):
            with self.subTest(status=status):
                self.assertEqual(co(status, {}), "error")

    def test_404_is_not_found_with_no_anomaly(self):
        responses = [
            _tracker_ok({"status": "open", "title": "Found", "project_id": "enceladus"}),
            _not_found("ZZZ-TSK-1"),
        ]
        digest, _ = _run(["ENC-TSK-1", "ZZZ-TSK-1"], responses)

        self.assertEqual(
            _rows_by_id(digest)["ZZZ-TSK-1"],
            {
                "id": "ZZZ-TSK-1",
                "kind": "tracker",
                "ok": False,
                "outcome": "not_found",
                "http_status": 404,
                "project_id": None,
                "status_or_version": None,
                "title": "",
            },
        )
        # No per-id anomaly AND no digest-level identity anomaly: a 404 is
        # an authenticated, routed answer, not an ambiguous signal.
        self.assertEqual(digest["anomalies"], [])
        self.assertFalse(digest["ok"])
        self.assertEqual(digest["status"], 207)
        self.assertEqual(digest["counts"]["fetched"], 1)
        self.assertEqual(digest["counts"]["not_found"], 1)
        self.assertEqual(digest["counts"]["failed"], 0)

    def test_all_not_found_is_502_with_no_anomalies(self):
        digest, _ = _run(["ZZZ-TSK-1", "ZZZ-ISS-2"], [_not_found("ZZZ-TSK-1"), _not_found("ZZZ-ISS-2")])
        self.assertFalse(digest["ok"])
        self.assertEqual(digest["status"], 502)
        self.assertEqual(digest["anomalies"], [])
        self.assertEqual(digest["counts"]["fetched"], 0)
        self.assertEqual(digest["counts"]["not_found"], 2)
        self.assertEqual(digest["counts"]["failed"], 0)

    def test_401_is_forbidden_with_auth_anomaly(self):
        digest, _ = _run(["ENC-TSK-1"], [_http_error(401, b'{"error": "unauthorized"}')])
        row = digest["rows"][0]
        self.assertEqual(row["outcome"], "forbidden")
        self.assertEqual(row["http_status"], 401)
        self.assertFalse(row["ok"])
        self.assertIn("ENC-TSK-1: auth_rejected_http_401", digest["anomalies"])
        self.assertIn("ENC-TSK-1: tracker_get_failed_http_401 (unauthorized)", digest["anomalies"])
        self.assertEqual(digest["counts"]["failed"], 1)
        self.assertEqual(digest["counts"]["not_found"], 0)
        self.assertEqual(digest["status"], 502)
        self.assertEqual(digest["identity_posture"], "unknown")

    def test_403_is_forbidden_with_auth_anomaly(self):
        digest, _ = _run(["ENC-TSK-1"], [_http_error(403, b"")])
        row = digest["rows"][0]
        self.assertEqual(row["outcome"], "forbidden")
        self.assertEqual(row["http_status"], 403)
        self.assertIn("ENC-TSK-1: auth_rejected_http_403", digest["anomalies"])
        self.assertIn("ENC-TSK-1: tracker_get_failed_http_403", digest["anomalies"])

    def test_500_after_the_one_get_retry_is_error(self):
        # The transport retries a GET once on 5xx -- two responses, one id.
        digest, mock_urlopen = _run(["ENC-TSK-1"], [_http_error(500, b""), _http_error(500, b"")])
        self.assertEqual(mock_urlopen.call_count, 2)
        row = digest["rows"][0]
        self.assertEqual(row["outcome"], "error")
        self.assertEqual(row["http_status"], 500)
        self.assertFalse(row["ok"])
        self.assertIn("ENC-TSK-1: upstream_error_http_500", digest["anomalies"])
        self.assertIn("ENC-TSK-1: tracker_get_failed_http_500", digest["anomalies"])
        self.assertEqual(digest["counts"]["failed"], 1)

    def test_unreachable_is_error_with_http_status_0(self):
        digest, _ = _run(["ENC-TSK-1"], [urllib.error.URLError("dns failed")])
        row = digest["rows"][0]
        self.assertEqual(row["outcome"], "error")
        self.assertEqual(row["http_status"], 0)
        self.assertIn("ENC-TSK-1: unreachable", digest["anomalies"])
        self.assertIn("ENC-TSK-1: tracker_get_failed_http_0 (unreachable: dns failed)", digest["anomalies"])

    def test_2xx_body_carrying_error_is_error(self):
        responses = [_FakeHttpResponse(200, json.dumps({"error": "shape mismatch"}).encode("utf-8"))]
        digest, _ = _run(["ENC-TSK-1"], responses)
        row = digest["rows"][0]
        self.assertEqual(row["outcome"], "error")
        self.assertEqual(row["http_status"], 200)
        self.assertFalse(row["ok"])
        self.assertIn("ENC-TSK-1: tracker_get_failed_http_200 (shape mismatch)", digest["anomalies"])

    def test_sentinel_route_unsupported_by_server_is_error_not_not_found(self):
        digest, _ = _run(["ENC-TSK-1"], [_sentinel_unsupported()])
        row = digest["rows"][0]
        self.assertEqual(row["outcome"], "error")
        self.assertEqual(row["http_status"], 404)
        self.assertFalse(row["ok"])
        # Exactly one anomaly for this case -- the specific one, never the
        # generic tracker_get_failed_http_404.
        self.assertEqual(digest["anomalies"], ["ENC-TSK-1: sentinel_route_unsupported_by_server"])
        self.assertEqual(digest["counts"]["failed"], 1)
        self.assertEqual(digest["counts"]["not_found"], 0)
        self.assertEqual(digest["status"], 502)

    def test_sentinel_marker_matched_case_insensitively_and_in_envelope(self):
        body = {
            "success": False,
            "error": "not found",
            "error_envelope": {"code": "NOT_FOUND", "message": "project '_' IS NOT REGISTERED"},
        }
        digest, _ = _run(["ENC-TSK-1"], [_http_error(404, json.dumps(body).encode("utf-8"))])
        self.assertEqual(digest["rows"][0]["outcome"], "error")
        self.assertEqual(digest["anomalies"], ["ENC-TSK-1: sentinel_route_unsupported_by_server"])

    def test_unsupported_shape_is_error_without_any_network_call(self):
        with patch(_URLOPEN) as mock_urlopen:
            digest = elr_batch_get.run_batch_get(["garbage", "ENC-XYZ-1"], "prod", 5)
        mock_urlopen.assert_not_called()

        for row in digest["rows"]:
            with self.subTest(row=row["id"]):
                self.assertEqual(row["kind"], "unsupported")
                self.assertFalse(row["ok"])
                self.assertEqual(row["outcome"], "error")
                self.assertEqual(row["http_status"], 0)
                self.assertIsNone(row["project_id"])
                self.assertIsNone(row["status_or_version"])
                self.assertEqual(row["title"], "")
        self.assertEqual(
            digest["anomalies"],
            ["GARBAGE: unsupported_id_shape", "ENC-XYZ-1: unsupported_id_shape"],
        )
        self.assertEqual(digest["counts"]["failed"], 2)
        self.assertEqual(digest["counts"]["fetched"], 0)
        self.assertEqual(digest["counts"]["not_found"], 0)
        self.assertEqual(digest["status"], 502)
        self.assertEqual(digest["identity_posture"], "unknown")

    def test_document_404_is_not_found(self):
        digest, _ = _run(["DOC-ABCDEF"], [_http_error(404, b'{"error": "Document not found"}')])
        row = digest["rows"][0]
        self.assertEqual(row["kind"], "document")
        self.assertEqual(row["outcome"], "not_found")
        self.assertEqual(row["http_status"], 404)
        self.assertFalse(row["ok"])
        self.assertEqual(digest["anomalies"], [])
        self.assertEqual(digest["counts"]["not_found"], 1)

    def test_document_403_is_forbidden(self):
        digest, _ = _run(["DOC-ABCDEF"], [_http_error(403, b'{"error": "nope"}')])
        row = digest["rows"][0]
        self.assertEqual(row["outcome"], "forbidden")
        self.assertIn("DOC-ABCDEF: auth_rejected_http_403", digest["anomalies"])
        self.assertIn("DOC-ABCDEF: document_get_failed_http_403 (nope)", digest["anomalies"])

    def test_document_500_after_retry_is_error(self):
        digest, mock_urlopen = _run(["DOC-ABCDEF"], [_http_error(503, b""), _http_error(503, b"")])
        self.assertEqual(mock_urlopen.call_count, 2)
        self.assertEqual(digest["rows"][0]["outcome"], "error")
        self.assertIn("DOC-ABCDEF: document_get_failed_http_503", digest["anomalies"])

    def test_found_row_project_id_is_the_servers_value(self):
        responses = [
            _tracker_ok({"status": "open", "title": "T", "project_id": "intelligence"}),
            _document_ok({"version": 3, "title": "D", "project_id": "devops"}),
        ]
        digest, _ = _run(["INT-TSK-1", "DOC-ABCDEF"], responses)
        rows = _rows_by_id(digest)
        self.assertEqual(rows["INT-TSK-1"]["outcome"], "found")
        self.assertEqual(rows["INT-TSK-1"]["project_id"], "intelligence")
        self.assertEqual(rows["INT-TSK-1"]["http_status"], 200)
        self.assertEqual(rows["DOC-ABCDEF"]["project_id"], "devops")
        self.assertTrue(digest["ok"])

    def test_found_row_without_server_project_id_reports_none(self):
        digest, _ = _run(["ENC-TSK-1"], [_tracker_ok({"status": "open", "title": "T"})])
        row = digest["rows"][0]
        self.assertTrue(row["ok"])
        self.assertIsNone(row["project_id"])

    def test_found_and_not_found_share_one_identity_posture(self):
        # A not_found answer came through the same authenticated route as
        # a found one, so it must not poison the batch posture to "unknown".
        responses = [_tracker_ok({"status": "open", "title": "T"}), _not_found("ZZZ-TSK-1")]
        digest, _ = _run(["ENC-TSK-1", "ZZZ-TSK-1"], responses)
        self.assertIn(digest["identity_posture"], ("internal-key", "server-held-keys"))
        self.assertFalse(any(a.startswith("mixed_identity_posture") for a in digest["anomalies"]))


# ---------------------------------------------------------------------------
# Per-ID failure partitioning
# ---------------------------------------------------------------------------


class FailurePartitioningTests(unittest.TestCase):
    def test_one_404_does_not_fail_the_whole_batch(self):
        responses = [
            _tracker_ok({"status": "open", "title": "Found task"}),
            _not_found("ENC-TSK-MISSING"),
            _document_ok({"version": 2, "title": "Found doc"}),
        ]
        digest, _ = _run(["ENC-TSK-1", "ENC-TSK-MISSING", "DOC-ABCDEF"], responses)

        rows = _rows_by_id(digest)
        self.assertTrue(rows["ENC-TSK-1"]["ok"])
        self.assertFalse(rows["ENC-TSK-MISSING"]["ok"])
        self.assertEqual(rows["ENC-TSK-MISSING"]["outcome"], "not_found")
        self.assertTrue(rows["DOC-ABCDEF"]["ok"])

        self.assertEqual(digest["counts"]["requested"], 3)
        self.assertEqual(digest["counts"]["fetched"], 2)
        self.assertEqual(digest["counts"]["not_found"], 1)
        self.assertEqual(digest["counts"]["failed"], 0)
        self.assertFalse(digest["ok"])
        self.assertEqual(digest["status"], 207)
        self.assertFalse(any("ENC-TSK-MISSING" in a for a in digest["anomalies"]))

    def test_all_succeed_gives_overall_ok(self):
        responses = [
            _tracker_ok({"status": "open", "title": "A"}),
            _tracker_ok({"status": "closed", "title": "B"}),
        ]
        digest, _ = _run(["ENC-TSK-1", "ENC-TSK-2"], responses)
        self.assertTrue(digest["ok"])
        self.assertEqual(digest["status"], 200)
        self.assertEqual(digest["counts"]["fetched"], 2)

    def test_all_fail_gives_502_and_not_ok(self):
        # 500 (+ its one retry) for the first id, 404 for the second.
        responses = [_http_error(500, b""), _http_error(500, b""), _not_found("ENC-TSK-2")]
        digest, _ = _run(["ENC-TSK-1", "ENC-TSK-2"], responses)
        self.assertFalse(digest["ok"])
        self.assertEqual(digest["status"], 502)
        self.assertEqual(digest["counts"]["fetched"], 0)
        self.assertEqual(digest["counts"]["failed"], 1)
        self.assertEqual(digest["counts"]["not_found"], 1)

    def test_mixed_found_and_unsupported_partitions_correctly(self):
        digest, _ = _run(["ENC-TSK-1", "GARBAGE-ID"], [_tracker_ok({"status": "open", "title": "A"})])
        self.assertEqual(digest["counts"]["fetched"], 1)
        self.assertEqual(digest["counts"]["failed"], 1)
        self.assertEqual(digest["counts"]["not_found"], 0)
        self.assertFalse(digest["ok"])
        self.assertEqual(digest["status"], 207)

    def test_empty_id_list_does_not_crash_and_is_not_ok(self):
        digest = elr_batch_get.run_batch_get([], "prod", 5)
        self.assertFalse(digest["ok"])
        self.assertEqual(digest["status"], 400)
        self.assertEqual(digest["counts"]["requested"], 0)
        self.assertEqual(digest["counts"]["not_found"], 0)
        self.assertIn("no_ids_supplied", digest["anomalies"])


# ---------------------------------------------------------------------------
# lower_bound labeling
# ---------------------------------------------------------------------------


class LowerBoundLabelingTests(unittest.TestCase):
    def test_lower_bound_true_on_success(self):
        digest, _ = _run(["ENC-TSK-1"], [_tracker_ok({"status": "open", "title": "A"})])
        self.assertIs(digest["counts"]["lower_bound"], True)

    def test_lower_bound_true_on_not_found(self):
        digest, _ = _run(["ENC-TSK-1"], [_not_found("ENC-TSK-1")])
        self.assertIs(digest["counts"]["lower_bound"], True)

    def test_lower_bound_true_on_empty_request(self):
        digest = elr_batch_get.run_batch_get([], "prod", 5)
        self.assertIs(digest["counts"]["lower_bound"], True)


# ---------------------------------------------------------------------------
# Digest shape
# ---------------------------------------------------------------------------


class DigestShapeTests(unittest.TestCase):
    def test_top_level_keys(self):
        responses = [_tracker_ok({"status": "open", "title": "A"}), _document_ok({"version": 1, "title": "B"})]
        digest, _ = _run(["ENC-TSK-1", "DOC-ABCDEF"], responses)
        self.assertEqual(
            set(digest.keys()),
            {"operation", "ok", "status", "identity_posture", "anomalies", "counts", "rows"},
        )
        self.assertEqual(digest["operation"], "elr_batch_get.batch")
        # ENC-TSK-Q10: the ENC-TSK-P90 prefix-resolution fields are gone.
        self.assertNotIn("prefix_map_source", digest)
        self.assertNotIn("unclassified", digest)

    def test_counts_keys(self):
        digest, _ = _run(["ENC-TSK-1"], [_tracker_ok({"status": "open", "title": "A"})])
        self.assertEqual(
            set(digest["counts"].keys()),
            {"requested", "fetched", "failed", "not_found", "lower_bound"},
        )

    def test_row_shape(self):
        digest, _ = _run(["ENC-TSK-1"], [_tracker_ok({"status": "open", "title": "A task", "project_id": "enceladus"})])
        row = digest["rows"][0]
        self.assertEqual(
            set(row.keys()),
            {"id", "kind", "ok", "outcome", "http_status", "project_id", "status_or_version", "title"},
        )
        self.assertEqual(row["id"], "ENC-TSK-1")
        self.assertEqual(row["kind"], "tracker")
        self.assertTrue(row["ok"])
        self.assertEqual(row["outcome"], "found")
        self.assertEqual(row["http_status"], 200)
        self.assertEqual(row["project_id"], "enceladus")
        self.assertEqual(row["status_or_version"], "open")
        self.assertEqual(row["title"], "A task")

    def test_ok_is_exactly_outcome_found(self):
        responses = [
            _tracker_ok({"status": "open", "title": "A"}),
            _not_found("ENC-TSK-2"),
            _http_error(403, b""),
            _http_error(500, b""),
            _http_error(500, b""),
        ]
        digest, _ = _run(["ENC-TSK-1", "ENC-TSK-2", "ENC-TSK-3", "ENC-TSK-4", "nonsense"], responses)
        for row in digest["rows"]:
            with self.subTest(row=row["id"]):
                self.assertEqual(row["ok"], row["outcome"] == "found")
                self.assertIn(row["outcome"], elr_batch_get.VALID_OUTCOMES)
                self.assertIsInstance(row["http_status"], int)
        outcomes = [r["outcome"] for r in digest["rows"]]
        self.assertEqual(outcomes, ["found", "not_found", "forbidden", "error", "error"])

    def test_document_row_uses_version_for_status_or_version(self):
        digest, _ = _run(["DOC-ABCDEF"], [_document_ok({"version": 7, "title": "A doc"})])
        row = digest["rows"][0]
        self.assertEqual(row["kind"], "document")
        self.assertEqual(row["status_or_version"], 7)

    def test_digest_never_contains_full_record_bodies(self):
        """digest-first contract: no verbatim record body may leak into
        the digest, only the compact row projection.
        """
        big_body = {"status": "open", "title": "A", "history": ["huge"] * 500, "secret_field": "leak-me"}
        digest, _ = _run(["ENC-TSK-1"], [_tracker_ok(big_body)])
        serialized = json.dumps(digest)
        self.assertNotIn("secret_field", serialized)
        self.assertNotIn("leak-me", serialized)

    def test_digest_is_json_serializable_and_stable_across_calls(self):
        digest, _ = _run(["ENC-TSK-1"], [_tracker_ok({"status": "open", "title": "A"})])
        serialized = json.dumps(digest, sort_keys=True)
        self.assertEqual(json.loads(serialized), digest)

    def test_title_truncated_to_60_chars(self):
        long_title = "X" * 200
        digest, _ = _run(["ENC-TSK-1"], [_tracker_ok({"status": "open", "title": long_title})])
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
        # ENC-TSK-P77: --profile is now the ENVIRONMENT profile, default "prod".
        self.assertEqual(args.profile, "prod")
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
        with patch(_URLOPEN, side_effect=responses):
            with contextlib.redirect_stdout(stdout):
                exit_code = elr_batch_get.main(["--ids", "ENC-TSK-1", "--json"])
        self.assertEqual(exit_code, 0)
        lines = [line for line in stdout.getvalue().splitlines() if line.strip()]
        self.assertEqual(len(lines), 1)
        parsed = json.loads(lines[0])
        self.assertTrue(parsed["ok"])

    def test_main_default_output_is_still_valid_json(self):
        responses = [_not_found("ENC-TSK-1")]
        stdout = io.StringIO()
        with patch(_URLOPEN, side_effect=responses):
            with contextlib.redirect_stdout(stdout):
                exit_code = elr_batch_get.main(["--ids", "ENC-TSK-1"])
        self.assertEqual(exit_code, 1)
        parsed = json.loads(stdout.getvalue())
        self.assertFalse(parsed["ok"])
        self.assertEqual(parsed["rows"][0]["outcome"], "not_found")

    def test_main_with_no_ids_exits_nonzero(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = elr_batch_get.main([])
        self.assertEqual(exit_code, 1)


if __name__ == "__main__":
    unittest.main()
