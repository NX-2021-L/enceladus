"""Offline tests for elr_lib.plane_safety -- the five-step guard around a
governed docstore write (DOC-F2CF625B7556 A.7, ENC-TSK-O54). No network
access -- urllib.request.urlopen is mocked at both call sites this
module uses: elr_lib.transport (InternalClient, the target plane) and
elr_lib.plane_safety itself (the bare plane-B client).
"""

import io
import json
import unittest
import urllib.error
from unittest.mock import patch

from elr_lib import config as elr_config
from elr_lib import plane_safety as ps
from elr_lib import transport as elr_transport


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


def _doc_body(doc):
    return {"success": True, "document": doc, **doc}


def _sentinel_doc(version=3):
    return {"document_id": ps.SENTINEL_DOCUMENT_ID, "version": version, "content_hash": "sentinelhash"}


def _list_body(ids, count=None, total_matches=None):
    docs = [{"document_id": i} for i in ids]
    return {
        "success": True,
        "documents": docs,
        "count": count if count is not None else len(docs),
        "total_matches": total_matches if total_matches is not None else len(docs),
    }


def _client():
    cfg = elr_config.InternalProfileConfig()
    return elr_transport.InternalClient(cfg, timeout=5)


class RunPreWriteTests(unittest.TestCase):
    def test_sentinel_ok_and_count_probe_populate_report_no_abort(self):
        responses = [
            _FakeHttpResponse(200, json.dumps(_doc_body(_sentinel_doc())).encode("utf-8")),
            _FakeHttpResponse(200, json.dumps(_list_body(["DOC-AAA", "DOC-BBB"])).encode("utf-8")),
        ]
        with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses):
            pre_state = ps.run_pre_write(_client(), "enceladus", timeout=5)

        self.assertFalse(pre_state["abort"])
        self.assertIsNone(pre_state["abort_reason"])
        self.assertTrue(pre_state["step2_sentinel_identity"]["ok"])
        self.assertEqual(pre_state["step1_pre_state"]["count_probe"]["sample_ids"], ["DOC-AAA", "DOC-BBB"])
        # plane B not configured in this test env -> "unavailable"
        self.assertEqual(pre_state["step1_pre_state"]["plane_b"]["status"], "unavailable")
        self.assertEqual(pre_state["step1_pre_state"]["plane_b"]["anomaly"], "plane-b-probe-unconfigured")

    def test_sentinel_wrong_id_echo_aborts(self):
        wrong_doc = {"document_id": "DOC-WRONGTWIN01", "version": 1}
        responses = [
            _FakeHttpResponse(200, json.dumps(_doc_body(wrong_doc)).encode("utf-8")),
            _FakeHttpResponse(200, json.dumps(_list_body([])).encode("utf-8")),
        ]
        with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses):
            pre_state = ps.run_pre_write(_client(), "enceladus", timeout=5)

        self.assertTrue(pre_state["abort"])
        self.assertEqual(pre_state["abort_reason"], "plane-safety-sentinel-mismatch")
        self.assertFalse(pre_state["step2_sentinel_identity"]["ok"])

    def test_sentinel_404_aborts(self):
        http_error = urllib.error.HTTPError(
            url="https://jreese.net/api/v1/documents/DOC-87EC08ECF51A",
            code=404,
            msg="Not Found",
            hdrs=None,
            fp=io.BytesIO(b'{"error":"not found"}'),
        )
        responses = [http_error, _FakeHttpResponse(200, json.dumps(_list_body([])).encode("utf-8"))]
        with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses):
            pre_state = ps.run_pre_write(_client(), "enceladus", timeout=5)

        self.assertTrue(pre_state["abort"])
        self.assertEqual(pre_state["step2_sentinel_identity"]["status"], 404)

    def test_plane_b_configured_and_reachable(self):
        responses = [
            _FakeHttpResponse(200, json.dumps(_doc_body(_sentinel_doc())).encode("utf-8")),
            _FakeHttpResponse(200, json.dumps(_list_body([])).encode("utf-8")),
        ]
        plane_b_doc = {"document_id": "DOC-PLANEBPROBE1", "version": 7}
        plane_b_resp = _FakeHttpResponse(200, json.dumps(_doc_body(plane_b_doc)).encode("utf-8"))
        env = {
            ps.PLANE_B_BASE_ENV: "https://gamma.example.com/api/v1/documents",
            ps.PLANE_B_PROBE_ENV: "DOC-PLANEBPROBE1",
        }
        with patch.dict("os.environ", env, clear=False):
            with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses):
                with patch("elr_lib.plane_safety.urllib.request.urlopen", return_value=plane_b_resp):
                    pre_state = ps.run_pre_write(_client(), "enceladus", timeout=5)

        plane_b = pre_state["step1_pre_state"]["plane_b"]
        self.assertEqual(plane_b["status"], 200)
        self.assertTrue(plane_b["ok"])
        self.assertEqual(plane_b["document_id_echoed"], "DOC-PLANEBPROBE1")


class RunPostWriteTests(unittest.TestCase):
    def _pre_state(self, sample_ids=None, plane_b_configured=False, plane_b_doc=None):
        step1 = {
            "sentinel": {"status": 200, "ok": True, "document_id_echoed": ps.SENTINEL_DOCUMENT_ID, "version": 1},
            "count_probe": {
                "status": 200,
                "ok": True,
                "count": len(sample_ids or []),
                "total_matches": len(sample_ids or []),
                "sample_ids": sample_ids or [],
            },
            "plane_b": (
                {"status": "unavailable", "ok": None, "anomaly": "plane-b-probe-unconfigured"}
                if not plane_b_configured
                else {
                    "status": 200,
                    "ok": True,
                    "document_id_echoed": plane_b_doc["document_id"],
                    "version": plane_b_doc["version"],
                }
            ),
        }
        return {
            "step1_pre_state": step1,
            "step2_sentinel_identity": step1["sentinel"],
            "abort": False,
            "abort_reason": None,
        }

    def test_target_moved_and_monotonic_id_ok(self):
        minted = "DOC-FRESHLYMINT1"
        new_doc = {"document_id": minted, "version": 1, "content_hash": "abc123", "size_bytes": 42}
        responses = [_FakeHttpResponse(200, json.dumps(_doc_body(new_doc)).encode("utf-8"))]
        pre_state = self._pre_state(sample_ids=["DOC-AAA", "DOC-BBB"])

        with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses):
            post_state = ps.run_post_write(_client(), "enceladus", minted, pre_state, timeout=5)

        self.assertTrue(post_state["step4_post_probe"]["target"]["ok"])
        self.assertTrue(post_state["step5_monotonic_id"]["ok"])
        self.assertTrue(post_state["step5_monotonic_id"]["previously_unseen"])
        self.assertIsNone(post_state["step4_post_probe"]["plane_b_unchanged"])

    def test_monotonic_id_flags_when_id_was_in_pre_sample(self):
        """A minted id that was somehow already in the pre-state listing
        sample is a genuine anomaly (ID reuse / collision) -- the report
        must flag it, not silently pass.
        """
        minted = "DOC-COLLISION01"
        new_doc = {"document_id": minted, "version": 1}
        responses = [_FakeHttpResponse(200, json.dumps(_doc_body(new_doc)).encode("utf-8"))]
        pre_state = self._pre_state(sample_ids=[minted, "DOC-BBB"])

        with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses):
            post_state = ps.run_post_write(_client(), "enceladus", minted, pre_state, timeout=5)

        self.assertFalse(post_state["step5_monotonic_id"]["ok"])
        self.assertFalse(post_state["step5_monotonic_id"]["previously_unseen"])

    def test_plane_b_unchanged_when_stable(self):
        minted = "DOC-FRESHLYMINT2"
        plane_b_doc = {"document_id": "DOC-PLANEBPROBE1", "version": 7}
        pre_state = self._pre_state(plane_b_configured=True, plane_b_doc=plane_b_doc)

        target_resp = _FakeHttpResponse(
            200, json.dumps(_doc_body({"document_id": minted, "version": 1})).encode("utf-8")
        )
        plane_b_resp = _FakeHttpResponse(200, json.dumps(_doc_body(plane_b_doc)).encode("utf-8"))

        env = {ps.PLANE_B_BASE_ENV: "https://gamma.example.com/api/v1/documents", ps.PLANE_B_PROBE_ENV: "DOC-PLANEBPROBE1"}
        with patch.dict("os.environ", env, clear=False):
            with patch("elr_lib.transport.urllib.request.urlopen", return_value=target_resp):
                with patch("elr_lib.plane_safety.urllib.request.urlopen", return_value=plane_b_resp):
                    post_state = ps.run_post_write(_client(), "enceladus", minted, pre_state, timeout=5)

        self.assertTrue(post_state["step4_post_probe"]["plane_b_unchanged"])

    def test_plane_b_drift_detected_when_version_changes(self):
        minted = "DOC-FRESHLYMINT3"
        pre_plane_b_doc = {"document_id": "DOC-PLANEBPROBE1", "version": 7}
        post_plane_b_doc = {"document_id": "DOC-PLANEBPROBE1", "version": 8}
        pre_state = self._pre_state(plane_b_configured=True, plane_b_doc=pre_plane_b_doc)

        target_resp = _FakeHttpResponse(
            200, json.dumps(_doc_body({"document_id": minted, "version": 1})).encode("utf-8")
        )
        plane_b_resp = _FakeHttpResponse(200, json.dumps(_doc_body(post_plane_b_doc)).encode("utf-8"))

        env = {ps.PLANE_B_BASE_ENV: "https://gamma.example.com/api/v1/documents", ps.PLANE_B_PROBE_ENV: "DOC-PLANEBPROBE1"}
        with patch.dict("os.environ", env, clear=False):
            with patch("elr_lib.transport.urllib.request.urlopen", return_value=target_resp):
                with patch("elr_lib.plane_safety.urllib.request.urlopen", return_value=plane_b_resp):
                    post_state = ps.run_post_write(_client(), "enceladus", minted, pre_state, timeout=5)

        self.assertFalse(post_state["step4_post_probe"]["plane_b_unchanged"])


class BuildReportTests(unittest.TestCase):
    def _pre_state(self, sentinel_ok=True):
        sentinel = {"status": 200, "ok": sentinel_ok, "document_id_echoed": ps.SENTINEL_DOCUMENT_ID, "version": 1}
        return {
            "step1_pre_state": {
                "sentinel": sentinel,
                "count_probe": {"status": 200, "ok": True, "count": 0, "total_matches": 0, "sample_ids": []},
                "plane_b": {"status": "unavailable", "ok": None, "anomaly": "plane-b-probe-unconfigured"},
            },
            "step2_sentinel_identity": sentinel,
            "abort": not sentinel_ok,
            "abort_reason": None if sentinel_ok else "plane-safety-sentinel-mismatch",
        }

    def test_report_ok_when_all_steps_pass(self):
        pre_state = self._pre_state()
        post_state = {
            "step4_post_probe": {
                "target": {"status": 200, "ok": True},
                "plane_b": {"status": "unavailable", "ok": None},
                "plane_b_unchanged": None,
            },
            "step5_monotonic_id": {"minted_document_id": "DOC-X", "previously_unseen": True, "ok": True},
        }
        report = ps.build_report(pre_state, post_state, write_ok=True)
        self.assertTrue(report["ok"])
        self.assertEqual(set(report["steps"].keys()), {"1_pre_state", "2_sentinel_identity", "3_write", "4_post_probe", "5_monotonic_id"})
        self.assertIn("plane-b-probe-unconfigured", report["anomalies"])

    def test_report_not_ok_when_sentinel_failed(self):
        pre_state = self._pre_state(sentinel_ok=False)
        report = ps.build_report(pre_state, None, write_ok=None)
        self.assertFalse(report["ok"])
        self.assertIn("plane-safety-sentinel-mismatch", report["anomalies"])
        self.assertIsNone(report["steps"]["4_post_probe"]["ok"])
        self.assertIsNone(report["steps"]["5_monotonic_id"]["ok"])

    def test_report_degraded_plane_b_does_not_flip_ok(self):
        """An unconfigured plane B is honest degradation, not failure --
        the overall report can still be ok=True.
        """
        pre_state = self._pre_state()
        post_state = {
            "step4_post_probe": {
                "target": {"status": 200, "ok": True},
                "plane_b": {"status": "unavailable", "ok": None},
                "plane_b_unchanged": None,
            },
            "step5_monotonic_id": {"minted_document_id": "DOC-X", "previously_unseen": True, "ok": True},
        }
        report = ps.build_report(pre_state, post_state, write_ok=True)
        self.assertTrue(report["ok"])

    def test_report_not_ok_when_target_post_probe_fails(self):
        pre_state = self._pre_state()
        post_state = {
            "step4_post_probe": {
                "target": {"status": 404, "ok": False},
                "plane_b": {"status": "unavailable", "ok": None},
                "plane_b_unchanged": None,
            },
            "step5_monotonic_id": {"minted_document_id": "DOC-X", "previously_unseen": True, "ok": True},
        }
        report = ps.build_report(pre_state, post_state, write_ok=True)
        self.assertFalse(report["ok"])
        self.assertIn("plane-safety-target-post-probe-failed", report["anomalies"])

    def test_report_not_ok_when_plane_b_drift_detected(self):
        pre_state = self._pre_state()
        post_state = {
            "step4_post_probe": {
                "target": {"status": 200, "ok": True},
                "plane_b": {"status": 200, "ok": True},
                "plane_b_unchanged": False,
            },
            "step5_monotonic_id": {"minted_document_id": "DOC-X", "previously_unseen": True, "ok": True},
        }
        report = ps.build_report(pre_state, post_state, write_ok=True)
        self.assertFalse(report["ok"])
        self.assertIn("plane-safety-plane-b-drift-detected", report["anomalies"])


if __name__ == "__main__":
    unittest.main()
