"""Unit tests for cursor_webhook.py (ADE Component C).

Pure, hermetic tests — no network, no AWS. All side effects are injected via a
fake CursorWebhookDeps. Run with:

    cd backend/lambda/coordination_api && python -m pytest test_cursor_webhook.py -q
    # or, if pytest is unavailable:
    python -m unittest test_cursor_webhook -v
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import importlib.util
import json
import pathlib
import sys
import unittest

# Import the module under test by file path so the test is runnable from any cwd
# and does not depend on the (heavy) coordination_api package importing cleanly.
_MODULE_PATH = pathlib.Path(__file__).with_name("cursor_webhook.py")
_SPEC = importlib.util.spec_from_file_location("cursor_webhook_under_test", _MODULE_PATH)
assert _SPEC and _SPEC.loader
cursor_webhook = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = cursor_webhook
_SPEC.loader.exec_module(cursor_webhook)


SECRET = "super-secret-shared-key"


def _sign(raw: bytes, secret: str = SECRET) -> str:
    return hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()


def _finished_body() -> dict:
    return {
        "id": "agent-abc123",
        "status": "FINISHED",
        "source": {"repository": "jreese/enceladus", "ref": "main"},
        "target": {
            "branchName": "claude/enc-tsk-i40",
            "prUrl": "https://github.com/jreese/enceladus/pull/42",
        },
        "summary": "Implemented the widget and added tests.",
    }


def _error_body() -> dict:
    return {
        "id": "agent-err999",
        "status": "ERROR",
        "source": {"repository": "jreese/enceladus", "ref": "main"},
        "target": {"branchName": "claude/enc-tsk-z99"},
        "summary": "Build failed: import error.",
    }


def _event(body_obj, *, secret: str = SECRET, sign: bool = True, base64_encode: bool = False,
           bad_signature: bool = False, omit_signature: bool = False, raw_override: bytes = None):
    """Build a synthetic API Gateway HTTP API (v2.0) event."""
    if raw_override is not None:
        raw = raw_override
    else:
        raw = json.dumps(body_obj).encode("utf-8")

    headers = {"content-type": "application/json"}
    if not omit_signature:
        if bad_signature:
            sig = "sha256=" + "0" * 64
        elif sign:
            sig = "sha256=" + _sign(raw, secret)
        else:
            sig = ""
        headers["X-Webhook-Signature"] = sig

    if base64_encode:
        body_field = base64.b64encode(raw).decode("ascii")
        is_b64 = True
    else:
        body_field = raw.decode("utf-8")
        is_b64 = False

    return {
        "requestContext": {"http": {"method": "POST"}},
        "rawPath": "/api/v1/cursor/webhook",
        "headers": headers,
        "body": body_field,
        "isBase64Encoded": is_b64,
    }


class FakeDeps(cursor_webhook.CursorWebhookDeps):
    """Recording fake for the injected side effects."""

    def __init__(self, *, doc_id="DOC-ABC123DEF456", record_id="ENC-ISS-777",
                 gov_hash="govhash-deadbeef", doc_raises=False, issue_raises=False):
        self.documents_created = []
        self.issues_created = []
        self.gov_hash = gov_hash
        self._doc_id = doc_id
        self._record_id = record_id
        self._doc_raises = doc_raises
        self._issue_raises = issue_raises
        super().__init__(
            create_document=self._create_document,
            create_issue=self._create_issue,
            resolve_governance_hash=self._resolve_gov,
        )

    def _create_document(self, payload):
        if self._doc_raises:
            raise RuntimeError("simulated document API failure")
        self.documents_created.append(payload)
        return {"document_id": self._doc_id}

    def _create_issue(self, payload):
        if self._issue_raises:
            raise RuntimeError("simulated tracker create failure")
        self.issues_created.append(payload)
        return {"record_id": self._record_id}

    def _resolve_gov(self):
        return self.gov_hash


# ---------------------------------------------------------------------------
# verify_signature
# ---------------------------------------------------------------------------


class TestVerifySignature(unittest.TestCase):
    def test_valid_prefixed_signature_accepted(self):
        raw = b'{"hello":"world"}'
        sig = "sha256=" + _sign(raw)
        self.assertTrue(cursor_webhook.verify_signature(raw, sig, SECRET))

    def test_valid_bare_hex_signature_accepted(self):
        raw = b'{"hello":"world"}'
        sig = _sign(raw)  # bare hex, no prefix
        self.assertTrue(cursor_webhook.verify_signature(raw, sig, SECRET))

    def test_uppercase_prefix_and_hex_accepted(self):
        raw = b'{"a":1}'
        sig = "SHA256=" + _sign(raw).upper()
        self.assertTrue(cursor_webhook.verify_signature(raw, sig, SECRET))

    def test_missing_signature_rejected(self):
        self.assertFalse(cursor_webhook.verify_signature(b"{}", None, SECRET))
        self.assertFalse(cursor_webhook.verify_signature(b"{}", "", SECRET))

    def test_invalid_signature_rejected(self):
        raw = b'{"hello":"world"}'
        self.assertFalse(cursor_webhook.verify_signature(raw, "sha256=" + "f" * 64, SECRET))

    def test_wrong_secret_rejected(self):
        raw = b'{"hello":"world"}'
        sig = "sha256=" + _sign(raw, "the-wrong-secret")
        self.assertFalse(cursor_webhook.verify_signature(raw, sig, SECRET))

    def test_empty_secret_fails_closed(self):
        raw = b'{"hello":"world"}'
        sig = "sha256=" + _sign(raw, "")
        self.assertFalse(cursor_webhook.verify_signature(raw, sig, ""))

    def test_non_hex_signature_rejected(self):
        self.assertFalse(cursor_webhook.verify_signature(b"{}", "sha256=not-hex-zz", SECRET))

    def test_signature_is_over_raw_bytes_not_reserialized(self):
        # Whitespace-significant body: a re-serialization would change bytes and
        # break the HMAC. Verify we sign the exact bytes.
        raw = b'{ "spaced" : true }'
        sig = "sha256=" + _sign(raw)
        self.assertTrue(cursor_webhook.verify_signature(raw, sig, SECRET))
        # The compact re-serialization must NOT validate against the spaced sig.
        compact = json.dumps(json.loads(raw)).encode("utf-8")
        self.assertNotEqual(compact, raw)
        self.assertFalse(cursor_webhook.verify_signature(compact, sig, SECRET))


# ---------------------------------------------------------------------------
# derive_task_id
# ---------------------------------------------------------------------------


class TestDeriveTaskId(unittest.TestCase):
    def test_basic_normalization(self):
        self.assertEqual(cursor_webhook.derive_task_id("claude/enc-tsk-i40"), "ENC-TSK-I40")

    def test_already_uppercase(self):
        self.assertEqual(cursor_webhook.derive_task_id("claude/ENC-TSK-I40"), "ENC-TSK-I40")

    def test_mixed_case(self):
        self.assertEqual(cursor_webhook.derive_task_id("claude/Enc-Tsk-Abc"), "ENC-TSK-ABC")

    def test_surrounding_whitespace(self):
        self.assertEqual(cursor_webhook.derive_task_id("  claude/enc-tsk-i40  "), "ENC-TSK-I40")

    def test_non_claude_branch_returns_empty(self):
        self.assertEqual(cursor_webhook.derive_task_id("feature/something"), "")
        self.assertEqual(cursor_webhook.derive_task_id("main"), "")

    def test_empty_and_none(self):
        self.assertEqual(cursor_webhook.derive_task_id(""), "")
        self.assertEqual(cursor_webhook.derive_task_id(None), "")

    def test_claude_prefix_only_returns_empty(self):
        # "claude/" with nothing after -> no task id
        self.assertEqual(cursor_webhook.derive_task_id("claude/"), "")

    def test_nested_path_after_claude(self):
        # Defensive: extra slashes are trimmed/captured as-is then uppercased.
        self.assertEqual(cursor_webhook.derive_task_id("claude/enc-tsk-i40/extra"),
                         "ENC-TSK-I40/EXTRA")


# ---------------------------------------------------------------------------
# parse_event
# ---------------------------------------------------------------------------


class TestParseEvent(unittest.TestCase):
    def test_full_payload(self):
        parsed = cursor_webhook.parse_event(_finished_body())
        self.assertEqual(parsed["cursor_agent_id"], "agent-abc123")
        self.assertEqual(parsed["status"], "FINISHED")
        self.assertEqual(parsed["repository"], "jreese/enceladus")
        self.assertEqual(parsed["ref"], "main")
        self.assertEqual(parsed["branch_name"], "claude/enc-tsk-i40")
        self.assertEqual(parsed["pr_url"], "https://github.com/jreese/enceladus/pull/42")
        self.assertIn("Implemented", parsed["summary"])

    def test_missing_nested_keys_tolerated(self):
        parsed = cursor_webhook.parse_event({"id": "x", "status": "finished"})
        self.assertEqual(parsed["status"], "FINISHED")  # uppercased
        self.assertEqual(parsed["repository"], "")
        self.assertEqual(parsed["branch_name"], "")
        self.assertEqual(parsed["pr_url"], "")
        self.assertEqual(parsed["summary"], "")

    def test_non_dict_body_tolerated(self):
        parsed = cursor_webhook.parse_event(None)  # type: ignore[arg-type]
        self.assertEqual(parsed["cursor_agent_id"], "")
        self.assertEqual(parsed["status"], "")

    def test_source_target_not_dicts(self):
        parsed = cursor_webhook.parse_event({"source": "nope", "target": 5})
        self.assertEqual(parsed["repository"], "")
        self.assertEqual(parsed["branch_name"], "")


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------


class TestEvidenceDocPayload(unittest.TestCase):
    def test_fields(self):
        parsed = cursor_webhook.parse_event(_finished_body())
        ts = "2026-06-27T12:34:56Z"
        payload = cursor_webhook.build_evidence_doc_payload(parsed, ts)
        self.assertEqual(payload["title"], f"Cursor Deploy Evidence — ENC-TSK-I40 — {ts}")
        self.assertEqual(payload["document_subtype"], "doc")
        self.assertEqual(payload["subtypepattern"], "deploy-evidence")
        content = payload["content"]
        self.assertIn("ENC-TSK-I40", content)
        self.assertIn("agent-abc123", content)
        self.assertIn("https://github.com/jreese/enceladus/pull/42", content)
        self.assertIn("claude/enc-tsk-i40", content)
        self.assertIn(ts, content)
        self.assertIn("FINISHED", content)
        self.assertIn("Implemented the widget", content)


class TestFinishedIssuePayload(unittest.TestCase):
    def test_fields(self):
        parsed = cursor_webhook.parse_event(_finished_body())
        payload = cursor_webhook.build_finished_issue_payload(parsed, "DOC-XYZ")
        self.assertEqual(
            payload["title"],
            "Close-out ready: ENC-TSK-I40 — Cursor agent FINISHED, PR open",
        )
        self.assertEqual(payload["priority"], "P2")
        self.assertIn("agent-abc123", payload["hypothesis"])
        self.assertIn("ENC-TSK-I40", payload["hypothesis"])
        self.assertIn("https://github.com/jreese/enceladus/pull/42", payload["hypothesis"])
        self.assertIn("DOC-XYZ", payload["hypothesis"])
        self.assertIn("close-out", payload["hypothesis"].lower())
        self.assertIn("DOC-XYZ", payload["technical_notes"])
        self.assertIn("Auto-filed by Enceladus Cursor webhook handler", payload["technical_notes"])


class TestErrorIssuePayload(unittest.TestCase):
    def test_fields(self):
        parsed = cursor_webhook.parse_event(_error_body())
        payload = cursor_webhook.build_error_issue_payload(parsed)
        self.assertEqual(
            payload["title"],
            "Cursor agent ERROR on ENC-TSK-Z99 — manual intervention required",
        )
        self.assertEqual(payload["priority"], "P1")
        self.assertIn("agent-err999", payload["hypothesis"])
        self.assertIn("ENC-TSK-Z99", payload["hypothesis"])
        self.assertIn("https://cursor.com/agents/agent-err999", payload["hypothesis"])
        self.assertIn("Build failed", payload["hypothesis"])
        self.assertIn("Review the agent conversation log", payload["technical_notes"])


# ---------------------------------------------------------------------------
# handle() — full flow
# ---------------------------------------------------------------------------


class TestHandleFinished(unittest.TestCase):
    def test_finished_creates_doc_then_issue_and_returns_200(self):
        deps = FakeDeps()
        ts = "2026-06-27T00:00:00Z"
        status, body = cursor_webhook.handle(
            _event(_finished_body()), None, deps, secret=SECRET, timestamp=ts,
        )
        self.assertEqual(status, 200)
        self.assertTrue(body["success"])
        self.assertEqual(body["task_id"], "ENC-TSK-I40")
        self.assertEqual(body["document_id"], "DOC-ABC123DEF456")
        self.assertEqual(body["record_id"], "ENC-ISS-777")

        # Exactly one doc + one issue created, in that order, with gov hash.
        self.assertEqual(len(deps.documents_created), 1)
        self.assertEqual(len(deps.issues_created), 1)

        doc = deps.documents_created[0]
        self.assertEqual(doc["document_subtype"], "doc")
        self.assertEqual(doc["subtypepattern"], "deploy-evidence")
        self.assertEqual(doc["governance_hash"], "govhash-deadbeef")
        self.assertIn("ENC-TSK-I40", doc["title"])

        issue = deps.issues_created[0]
        self.assertEqual(issue["priority"], "P2")
        self.assertEqual(issue["governance_hash"], "govhash-deadbeef")
        # The issue references the server-returned document_id (no prediction).
        self.assertIn("DOC-ABC123DEF456", issue["hypothesis"])
        self.assertIn("DOC-ABC123DEF456", issue["technical_notes"])


class TestHandleError(unittest.TestCase):
    def test_error_creates_p1_issue_and_returns_200(self):
        deps = FakeDeps(record_id="ENC-ISS-911")
        status, body = cursor_webhook.handle(
            _event(_error_body()), None, deps, secret=SECRET,
        )
        self.assertEqual(status, 200)
        self.assertTrue(body["success"])
        self.assertEqual(body["task_id"], "ENC-TSK-Z99")
        self.assertEqual(body["record_id"], "ENC-ISS-911")

        # ERROR path creates a single issue and NO document.
        self.assertEqual(len(deps.documents_created), 0)
        self.assertEqual(len(deps.issues_created), 1)
        issue = deps.issues_created[0]
        self.assertEqual(issue["priority"], "P1")
        self.assertIn("manual intervention required", issue["title"])
        self.assertEqual(issue["governance_hash"], "govhash-deadbeef")


class TestHandleSignatureAndBody(unittest.TestCase):
    def test_missing_signature_returns_401(self):
        deps = FakeDeps()
        status, body = cursor_webhook.handle(
            _event(_finished_body(), omit_signature=True), None, deps, secret=SECRET,
        )
        self.assertEqual(status, 401)
        self.assertFalse(body["success"])
        self.assertEqual(deps.documents_created, [])
        self.assertEqual(deps.issues_created, [])

    def test_invalid_signature_returns_401(self):
        deps = FakeDeps()
        status, body = cursor_webhook.handle(
            _event(_finished_body(), bad_signature=True), None, deps, secret=SECRET,
        )
        self.assertEqual(status, 401)
        self.assertFalse(body["success"])
        self.assertEqual(deps.issues_created, [])

    def test_unparseable_body_returns_400(self):
        deps = FakeDeps()
        raw = b"this is { not json"
        # Sign the malformed bytes so the signature check passes and we reach
        # the JSON parse step (which must fail with 400).
        event = _event(None, raw_override=raw)
        status, body = cursor_webhook.handle(event, None, deps, secret=SECRET)
        self.assertEqual(status, 400)
        self.assertFalse(body["success"])
        self.assertEqual(deps.issues_created, [])

    def test_base64_encoded_body_signature_path(self):
        deps = FakeDeps()
        ts = "2026-06-27T09:09:09Z"
        # Body delivered base64-encoded; signature is over the RAW (decoded) bytes.
        event = _event(_finished_body(), base64_encode=True)
        status, body = cursor_webhook.handle(event, None, deps, secret=SECRET, timestamp=ts)
        self.assertEqual(status, 200)
        self.assertTrue(body["success"])
        self.assertEqual(body["task_id"], "ENC-TSK-I40")
        self.assertEqual(len(deps.documents_created), 1)
        self.assertEqual(len(deps.issues_created), 1)

    def test_base64_body_with_signature_over_encoded_bytes_is_rejected(self):
        # Guard: a signature computed over the BASE64 text (not the decoded raw)
        # must NOT validate — proves we decode before verifying.
        body_obj = _finished_body()
        raw = json.dumps(body_obj).encode("utf-8")
        b64 = base64.b64encode(raw).decode("ascii")
        wrong_sig = "sha256=" + _sign(b64.encode("utf-8"))  # signed the encoded form
        event = {
            "requestContext": {"http": {"method": "POST"}},
            "rawPath": "/api/v1/cursor/webhook",
            "headers": {"X-Webhook-Signature": wrong_sig},
            "body": b64,
            "isBase64Encoded": True,
        }
        deps = FakeDeps()
        status, _ = cursor_webhook.handle(event, None, deps, secret=SECRET)
        self.assertEqual(status, 401)


class TestHandleInternalErrorStill200(unittest.TestCase):
    def test_document_create_failure_returns_200_and_no_issue(self):
        # Valid signature, but the document create raises -> Cursor must not be
        # told to retry, so we return 200 and log. Issue is never attempted.
        deps = FakeDeps(doc_raises=True)
        status, body = cursor_webhook.handle(
            _event(_finished_body()), None, deps, secret=SECRET, timestamp="2026-06-27T00:00:00Z",
        )
        self.assertEqual(status, 200)
        self.assertFalse(body["success"])
        self.assertEqual(deps.issues_created, [])

    def test_issue_create_failure_returns_200(self):
        deps = FakeDeps(issue_raises=True)
        status, body = cursor_webhook.handle(
            _event(_error_body()), None, deps, secret=SECRET,
        )
        self.assertEqual(status, 200)
        self.assertFalse(body["success"])


class TestHandleUnknownStatus(unittest.TestCase):
    def test_unknown_status_acknowledged_200_no_side_effects(self):
        deps = FakeDeps()
        body_obj = _finished_body()
        body_obj["status"] = "RUNNING"
        status, body = cursor_webhook.handle(
            _event(body_obj), None, deps, secret=SECRET,
        )
        self.assertEqual(status, 200)
        self.assertTrue(body.get("ignored"))
        self.assertEqual(deps.documents_created, [])
        self.assertEqual(deps.issues_created, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
