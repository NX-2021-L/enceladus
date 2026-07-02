"""Tests for coordination_api lesson-candidate approve/reject (ENC-TSK-J46 / ENC-FTR-096 Ph2).

Validates:
- Cognito-only enforcement (403 for internal-key sessions) on both approve and reject.
- Approve requires observation/insight/pillar_scores; creates a lesson record with
  evidence_chain including the candidate document_id, then finalizes the candidate
  to handoff_status='approved' via a direct DynamoDB write (NOT document_api's PATCH
  -- that endpoint's internal-key auth is shared with the MCP server's agent-facing
  documents.patch relay, so it can't distinguish this already-Cognito-verified call
  from a bare agent session; see _finalize_lesson_candidate_decision).
- Reject requires rejection_reason >= 10 chars; finalizes the candidate to
  handoff_status='stale' with the reason appended to its decision_log (append-only,
  never deleted).
- 404 when the candidate document is missing; 400 when it isn't a lesson-candidate;
  409 when it isn't pending (already decided), including the concurrent-decision race.
"""

import importlib.util
import json
import os
import sys
import unittest
from unittest import mock


sys.path.insert(0, os.path.dirname(__file__))
_SPEC = importlib.util.spec_from_file_location(
    "coordination_lambda_lesson_candidate",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
coordination_lambda = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
sys.modules[_SPEC.name] = coordination_lambda
_SPEC.loader.exec_module(coordination_lambda)


COGNITO_CLAIMS = {
    "auth_mode": "cognito",
    "sub": "user-sub-123",
    "email": "lead@example.com",
    "cognito:username": "lead",
}
INTERNAL_CLAIMS = {"auth_mode": "internal-key", "sub": "agent"}

PILLAR_SCORES = {
    "efficiency": 0.8,
    "human_protection": 0.9,
    "intention": 0.7,
    "alignment": 0.8,
}

PENDING_CANDIDATE = {
    "_status_code": 200,
    "document_id": "DOC-CANDIDATE01",
    "project_id": "enceladus",
    "title": "LESSON-CANDIDATE -- recurring co-citation cluster",
    "document_subtype": "lesson-candidate",
    "handoff_status": "pending",
}


def _event(body):
    return {"httpMethod": "POST", "body": json.dumps(body or {})}


class LessonCandidateApproveTests(unittest.TestCase):
    def test_internal_key_returns_403(self):
        resp = coordination_lambda._handle_lesson_candidate_approve(
            "DOC-CANDIDATE01", _event({}), INTERNAL_CLAIMS
        )
        self.assertEqual(resp["statusCode"], 403)

    def test_missing_candidate_returns_404(self):
        with mock.patch.object(
            coordination_lambda, "_invoke_document_api", return_value={"_status_code": 404}
        ):
            resp = coordination_lambda._handle_lesson_candidate_approve(
                "DOC-MISSING", _event({}), COGNITO_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 404)

    def test_wrong_subtype_returns_400(self):
        wrong = dict(PENDING_CANDIDATE, document_subtype="doc")
        with mock.patch.object(coordination_lambda, "_invoke_document_api", return_value=wrong):
            resp = coordination_lambda._handle_lesson_candidate_approve(
                "DOC-CANDIDATE01", _event({}), COGNITO_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 400)

    def test_already_decided_returns_409(self):
        decided = dict(PENDING_CANDIDATE, handoff_status="approved")
        with mock.patch.object(coordination_lambda, "_invoke_document_api", return_value=decided):
            resp = coordination_lambda._handle_lesson_candidate_approve(
                "DOC-CANDIDATE01", _event({}), COGNITO_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 409)

    def test_missing_observation_returns_400(self):
        with mock.patch.object(
            coordination_lambda, "_invoke_document_api", return_value=PENDING_CANDIDATE
        ):
            resp = coordination_lambda._handle_lesson_candidate_approve(
                "DOC-CANDIDATE01",
                _event({"insight": "x", "pillar_scores": PILLAR_SCORES}),
                COGNITO_CLAIMS,
            )
        self.assertEqual(resp["statusCode"], 400)

    def test_missing_pillar_scores_returns_400(self):
        with mock.patch.object(
            coordination_lambda, "_invoke_document_api", return_value=PENDING_CANDIDATE
        ):
            resp = coordination_lambda._handle_lesson_candidate_approve(
                "DOC-CANDIDATE01",
                _event({"observation": "o", "insight": "i"}),
                COGNITO_CLAIMS,
            )
        self.assertEqual(resp["statusCode"], 400)

    def test_happy_path_creates_lesson_and_finalizes_candidate(self):
        with mock.patch.object(coordination_lambda, "_invoke_document_api", return_value=PENDING_CANDIDATE), \
             mock.patch.object(
                 coordination_lambda,
                 "_load_project_meta",
                 return_value=coordination_lambda.ProjectMeta(project_id="enceladus", prefix="ENC"),
             ), \
             mock.patch.object(coordination_lambda, "_create_lesson_record", return_value="ENC-LSN-042") as create_mock, \
             mock.patch.object(coordination_lambda, "_finalize_lesson_candidate_decision") as finalize_mock:
            resp = coordination_lambda._handle_lesson_candidate_approve(
                "DOC-CANDIDATE01",
                _event({
                    "observation": "Records recur together across handoffs.",
                    "insight": "This signals a transferable workflow pattern.",
                    "pillar_scores": PILLAR_SCORES,
                }),
                COGNITO_CLAIMS,
            )

        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["lesson_id"], "ENC-LSN-042")
        self.assertEqual(body["handoff_status"], "approved")

        # evidence_chain must include the candidate document_id (provenance anchor).
        create_args = create_mock.call_args.args
        evidence_chain = create_args[5]
        self.assertIn("DOC-CANDIDATE01", evidence_chain)

        # The candidate must be finalized to approved via the direct-write path
        # (never via document_api's shared-internal-key PATCH -- see
        # _finalize_lesson_candidate_decision's docstring for why).
        finalize_mock.assert_called_once()
        finalize_args = finalize_mock.call_args.args
        self.assertEqual(finalize_args[0], "DOC-CANDIDATE01")
        self.assertEqual(finalize_args[1], "approved")


class LessonCandidateRejectTests(unittest.TestCase):
    def test_internal_key_returns_403(self):
        resp = coordination_lambda._handle_lesson_candidate_reject(
            "DOC-CANDIDATE01", _event({"rejection_reason": "not useful pattern"}), INTERNAL_CLAIMS
        )
        self.assertEqual(resp["statusCode"], 403)

    def test_short_reason_returns_400(self):
        resp = coordination_lambda._handle_lesson_candidate_reject(
            "DOC-CANDIDATE01", _event({"rejection_reason": "meh"}), COGNITO_CLAIMS
        )
        self.assertEqual(resp["statusCode"], 400)

    def test_missing_candidate_returns_404(self):
        with mock.patch.object(
            coordination_lambda, "_invoke_document_api", return_value={"_status_code": 404}
        ):
            resp = coordination_lambda._handle_lesson_candidate_reject(
                "DOC-MISSING", _event({"rejection_reason": "not useful pattern"}), COGNITO_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 404)

    def test_already_decided_returns_409(self):
        decided = dict(PENDING_CANDIDATE, handoff_status="stale")
        with mock.patch.object(coordination_lambda, "_invoke_document_api", return_value=decided):
            resp = coordination_lambda._handle_lesson_candidate_reject(
                "DOC-CANDIDATE01", _event({"rejection_reason": "not useful pattern"}), COGNITO_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 409)

    def test_happy_path_marks_stale_via_direct_write(self):
        with mock.patch.object(coordination_lambda, "_invoke_document_api", return_value=PENDING_CANDIDATE), \
             mock.patch.object(coordination_lambda, "_finalize_lesson_candidate_decision") as finalize_mock:
            resp = coordination_lambda._handle_lesson_candidate_reject(
                "DOC-CANDIDATE01",
                _event({"rejection_reason": "Cluster is coincidental, not a real pattern."}),
                COGNITO_CLAIMS,
            )

        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["handoff_status"], "stale")

        finalize_mock.assert_called_once_with(
            "DOC-CANDIDATE01", "stale", "lead@example.com",
            "Cluster is coincidental, not a real pattern.",
        )

    def test_concurrent_decision_race_returns_409(self):
        class _CCFE(Exception):
            pass

        error_response = {"Error": {"Code": "ConditionalCheckFailedException"}}
        with mock.patch.object(coordination_lambda, "_invoke_document_api", return_value=PENDING_CANDIDATE), \
             mock.patch.object(
                 coordination_lambda, "_finalize_lesson_candidate_decision",
                 side_effect=coordination_lambda.ClientError(error_response, "UpdateItem"),
             ):
            resp = coordination_lambda._handle_lesson_candidate_reject(
                "DOC-CANDIDATE01",
                _event({"rejection_reason": "Cluster is coincidental, not a real pattern."}),
                COGNITO_CLAIMS,
            )
        self.assertEqual(resp["statusCode"], 409)


if __name__ == "__main__":
    unittest.main()
