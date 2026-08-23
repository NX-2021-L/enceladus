#!/usr/bin/env python3
"""ENC-TSK-P02 / ENC-ISS-659: tests for the agent-cli S3 boundary transform.

This script edits the security boundary of every enceladus agent session, from a
document it reads at runtime and cannot see at review time. So the tests carry
more weight than usual: they pin the shape it expects, prove it refuses anything
else, and prove it does not widen access it was not asked to widen.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from correct_agent_cli_s3_boundary import CONTAINMENT_SID, transform  # noqa: E402


def live_shaped_policy() -> dict:
    """The shape io's read-only inspection reported on 2026-08-23."""
    return {"Version": "2012-10-17", "Statement": [
        {"Sid": "AllowMinimalReads", "Effect": "Allow",
         "Action": ["s3:GetObject", "s3:ListBucket", "logs:GetLogEvents"],
         "Resource": "*"},
        {"Sid": "HarrisonFamilySiteDeploy", "Effect": "Allow", "Action": "s3:*",
         "Resource": "arn:aws:s3:::harrisonfamily-frontend"},
        {"Sid": "DenyS3Elsewhere", "Effect": "Deny", "Action": "s3:*",
         "NotResource": "arn:aws:s3:::harrisonfamily-frontend"},
        {"Sid": "DenyAllDynamoWrites", "Effect": "Deny",
         "Action": ["dynamodb:PutItem", "dynamodb:UpdateItem"], "Resource": "*"},
    ]}


class TestTransform(unittest.TestCase):
    def test_removes_the_cross_project_write_privilege(self):
        new, _ = transform(live_shaped_policy(), "none")
        for statement in new["Statement"]:
            if statement.get("Effect") == "Allow":
                resources = statement.get("Resource")
                resources = resources if isinstance(resources, list) else [resources]
                for resource in resources:
                    self.assertNotIn("harrisonfamily-frontend", resource)

    def test_removes_the_shadowing_deny(self):
        new, _ = transform(live_shaped_policy(), "none")
        shadowing = [
            s for s in new["Statement"]
            if s.get("Effect") == "Deny"
            and "harrisonfamily-frontend" in str(s.get("NotResource", ""))
        ]
        self.assertEqual(shadowing, [])

    def test_read_scope_none_denies_s3_everywhere(self):
        """The conservative option must not widen anything.

        ENC-TSK-P05 CORRECTION. This test previously asserted
        NotResource == [] and passed -- while the statement it was pinning
        denied NOTHING. AWS Access Analyzer on that exact document returns
        EMPTY_ARRAY_RESOURCE, "includes no resources and does not affect the
        policy". So the conservative option was in fact the widest: it removed
        the shadowing Deny and replaced it with a no-op, promoting
        AllowMinimalReads' Resource "*" to live across every bucket.

        A test that asserts the shape a tool emits, and nothing about what that
        shape MEANS, cannot catch this. Hence
        test_every_read_scope_produces_a_policy_aws_itself_accepts below.
        """
        new, _ = transform(live_shaped_policy(), "none")
        containment = [s for s in new["Statement"] if s.get("Sid") == CONTAINMENT_SID]
        self.assertEqual(len(containment), 1)
        self.assertEqual(containment[0]["Effect"], "Deny")
        self.assertEqual(containment[0]["Resource"], "*")
        self.assertNotIn(
            "NotResource", containment[0],
            "an empty NotResource is a no-op; deny-everywhere must be Resource '*'")

    def test_read_scope_jreese_net_opens_exactly_one_bucket(self):
        new, _ = transform(live_shaped_policy(), "jreese-net")
        containment = [s for s in new["Statement"] if s.get("Sid") == CONTAINMENT_SID][0]
        self.assertEqual(
            containment["NotResource"],
            ["arn:aws:s3:::jreese-net", "arn:aws:s3:::jreese-net/*"])

    def test_containment_is_never_simply_deleted(self):
        """Deleting it would make AllowMinimalReads' Resource '*' live everywhere.

        That is a far larger widening than ENC-ISS-659 asks for, arrived at by
        REMOVING a statement -- exactly the silent consequence this record is about.
        """
        for scope in ("none", "jreese-net"):
            new, _ = transform(live_shaped_policy(), scope)
            self.assertEqual(
                len([s for s in new["Statement"] if s.get("Sid") == CONTAINMENT_SID]), 1,
                f"scope={scope}")

    def test_unrelated_statements_are_untouched(self):
        new, _ = transform(live_shaped_policy(), "none")
        sids = [s.get("Sid") for s in new["Statement"]]
        self.assertIn("AllowMinimalReads", sids)
        self.assertIn("DenyAllDynamoWrites", sids)

    def test_refuses_an_already_corrected_policy(self):
        already = {"Version": "2012-10-17", "Statement": [
            {"Sid": "AllowMinimalReads", "Effect": "Allow",
             "Action": "s3:GetObject", "Resource": "*"}]}
        with self.assertRaises(SystemExit):
            transform(already, "none")

    def test_refuses_when_the_deny_is_missing(self):
        drifted = live_shaped_policy()
        drifted["Statement"] = [
            s for s in drifted["Statement"] if s.get("Sid") != "DenyS3Elsewhere"]
        with self.assertRaises(SystemExit):
            transform(drifted, "none")

    def test_refuses_an_empty_document(self):
        with self.assertRaises(SystemExit):
            transform({"Version": "2012-10-17", "Statement": []}, "none")

    def test_handles_list_valued_resource_and_notresource(self):
        policy = live_shaped_policy()
        policy["Statement"][1]["Resource"] = [
            "arn:aws:s3:::harrisonfamily-frontend",
            "arn:aws:s3:::harrisonfamily-frontend/*"]
        policy["Statement"][2]["NotResource"] = [
            "arn:aws:s3:::harrisonfamily-frontend",
            "arn:aws:s3:::harrisonfamily-frontend/*"]
        new, notes = transform(policy, "none")
        self.assertTrue(any("R1 REMOVED" in n for n in notes))
        self.assertTrue(any("R2 REMOVED" in n for n in notes))


if __name__ == "__main__":
    unittest.main()


class TestAgainstAwsItself(unittest.TestCase):
    """ENC-TSK-P05 -- the check every test above structurally could not make.

    The rest of this file asserts the shape the tool emits, verified against the
    tool's own expectations: a declaration checked against itself. That is how
    read_scope=none shipped emitting a Deny that denied nothing, with a passing
    test named "denies s3 everywhere" pinning it.

    The correction is not a sharper assertion about the shape. It is to ask AWS.
    accessanalyzer:ValidatePolicy is reachable by enceladus-agent-cli
    unprivileged (verified live 2026-08-23), so this runs wherever the CLI is
    configured and skips cleanly where it is not.
    """

    BLOCKING_TYPES = {"ERROR", "SECURITY_WARNING"}
    BLOCKING_CODES = {"EMPTY_ARRAY_RESOURCE", "EMPTY_ARRAY_ACTION"}

    def _blocking_findings(self, document):
        import json
        import shutil
        import subprocess
        import tempfile

        if not shutil.which("aws"):
            return None
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(document, fh)
            path = fh.name
        proc = subprocess.run(
            ["aws", "accessanalyzer", "validate-policy",
             "--policy-document", f"file://{path}",
             "--policy-type", "IDENTITY_POLICY",
             "--region", "us-west-2", "--output", "json"],
            capture_output=True, text=True)
        if proc.returncode != 0:
            return None
        findings = json.loads(proc.stdout).get("findings", [])
        return [f for f in findings
                if f.get("findingType") in self.BLOCKING_TYPES
                or f.get("issueCode") in self.BLOCKING_CODES]

    def test_every_read_scope_produces_a_policy_aws_itself_accepts(self):
        for scope in ("none", "artifacts", "jreese-net"):
            with self.subTest(read_scope=scope):
                new, _ = transform(live_shaped_policy(), scope)
                blocking = self._blocking_findings(new)
                if blocking is None:
                    self.skipTest("AWS CLI unavailable or unauthorized")
                self.assertEqual(
                    blocking, [],
                    f"read_scope={scope} produced a policy AWS flags as blocking: "
                    f"{blocking}. A statement that does not affect the policy is "
                    f"not containment.")


class TestArtifactsScope(unittest.TestCase):
    def test_keeps_the_docstore_path_closed(self):
        """agent-documents/ objects must stay denied, or the raw-S3 route around
        governed documents.get reopens (ENC-ISS-640 class)."""
        new, _ = transform(live_shaped_policy(), "artifacts")
        stmt = [s for s in new["Statement"] if s.get("Sid") == CONTAINMENT_SID][0]
        self.assertIn("arn:aws:s3:::jreese-net/lambda-artifacts/*", stmt["NotResource"])
        self.assertNotIn(
            "arn:aws:s3:::jreese-net/*", stmt["NotResource"],
            "whole-bucket object read would expose agent-documents/ to raw S3")

    def test_keeps_the_bare_bucket_arn_so_a_missing_artifact_still_reports_404(self):
        """s3:ListBucket acts on the BUCKET. Without it S3 answers a missing key
        with 403 AccessDenied instead of 404 NoSuchKey, and the arm64 harness's
        point 1 routes a real artifact_missing FAIL into the permission_denied
        UNKNOWN branch -- losing the verdict its tri-state exists to carry."""
        new, _ = transform(live_shaped_policy(), "artifacts")
        stmt = [s for s in new["Statement"] if s.get("Sid") == CONTAINMENT_SID][0]
        self.assertIn("arn:aws:s3:::jreese-net", stmt["NotResource"])
