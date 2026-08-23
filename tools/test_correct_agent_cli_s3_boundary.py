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
        """The conservative option must not widen anything."""
        new, _ = transform(live_shaped_policy(), "none")
        containment = [s for s in new["Statement"] if s.get("Sid") == CONTAINMENT_SID]
        self.assertEqual(len(containment), 1)
        self.assertEqual(containment[0]["NotResource"], [])
        self.assertEqual(containment[0]["Effect"], "Deny")

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
