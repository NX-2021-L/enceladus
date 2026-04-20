"""Tests for coordination_api io-only lifecycle handlers (ENC-TSK-F40 AC[1f]).

_handle_components_revert / _handle_components_deprecate / _handle_components_restore
all require Cognito authentication; internal-key callers must receive 403 per
DOC-546B896390EA §3.3 authority matrix. Revert is the atomic-archive path and
must write lifecycle_status=archived alongside reverted_at + reverted_reason +
archived_at in a single UpdateExpression (DD-2).
"""

import importlib.util
import json
import os
import sys
import unittest
from unittest import mock


sys.path.insert(0, os.path.dirname(__file__))
_SPEC = importlib.util.spec_from_file_location(
    "coordination_lambda",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
coordination_lambda = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
sys.modules[_SPEC.name] = coordination_lambda
_SPEC.loader.exec_module(coordination_lambda)


INTERNAL_CLAIMS = {"auth_mode": "internal-key", "sub": "agent"}
IO_CLAIMS = {
    "auth_mode": "cognito",
    "sub": "user-sub",
    "email": "io@example.com",
    "cognito:username": "io",
}


def _event(body):
    return {"httpMethod": "POST", "body": json.dumps(body or {})}


class _TCE(Exception):
    """Stand-in for ddb.exceptions.ConditionalCheckFailedException."""


class ComponentDeprecateTests(unittest.TestCase):

    def setUp(self):
        coordination_lambda._COMPONENT_TRANSITION_TABLE_CACHE = None
        self._flag = mock.patch.object(
            coordination_lambda, "ENABLE_COMPONENT_PROPOSAL", True
        )
        self._flag.start()

    def tearDown(self):
        self._flag.stop()

    def test_internal_key_returns_403(self):
        resp = coordination_lambda._handle_components_deprecate(
            "comp-x", _event({}), INTERNAL_CLAIMS
        )
        self.assertEqual(resp["statusCode"], 403)

    def test_unknown_source_status_returns_409(self):
        """Deprecate is not valid from 'approved' — allowed sources are
        {production, development, code-red} per §3.3."""
        with mock.patch.object(
            coordination_lambda,
            "_get_component_record",
            return_value={"component_id": "comp-x", "lifecycle_status": "approved"},
        ):
            resp = coordination_lambda._handle_components_deprecate(
                "comp-x", _event({"reason": "obsolete"}), IO_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 409)
        body = json.loads(resp["body"])
        self.assertEqual(body["error_envelope"]["code"], "LIFECYCLE_TRANSITION_UNMET")

    def test_happy_path_from_production_writes_deprecated(self):
        fake = mock.MagicMock()
        fake.exceptions.ConditionalCheckFailedException = _TCE
        fake.update_item.return_value = {
            "Attributes": {
                "component_id": {"S": "comp-x"},
                "lifecycle_status": {"S": "deprecated"},
            }
        }
        with mock.patch.object(
            coordination_lambda,
            "_get_component_record",
            return_value={"component_id": "comp-x", "lifecycle_status": "production"},
        ), mock.patch.object(
            coordination_lambda, "_get_ddb", return_value=fake
        ):
            resp = coordination_lambda._handle_components_deprecate(
                "comp-x", _event({"reason": "replaced by comp-x-v2"}), IO_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["lifecycle_status"], "deprecated")
        self.assertEqual(body["previous_lifecycle_status"], "production")
        self.assertEqual(body["deprecated_by"], "io@example.com")


class ComponentRestoreTests(unittest.TestCase):

    def setUp(self):
        self._flag = mock.patch.object(
            coordination_lambda, "ENABLE_COMPONENT_PROPOSAL", True
        )
        self._flag.start()

    def tearDown(self):
        self._flag.stop()

    def test_internal_key_returns_403(self):
        resp = coordination_lambda._handle_components_restore(
            "comp-x", _event({}), INTERNAL_CLAIMS
        )
        self.assertEqual(resp["statusCode"], 403)

    def test_non_deprecated_source_returns_409(self):
        """Only deprecated may be restored (target: production) per §3.3."""
        with mock.patch.object(
            coordination_lambda,
            "_get_component_record",
            return_value={"component_id": "comp-x", "lifecycle_status": "production"},
        ):
            resp = coordination_lambda._handle_components_restore(
                "comp-x", _event({}), IO_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 409)

    def test_happy_path_writes_production(self):
        fake = mock.MagicMock()
        fake.exceptions.ConditionalCheckFailedException = _TCE
        fake.update_item.return_value = {
            "Attributes": {
                "component_id": {"S": "comp-x"},
                "lifecycle_status": {"S": "production"},
            }
        }
        with mock.patch.object(
            coordination_lambda,
            "_get_component_record",
            return_value={"component_id": "comp-x", "lifecycle_status": "deprecated"},
        ), mock.patch.object(
            coordination_lambda, "_get_ddb", return_value=fake
        ):
            resp = coordination_lambda._handle_components_restore(
                "comp-x", _event({}), IO_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["lifecycle_status"], "production")
        self.assertEqual(body["previous_lifecycle_status"], "deprecated")


class ComponentRevertTests(unittest.TestCase):

    def setUp(self):
        self._flag = mock.patch.object(
            coordination_lambda, "ENABLE_COMPONENT_PROPOSAL", True
        )
        self._flag.start()

    def tearDown(self):
        self._flag.stop()

    def test_internal_key_returns_403(self):
        resp = coordination_lambda._handle_components_revert(
            "comp-x", _event({"reverted_reason": "some long reason here"}),
            INTERNAL_CLAIMS,
        )
        self.assertEqual(resp["statusCode"], 403)

    def test_short_reason_returns_400(self):
        resp = coordination_lambda._handle_components_revert(
            "comp-x", _event({"reverted_reason": "short"}), IO_CLAIMS
        )
        self.assertEqual(resp["statusCode"], 400)

    def test_archived_source_returns_404_opacity(self):
        """Already-archived records return 404 per opacity contract."""
        with mock.patch.object(
            coordination_lambda,
            "_get_component_record",
            return_value={"component_id": "comp-x", "lifecycle_status": "archived"},
        ):
            resp = coordination_lambda._handle_components_revert(
                "comp-x",
                _event({"reverted_reason": "some long reason here"}),
                IO_CLAIMS,
            )
        self.assertEqual(resp["statusCode"], 404)

    def test_atomic_archive_writes_all_fields(self):
        """Revert writes lifecycle_status=archived + reverted_at + reverted_reason
        + archived_at atomically in one update expression (DD-2)."""
        fake = mock.MagicMock()
        fake.exceptions.ConditionalCheckFailedException = _TCE
        fake.update_item.return_value = {
            "Attributes": {
                "component_id": {"S": "comp-x"},
                "lifecycle_status": {"S": "archived"},
            }
        }
        with mock.patch.object(
            coordination_lambda,
            "_get_component_record",
            return_value={"component_id": "comp-x", "lifecycle_status": "proposed"},
        ), mock.patch.object(
            coordination_lambda, "_get_ddb", return_value=fake
        ):
            resp = coordination_lambda._handle_components_revert(
                "comp-x",
                _event({"reverted_reason": "out of scope per io review"}),
                IO_CLAIMS,
            )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["lifecycle_status"], "archived")
        self.assertEqual(body["reverted_reason"], "out of scope per io review")
        self.assertEqual(body["previous_lifecycle_status"], "proposed")
        self.assertIn("archived_at", body)
        self.assertIn("reverted_at", body)

        # Single UpdateExpression contains all four atomic writes.
        kwargs = fake.update_item.call_args.kwargs
        expr = kwargs["UpdateExpression"]
        self.assertIn("#ls = :archived", expr)
        self.assertIn("archived_at = :now", expr)
        self.assertIn("reverted_at = :now", expr)
        self.assertIn("reverted_reason = :reason", expr)


if __name__ == "__main__":
    unittest.main()
