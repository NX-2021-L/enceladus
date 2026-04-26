"""F50/AC-5 — Regression tests for the fail-loud required_transition_type path.

Exercises the three guarantees required by ENC-TSK-F50 AC-5:

    (a) checkout.task against a component whose registry record lacks
        `required_transition_type` returns HTTP 500 with
        `error_envelope.code == "COMPONENT_MISCONFIGURED"`.
    (b) checkout.advance against the same condition returns the same envelope.
    (c) The previous silent-default path
        (`item.get("transition_type", {}).get("S", "github_pr_deploy")`)
        is demonstrably removed from `_get_required_transition_type`.

Related: ENC-ISS-270 (the deadlock this remediation closes),
DOC-240A67973B13 (governance review document driving the backfill).
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import unittest
from unittest.mock import patch


_SPEC = importlib.util.spec_from_file_location(
    "checkout_service",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
checkout_service = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
_SPEC.loader.exec_module(checkout_service)


def _registry_item(*, component_id: str, required_value: str | None):
    """Shape a DynamoDB ``get_item`` response for a component registry row.

    ``required_value`` is the value stamped into the ``required_transition_type``
    attribute. Pass ``None`` to simulate a row whose backfill has not landed.
    """

    item: dict = {
        "component_id": {"S": component_id},
        # Legacy transition_type remains on the row post-F50 for back-compat
        # documentation. It MUST NOT be read by the strictness path.
        "transition_type": {"S": "github_pr_deploy"},
    }
    if required_value is not None:
        item["required_transition_type"] = {"S": required_value}
    return {"Item": item}


class ComponentMisconfiguredHelperTests(unittest.TestCase):
    """Unit coverage of ``_get_required_transition_type`` itself."""

    def test_missing_required_transition_type_raises(self):
        with patch.object(
            checkout_service._ddb,
            "get_item",
            return_value=_registry_item(
                component_id="comp-checkout-service", required_value=None
            ),
        ):
            with self.assertRaises(checkout_service.ComponentMisconfiguredError) as ctx:
                checkout_service._get_required_transition_type(["comp-checkout-service"])
        self.assertEqual(ctx.exception.component_id, "comp-checkout-service")
        self.assertEqual(ctx.exception.reason, "missing")

    def test_invalid_enum_value_raises_with_reason(self):
        with patch.object(
            checkout_service._ddb,
            "get_item",
            return_value=_registry_item(
                component_id="comp-coordination-api",
                required_value="definitely-not-a-real-type",
            ),
        ):
            with self.assertRaises(checkout_service.ComponentMisconfiguredError) as ctx:
                checkout_service._get_required_transition_type(["comp-coordination-api"])
        self.assertEqual(ctx.exception.component_id, "comp-coordination-api")
        self.assertEqual(ctx.exception.reason, "invalid_value")
        self.assertEqual(ctx.exception.bad_value, "definitely-not-a-real-type")

    def test_valid_required_transition_type_returns_most_restrictive(self):
        """With two components (strict + permissive), the strict rank wins."""

        def fake_get_item(**kwargs):
            cid = kwargs["Key"]["component_id"]["S"]
            mapping = {
                "comp-checkout-service": "github_pr_deploy",
                "comp-governance-docs": "no_code",
            }
            return _registry_item(component_id=cid, required_value=mapping[cid])

        with patch.object(checkout_service._ddb, "get_item", side_effect=fake_get_item):
            result = checkout_service._get_required_transition_type(
                ["comp-checkout-service", "comp-governance-docs"]
            )
        # github_pr_deploy has rank 0 (strictest) and wins.
        self.assertEqual(result, "github_pr_deploy")

    def test_missing_component_id_fails_open_with_warning(self):
        """A stale task.components entry (no registry row) must not hard block."""
        with patch.object(checkout_service._ddb, "get_item", return_value={}):
            result = checkout_service._get_required_transition_type(
                ["comp-does-not-exist"]
            )
        self.assertIsNone(result)


class CheckoutHandlerCOMPONENT_MISCONFIGUREDTests(unittest.TestCase):
    """End-to-end coverage through ``_handle_checkout`` and ``_handle_advance``."""

    def _envelope(self, response: dict) -> dict:
        return json.loads(response["body"])

    @patch.object(checkout_service, "_get_task")
    def test_handle_checkout_surfaces_component_misconfigured_envelope(self, mock_get_task):
        mock_get_task.return_value = (
            200,
            {
                "status": "open",
                "transition_type": "no_code",
                "components": ["comp-checkout-service"],
            },
        )
        with patch.object(
            checkout_service._ddb,
            "get_item",
            return_value=_registry_item(
                component_id="comp-checkout-service", required_value=None
            ),
        ):
            response = checkout_service._handle_checkout(
                "enceladus",
                "ENC-TSK-FAKE",
                {"active_agent_session_id": "test-session"},
            )

        self.assertEqual(response["statusCode"], 500)
        body = self._envelope(response)
        envelope = body["error_envelope"]
        self.assertEqual(envelope["code"], "COMPONENT_MISCONFIGURED")
        self.assertFalse(envelope["retryable"])
        details = envelope["details"]
        self.assertEqual(details["component_id"], "comp-checkout-service")
        self.assertEqual(details["reason"], "missing")
        self.assertIn(
            "jreese.net/components/comp-checkout-service", details["remediation_url"]
        )
        self.assertIn("required_transition_type", details["remediation_guidance"])
        self.assertIn("DOC-240A67973B13", details["rule_citation"])

    @patch.object(checkout_service, "_get_task")
    def test_handle_advance_surfaces_component_misconfigured_envelope(self, mock_get_task):
        mock_get_task.return_value = (
            200,
            {
                "status": "in-progress",
                "transition_type": "no_code",
                "active_agent_session": True,
                "active_agent_session_id": "test-session",
                "components": ["comp-coordination-api"],
                "checkout_transition_type": "no_code",
            },
        )
        with patch.object(
            checkout_service._ddb,
            "get_item",
            return_value=_registry_item(
                component_id="comp-coordination-api", required_value=None
            ),
        ):
            response = checkout_service._handle_advance(
                "enceladus",
                "ENC-TSK-FAKE",
                {
                    "target_status": "coding-complete",
                    "provider": "test-session",
                    "active_agent_session_id": "test-session",
                    "governance_hash": "hash",
                },
            )

        self.assertEqual(response["statusCode"], 500)
        body = self._envelope(response)
        envelope = body["error_envelope"]
        self.assertEqual(envelope["code"], "COMPONENT_MISCONFIGURED")
        details = envelope["details"]
        self.assertEqual(details["component_id"], "comp-coordination-api")
        self.assertEqual(details["reason"], "missing")


class SilentDefaultRemovalTests(unittest.TestCase):
    """F50/AC-5(c) — prove the old silent-default string is gone from the helper."""

    def test_get_required_transition_type_has_no_github_pr_deploy_fallback_literal(self):
        """``_get_required_transition_type`` must not carry the old fallback default.

        Regression guard: the pre-F50 helper read
        ``item.get("transition_type", {}).get("S", "github_pr_deploy")`` which
        silently coerced missing rows to strict-rank-0. The new helper reads
        ``required_transition_type`` and raises
        :class:`ComponentMisconfiguredError` on missing. The literal fallback
        form must not reappear.
        """
        import inspect

        source = inspect.getsource(checkout_service._get_required_transition_type)
        # The old silent fallback included the string "github_pr_deploy" as a
        # literal default in .get(). If the helper needs to mention the type
        # name in comments or log messages it should do so outside that
        # fallback idiom.
        forbidden_patterns = [
            r'\.get\(\s*"transition_type"\s*,\s*\{\}\s*\)\.get\(\s*"S"\s*,\s*"github_pr_deploy"\s*\)',
            r"\.get\(\s*'transition_type'\s*,\s*\{\}\s*\)\.get\(\s*'S'\s*,\s*'github_pr_deploy'\s*\)",
        ]
        for pattern in forbidden_patterns:
            self.assertIsNone(
                re.search(pattern, source),
                f"Silent-default pattern {pattern!r} reappeared in "
                "_get_required_transition_type; re-read F50/AC-3 before reverting.",
            )


if __name__ == "__main__":
    unittest.main()
