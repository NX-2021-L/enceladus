"""ENC-TSK-S83: fail-closed component use (off / observe / enforce) in checkout_service.

An unknown component id (absent from the registry) at checkout.task and
checkout.advance in each mode, plus registered-component semantics unchanged.
tracker_mutation is intentionally not covered: its role cannot read
component-registry, so task create/edit enforcement is out of this slice.
"""

import importlib.util
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared_layer", "python"))
_SPEC = importlib.util.spec_from_file_location(
    "checkout_lambda_s83", os.path.join(os.path.dirname(__file__), "lambda_function.py")
)
cl = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
sys.modules[_SPEC.name] = cl
_SPEC.loader.exec_module(cl)

LOG_PREFIX = "[COMPONENT-ENFORCE] mode=observe would_reject=true"
CREATED = "2026-11-15T06:00:00Z"  # at the epoch: not grandfathered
PRE_EPOCH = "2026-11-15T05:59:59Z"


def _ddb(items):
    def _side(TableName, Key):
        cid = Key["component_id"]["S"]
        meta = items.get(cid)
        if meta is None:
            return {}
        item = {
            "component_id": {"S": cid},
            "required_transition_type": {"S": "github_pr_deploy"},
        }
        if "lifecycle_status" in meta:
            item["lifecycle_status"] = {"S": meta["lifecycle_status"]}
        return {"Item": item}
    return _side


def _codes(resp):
    body = json.loads(resp["body"])
    err = body.get("error_envelope") or body.get("error") or {}
    return json.dumps(body), err


class ModeResolutionTests(unittest.TestCase):
    def test_values(self):
        for raw, want in [("off", "off"), ("observe", "observe"), ("enforce", "enforce"),
                          (" ENFORCE ", "enforce"), ("", "observe"), ("bogus", "observe")]:
            with mock.patch.object(cl, "COMPONENT_REGISTRY_ENFORCEMENT", raw):
                self.assertEqual(cl._component_registry_mode(), want, raw)

    def test_deployed_default_is_enforce(self):
        self.assertEqual(os.environ.get("COMPONENT_REGISTRY_ENFORCEMENT"), None)
        self.assertEqual(cl.COMPONENT_REGISTRY_ENFORCEMENT, "enforce")
        self.assertEqual(cl.COMPONENT_ENFORCEMENT_EPOCH, "2026-11-15T06:00:00Z")


class CheckoutTaskTests(unittest.TestCase):
    def _run(self, mode, components, registry):
        task = {"task_id": "ENC-TSK-TEST", "status": "open",
                "transition_type": "github_pr_deploy", "components": components,
                "created_at": CREATED}
        body = {"active_agent_session_id": "test-agent-session"}
        with mock.patch.object(cl, "COMPONENT_REGISTRY_ENFORCEMENT", mode), \
             mock.patch.object(cl, "_get_task", return_value=(200, task)), \
             mock.patch.object(cl._ddb, "get_item", side_effect=_ddb(registry)):
            with self.assertLogs(cl.logger, level="WARNING") as lg:
                try:
                    resp = cl._handle_checkout("enceladus", "ENC-TSK-TEST", body)
                except Exception:  # downstream of the gate; not under test
                    resp = None
                cl.logger.warning("sentinel")
        return resp, "\n".join(lg.output)

    def test_enforce_rejects_unknown_naming_id_and_propose(self):
        resp, _ = self._run("enforce", ["comp-ghost"], {})
        self.assertEqual(resp["statusCode"], 400)
        text, _ = _codes(resp)
        self.assertIn("COMPONENT_NOT_REGISTERED", text)
        self.assertIn("comp-ghost", text)
        self.assertIn("component.propose", text)

    def test_observe_logs_and_does_not_reject(self):
        resp, logs = self._run("observe", ["comp-ghost"], {})
        self.assertIn(LOG_PREFIX + " op=checkout.task task=ENC-TSK-TEST component=comp-ghost "
                      "caller=test-agent-session", logs)
        if resp is not None:
            self.assertNotIn("COMPONENT_NOT_REGISTERED", resp["body"])

    def test_off_is_silent_and_does_not_reject(self):
        resp, logs = self._run("off", ["comp-ghost"], {})
        self.assertNotIn("[COMPONENT-ENFORCE]", logs)
        if resp is not None:
            self.assertNotIn("COMPONENT_NOT_REGISTERED", resp["body"])

    def test_unrecognised_value_behaves_as_observe(self):
        resp, logs = self._run("nonsense", ["comp-ghost"], {})
        self.assertIn("[COMPONENT-ENFORCE] mode=observe", logs)
        if resp is not None:
            self.assertNotIn("COMPONENT_NOT_REGISTERED", resp["body"])

    def test_enforce_keeps_registered_semantics(self):
        reg = {"comp-arch": {"lifecycle_status": "archived"},
               "comp-prop": {"lifecycle_status": "proposed"}}
        resp, _ = self._run("enforce", ["comp-arch"], reg)
        self.assertEqual(resp["statusCode"], 404)
        resp, _ = self._run("enforce", ["comp-prop"], reg)
        self.assertEqual(resp["statusCode"], 400)
        self.assertIn("component_lifecycle_blocked", resp["body"])

    def test_enforce_registered_legacy_and_missing_lifecycle_pass_gate(self):
        reg = {"comp-ok": {}, "comp-legacy": {"lifecycle_status": "active"}}
        resp, _ = self._run("enforce", ["comp-ok", "comp-legacy"], reg)
        if resp is not None:
            self.assertNotIn("COMPONENT_NOT_REGISTERED", resp["body"])


class AdvanceTests(unittest.TestCase):
    def _run(self, mode, components, registry):
        task = {"record_id": "ENC-TSK-TEST", "components": components,
                "transition_type": "github_pr_deploy", "status": "in-progress",
                "active_agent_session": True, "active_agent_session_id": "sess-abc",
                "created_at": CREATED}
        body = {"target_status": "coding-complete", "provider": "test-agent",
                "transition_evidence": {}, "governance_hash": "h"}
        with mock.patch.object(cl, "COMPONENT_REGISTRY_ENFORCEMENT", mode), \
             mock.patch.object(cl, "_get_task", return_value=(200, task)), \
             mock.patch.object(cl._ddb, "get_item", side_effect=_ddb(registry)):
            with self.assertLogs(cl.logger, level="WARNING") as lg:
                try:
                    resp = cl._handle_advance("enceladus", "ENC-TSK-TEST", body)
                except Exception:  # downstream of the gate; not under test
                    resp = None
                cl.logger.warning("sentinel")
        return resp, "\n".join(lg.output)

    def test_enforce_rejects_unknown(self):
        resp, _ = self._run("enforce", ["comp-ghost"], {})
        self.assertEqual(resp["statusCode"], 400)
        self.assertIn("COMPONENT_NOT_REGISTERED", resp["body"])
        self.assertIn("comp-ghost", resp["body"])
        self.assertIn("component.propose", resp["body"])

    def test_observe_logs_and_does_not_reject(self):
        resp, logs = self._run("observe", ["comp-ghost"], {})
        self.assertIn(LOG_PREFIX + " op=checkout.advance task=ENC-TSK-TEST component=comp-ghost "
                      "caller=test-agent", logs)
        if resp is not None:
            self.assertNotIn("COMPONENT_NOT_REGISTERED", resp["body"])

    def test_off_is_silent_and_does_not_reject(self):
        resp, logs = self._run("off", ["comp-ghost"], {})
        self.assertNotIn("[COMPONENT-ENFORCE]", logs)
        if resp is not None:
            self.assertNotIn("COMPONENT_NOT_REGISTERED", resp["body"])

    def test_enforce_proposed_still_blocked_as_before(self):
        resp, _ = self._run("enforce", ["comp-prop"], {"comp-prop": {"lifecycle_status": "proposed"}})
        self.assertIn("component_not_approved", resp["body"])

    def test_transient_ddb_error_is_not_unknown(self):
        task = {"record_id": "ENC-TSK-TEST", "components": ["comp-x"],
                "transition_type": "github_pr_deploy", "status": "in-progress",
                "active_agent_session": True, "active_agent_session_id": "sess-abc",
                "created_at": CREATED}
        with mock.patch.object(cl, "COMPONENT_REGISTRY_ENFORCEMENT", "enforce"), \
             mock.patch.object(cl, "_get_task", return_value=(200, task)), \
             mock.patch.object(cl._ddb, "get_item", side_effect=RuntimeError("throttled")):
            try:
                resp = cl._handle_advance("enceladus", "ENC-TSK-TEST", {
                    "target_status": "coding-complete", "provider": "test-agent",
                    "transition_evidence": {}, "governance_hash": "h"})
            except Exception:
                resp = None
        if resp is not None:
            self.assertNotIn("COMPONENT_NOT_REGISTERED", resp["body"])


class EpochTests(unittest.TestCase):
    def _checkout(self, created_at, components, registry=None, mode="enforce"):
        task = {"task_id": "ENC-TSK-TEST", "status": "open",
                "transition_type": "github_pr_deploy", "components": components}
        if created_at is not None:
            task["created_at"] = created_at
        with mock.patch.object(cl, "COMPONENT_REGISTRY_ENFORCEMENT", mode), \
             mock.patch.object(cl, "_get_task", return_value=(200, task)), \
             mock.patch.object(cl._ddb, "get_item", side_effect=_ddb(registry or {})):
            with self.assertLogs(cl.logger, level="WARNING") as lg:
                try:
                    resp = cl._handle_checkout(
                        "enceladus", "ENC-TSK-TEST",
                        {"active_agent_session_id": "test-agent-session"})
                except Exception:
                    resp = None
                cl.logger.warning("sentinel")
        return resp, "\n".join(lg.output)

    def test_pre_epoch_unknown_passes_and_logs(self):
        resp, logs = self._checkout(PRE_EPOCH, ["comp-ghost"])
        self.assertIn("[COMPONENT-ENFORCE] mode=enforce grandfathered=true", logs)
        self.assertIn("component=comp-ghost", logs)
        if resp is not None:
            self.assertNotIn("COMPONENT_NOT_REGISTERED", resp["body"])

    def test_missing_created_at_is_grandfathered(self):
        resp, logs = self._checkout(None, ["comp-ghost"])
        self.assertIn("grandfathered=true", logs)
        if resp is not None:
            self.assertNotIn("COMPONENT_NOT_REGISTERED", resp["body"])

    def test_post_epoch_unknown_rejected_at_checkout(self):
        resp, logs = self._checkout("2026-11-16T00:00:00Z", ["comp-ghost"])
        self.assertEqual(resp["statusCode"], 400)
        self.assertIn("COMPONENT_NOT_REGISTERED", resp["body"])
        self.assertNotIn("grandfathered", logs)

    def test_post_epoch_unknown_rejected_at_advance(self):
        task = {"record_id": "ENC-TSK-TEST", "components": ["comp-ghost"],
                "transition_type": "github_pr_deploy", "status": "in-progress",
                "active_agent_session": True, "active_agent_session_id": "sess-abc",
                "created_at": "2026-11-16T00:00:00Z"}
        with mock.patch.object(cl, "COMPONENT_REGISTRY_ENFORCEMENT", "enforce"), \
             mock.patch.object(cl, "_get_task", return_value=(200, task)), \
             mock.patch.object(cl._ddb, "get_item", side_effect=_ddb({})):
            resp = cl._handle_advance("enceladus", "ENC-TSK-TEST", {
                "target_status": "coding-complete", "provider": "test-agent",
                "transition_evidence": {}, "governance_hash": "h"})
        self.assertEqual(resp["statusCode"], 400)
        self.assertIn("COMPONENT_NOT_REGISTERED", resp["body"])

    def test_registered_component_passes_post_epoch(self):
        resp, logs = self._checkout(CREATED, ["comp-ok"], {"comp-ok": {}})
        self.assertNotIn("[COMPONENT-ENFORCE]", logs)
        if resp is not None:
            self.assertNotIn("COMPONENT_NOT_REGISTERED", resp["body"])

    def test_json_string_components_parsed(self):
        self.assertEqual(cl._task_components({"components": '["comp-x", "comp-y"]'}),
                         ["comp-x", "comp-y"])
        self.assertEqual(cl._task_components({"components": "comp-x"}), ["comp-x"])
        self.assertEqual(cl._task_components({"components": ["comp-x"]}), ["comp-x"])
        self.assertEqual(cl._task_components({}), [])
        resp, _ = self._checkout(CREATED, '["comp-ghost"]')
        self.assertEqual(resp["statusCode"], 400)
        self.assertIn("comp-ghost", resp["body"])
        self.assertNotIn('"["', resp["body"])

    def test_epoch_override_moves_the_boundary(self):
        with mock.patch.object(cl, "COMPONENT_ENFORCEMENT_EPOCH", "2027-01-01T00:00:00Z"):
            resp, logs = self._checkout("2026-12-01T00:00:00Z", ["comp-ghost"])
        self.assertIn("grandfathered=true", logs)
        if resp is not None:
            self.assertNotIn("COMPONENT_NOT_REGISTERED", resp["body"])

    def test_env_overrides_read_at_import(self):
        env = {"COMPONENT_REGISTRY_ENFORCEMENT": "observe",
               "COMPONENT_ENFORCEMENT_EPOCH": "2030-01-01T00:00:00Z"}
        with mock.patch.dict(os.environ, env):
            spec = importlib.util.spec_from_file_location("cl_env_s85", _SPEC.origin)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
        self.assertEqual(mod.COMPONENT_REGISTRY_ENFORCEMENT, "observe")
        self.assertEqual(mod.COMPONENT_ENFORCEMENT_EPOCH, "2030-01-01T00:00:00Z")


if __name__ == "__main__":
    unittest.main()
