"""DVP-TSK-B43 (isolation W4l): the governance_update recompute nudge reaches THIS plane's recompute (no AWS).

Unset, RECOMPUTE_GOVERNANCE_LAMBDA_NAME defaulted to the prod function, so gamma's nudge invoked prod. 02-compute now
sets it per environment and grants the coordination role the matching invoke; the other plane learns of the write
from the prod content bucket's governance/live event (RecomputeGovernanceContentEventRule).
"""

import importlib.util
import os
import pathlib
import re
import sys
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
COMPUTE = HERE.parents[2] / "infrastructure" / "cloudformation" / "02-compute.yaml"
sys.path.insert(0, str(HERE.parent / "shared_layer" / "python"))
sys.path.insert(0, str(HERE))


def _load(env):
    spec = importlib.util.spec_from_file_location("coordination_lambda_b43", HERE / "lambda_function.py")
    mod = importlib.util.module_from_spec(spec)
    with mock.patch.dict(os.environ, env):
        sys.modules[spec.name] = mod
        spec.loader.exec_module(mod)
    return mod


def _block(text, name):
    """The resource's body with comment lines dropped."""
    m = re.search(r"(?ms)^  " + name + r":\n(.*?)(?=^  [A-Za-z0-9]+:\n|\Z)", text)
    assert m, name
    return "".join(ln for ln in m.group(1).splitlines(True) if not ln.lstrip().startswith("#"))


class RecomputeNudgeTargetTests(unittest.TestCase):
    def test_the_nudge_invokes_the_configured_function(self):
        mod = _load({"RECOMPUTE_GOVERNANCE_LAMBDA_NAME": "devops-recompute-governance-gamma"})
        client = mock.MagicMock()
        with mock.patch.object(mod, "_get_lambda_client", return_value=client):
            mod._trigger_governance_recompute_push("governance/live/agents.md")
        self.assertEqual(client.invoke.call_args.kwargs["FunctionName"], "devops-recompute-governance-gamma")
        self.assertEqual(client.invoke.call_args.kwargs["InvocationType"], "Event")


class RecomputeNudgeCloudFormationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = COMPUTE.read_text(encoding="utf-8")

    def test_function_names_its_own_plane_recompute(self):
        b = _block(self.text, "CoordinationApiFunction")
        self.assertIn('RECOMPUTE_GOVERNANCE_LAMBDA_NAME: !Sub "devops-recompute-governance${EnvironmentSuffix}"\n', b)
        self.assertIn('FunctionName: !Sub "devops-recompute-governance${EnvironmentSuffix}"',
                      _block(self.text, "RecomputeGovernanceFunction"))

    def test_role_may_invoke_exactly_that_function(self):
        b = _block(self.text, "CoordinationApiRole")
        stmt = b.split("Sid: InvokeRecomputeGovernanceNudge", 1)[1].split("- Sid:", 1)[0]
        self.assertIn("lambda:InvokeFunction", stmt)
        resources = re.findall(r'- !Sub "(arn:aws:lambda:[^"]+)"', stmt)
        self.assertEqual(resources, [
            "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:devops-recompute-governance${EnvironmentSuffix}"])


if __name__ == "__main__":
    unittest.main()
