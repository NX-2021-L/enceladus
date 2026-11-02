"""ENC-TSK-S14 (N4): FLOW_WEIGHT_REFRESH_ENABLED flag default by environment, noop, router."""
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import lambda_function as lf  # noqa: E402

_KEYS = ("FLOW_WEIGHT_REFRESH_ENABLED", "AWS_LAMBDA_FUNCTION_NAME", "ENVIRONMENT_SUFFIX")


def _env(**kw):
    base = {k: v for k, v in os.environ.items() if k not in _KEYS}
    base.update(kw)
    return mock.patch.dict(os.environ, base, clear=True)


class FlowWeightFlagS14(unittest.TestCase):
    def test_default_gamma_true(self):
        with _env(AWS_LAMBDA_FUNCTION_NAME="devops-graph-query-api-gamma"):
            self.assertTrue(lf._flow_weight_refresh_enabled())
        with _env(ENVIRONMENT_SUFFIX="-gamma"):
            self.assertTrue(lf._flow_weight_refresh_enabled())

    def test_default_prod_false(self):
        with _env(AWS_LAMBDA_FUNCTION_NAME="devops-graph-query-api"):
            self.assertFalse(lf._flow_weight_refresh_enabled())
        with _env():
            self.assertFalse(lf._flow_weight_refresh_enabled())

    def test_env_override_wins(self):
        with _env(AWS_LAMBDA_FUNCTION_NAME="devops-graph-query-api-gamma", FLOW_WEIGHT_REFRESH_ENABLED="false"):
            self.assertFalse(lf._flow_weight_refresh_enabled())
        with _env(AWS_LAMBDA_FUNCTION_NAME="devops-graph-query-api", FLOW_WEIGHT_REFRESH_ENABLED="true"):
            self.assertTrue(lf._flow_weight_refresh_enabled())

    def test_noop_when_disabled(self):
        with _env(FLOW_WEIGHT_REFRESH_ENABLED="false"), mock.patch.object(lf, "_get_neo4j_driver") as drv:
            out = lf._handle_refresh_flow_weight({"action": "refresh_flow_weight"})
        self.assertEqual(out, {"status": "noop", "reason": "FLOW_WEIGHT_REFRESH_ENABLED=false"})
        drv.assert_not_called()

    def test_router_dispatches_and_enabled_delegates(self):
        with _env(FLOW_WEIGHT_REFRESH_ENABLED="false"):
            out = lf.lambda_handler({"action": "refresh_flow_weight"}, None)
        self.assertEqual(out.get("status"), "noop")
        fake = mock.Mock(run_refresh=mock.Mock(return_value={"ok": True}))
        with _env(FLOW_WEIGHT_REFRESH_ENABLED="true"), \
                mock.patch.dict(sys.modules, {"flow_weight_refresh": fake}), \
                mock.patch.object(lf, "_get_neo4j_driver", return_value=object()), \
                mock.patch.object(lf, "_ensure_live_driver", side_effect=lambda d: d), \
                mock.patch.object(lf, "_get_s3", return_value=object()):
            out = lf.lambda_handler({"action": "refresh_flow_weight"}, None)
        self.assertEqual(out, {"ok": True})


if __name__ == "__main__":
    unittest.main()
