"""ENC-TSK-S28-0A: eager boto3 client warm-up is skipped under SnapStart init (fresh credentials after restore).

Run: python3 -m pytest test_warm_clients_s28_0a.py -q
"""
from __future__ import annotations

import unittest
from unittest import mock

import lambda_function as m

_GETTERS = ("_get_ddb", "_get_events", "_get_sns", "_get_lambda_client",)


class WarmClientsSnapStartGuard(unittest.TestCase):
    def _run(self, env):
        calls = []
        patches = [mock.patch.object(m, g, side_effect=lambda g=g: calls.append(g)) for g in _GETTERS]
        for p in patches:
            p.start()
        try:
            with mock.patch.dict("os.environ", env, clear=False), self.assertLogs(m.logger, level="INFO") as cm:
                m._warm_clients()
        finally:
            for p in patches:
                p.stop()
        return calls, "\n".join(cm.output)

    def test_snap_start_skips_eager_build(self):
        calls, log = self._run({"AWS_LAMBDA_FUNCTION_NAME": "fn", "AWS_LAMBDA_INITIALIZATION_TYPE": "snap-start"})
        self.assertEqual(calls, [])
        self.assertIn("skipped (SnapStart init", log)

    def test_on_demand_builds_eagerly(self):
        env = {"AWS_LAMBDA_FUNCTION_NAME": "fn", "AWS_LAMBDA_INITIALIZATION_TYPE": "on-demand"}
        calls, log = self._run(env)
        self.assertEqual(sorted(calls), sorted(_GETTERS))
        self.assertIn("eager init-time build", log)


if __name__ == "__main__":
    unittest.main()
