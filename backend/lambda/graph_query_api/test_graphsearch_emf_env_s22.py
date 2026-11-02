"""ENC-TSK-S22 (PLN-103 F6): Environment dimension and per-environment EMF default."""

from __future__ import annotations

import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import lambda_function as lf  # noqa: E402

REC = {"search_type": "hybrid", "duration_ms": 10, "pathway_status": "ok"}
_CLEAR = ("GRAPHSEARCH_EMF_ENABLED", "AWS_LAMBDA_FUNCTION_NAME", "ENVIRONMENT_SUFFIX")


def _emit(env):
    buf = io.StringIO()
    with mock.patch.dict(os.environ, env, clear=False), redirect_stdout(buf):
        for k in _CLEAR:
            if k not in env:
                os.environ.pop(k, None)
        lf._emit_graphsearch_emf(REC)
    out = buf.getvalue().strip()
    return json.loads(out) if out else None


class EmfEnvironmentTests(unittest.TestCase):
    def test_prod_default_on_with_prod_dimension(self):
        o = _emit({"AWS_LAMBDA_FUNCTION_NAME": "devops-graph-query-api"})
        self.assertEqual(o["Environment"], "prod")
        self.assertEqual(o["_aws"]["CloudWatchMetrics"][0]["Dimensions"], [["SearchType", "Environment"]])

    def test_gamma_default_off(self):
        self.assertIsNone(_emit({"AWS_LAMBDA_FUNCTION_NAME": "devops-graph-query-api-gamma"}))
        self.assertIsNone(_emit({"ENVIRONMENT_SUFFIX": "-gamma"}))

    def test_gamma_override_on_carries_gamma_dimension(self):
        o = _emit({"AWS_LAMBDA_FUNCTION_NAME": "devops-graph-query-api-gamma", "GRAPHSEARCH_EMF_ENABLED": "true"})
        self.assertEqual(o["Environment"], "gamma")

    def test_prod_override_off(self):
        self.assertIsNone(_emit({"AWS_LAMBDA_FUNCTION_NAME": "devops-graph-query-api", "GRAPHSEARCH_EMF_ENABLED": "off"}))


if __name__ == "__main__":
    unittest.main()
