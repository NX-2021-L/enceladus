"""ENC-TSK-Q46 AC-3: the HTTP hybrid response carries corroboration_alpha and s_top."""

from __future__ import annotations

import json
import unittest
from unittest import mock

import lambda_function as lf  # noqa: E402
from test_hybrid_fields_compact_q49 import _fake_hybrid_result


def _call(**extra):
    qs = {"search_type": "hybrid", "project_id": "enceladus", "query": "q", "anchor_record_id": "ENC-TSK-1", "top_n": "5"}
    qs.update(extra)
    result = _fake_hybrid_result()
    result["corroboration_alpha"] = 0.02
    result["s_top"] = 0.0323
    with mock.patch.object(lf, "_get_neo4j_driver", return_value=object()), \
         mock.patch.dict(lf.SEARCH_HANDLERS, {"hybrid": lambda d, p, q: result}):
        resp = lf._handle_search({"queryStringParameters": qs})
    return json.loads(resp["body"])


class TestAlphaPassthrough(unittest.TestCase):
    def test_full_response_carries_bound_inputs(self):
        body = _call()
        self.assertEqual(body["corroboration_alpha"], 0.02)
        self.assertEqual(body["s_top"], 0.0323)

    def test_compact_response_keeps_bound_inputs(self):
        body = _call(fields="compact")
        self.assertEqual(body["corroboration_alpha"], 0.02)
        self.assertEqual(body["s_top"], 0.0323)


if __name__ == "__main__":
    unittest.main()
