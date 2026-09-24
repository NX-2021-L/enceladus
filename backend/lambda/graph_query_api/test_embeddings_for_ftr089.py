"""Unit tests for ENC-FTR-089 / ENC-TSK-I89 raw-embedding egress.

Exercises the admin-scoped `search_type=embeddings_for` handler in
graph_query_api without requiring Neo4j or Bedrock:

  - IAM scope gating (AC-2): internal key + admin-tier / io-dev-admin Cognito
    tokens accepted; standard/elevated/observe and anonymous callers -> 403.
  - Response shape (AC-1/AC-3/AC-5): 256-dim vectors per record_id, an N x 256
    `matrix` supporting np.mean(matrix, axis=0), no nulls for resolved records.
  - record_ids parsing (csv, multiValue, dedupe), bounds, and required params.
"""

from __future__ import annotations

import base64
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import lambda_function as lf  # noqa: E402


def _b64url(payload: dict) -> str:
    raw = json.dumps(payload).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _jwt(claims: dict) -> str:
    return f"{_b64url({'alg': 'RS256', 'typ': 'JWT'})}.{_b64url(claims)}.sig"


class _FakeSession:
    def __init__(self, records):
        self._records = records

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def run(self, _cypher, **_kwargs):
        return list(self._records)


class _FakeDriver:
    def __init__(self, records):
        self._records = records

    def session(self):
        return _FakeSession(self._records)

    def verify_connectivity(self):
        return True


def _vec(seed: float):
    return [seed + i * 0.0 for i in range(lf.EMBEDDING_EGRESS_DIMENSIONS)]


class _EmbeddingsForTestBase(unittest.TestCase):
    def setUp(self):
        self._orig_driver = lf._get_neo4j_driver
        self._orig_key = lf.COORDINATION_INTERNAL_API_KEY
        lf.COORDINATION_INTERNAL_API_KEY = "test-internal-key"

    def tearDown(self):
        lf._get_neo4j_driver = self._orig_driver
        lf.COORDINATION_INTERNAL_API_KEY = self._orig_key

    def _install_driver(self, records):
        lf._get_neo4j_driver = lambda: _FakeDriver(records)

    @staticmethod
    def _event(qs=None, headers=None, multi=None):
        return {
            "requestContext": {"http": {"method": "GET"}},
            "rawPath": "/api/v1/tracker/graphsearch",
            "queryStringParameters": qs or {},
            "multiValueQueryStringParameters": multi or {},
            "headers": headers or {},
        }

    @staticmethod
    def _body(resp):
        return json.loads(resp["body"])


class TestEgressAuthGating(_EmbeddingsForTestBase):
    def setUp(self):
        super().setUp()
        self._install_driver([
            {"record_id": "ENC-TSK-001", "embedding": _vec(0.1), "labels": ["Task"]},
        ])

    def _call(self, headers):
        event = self._event(
            qs={"project_id": "enceladus", "record_ids": "ENC-TSK-001"},
            headers=headers,
        )
        return lf._handle_embeddings_for(event)

    def test_internal_key_accepted(self):
        resp = self._call({"X-Coordination-Internal-Key": "test-internal-key"})
        self.assertEqual(resp["statusCode"], 200)

    def test_admin_tier_accepted(self):
        token = _jwt({"enc:agent_tier": "admin"})
        resp = self._call({"Authorization": f"Bearer {token}"})
        self.assertEqual(resp["statusCode"], 200)

    def test_io_dev_admin_group_accepted(self):
        token = _jwt({"cognito:groups": ["io-dev-admin", "viewers"]})
        resp = self._call({"Authorization": f"Bearer {token}"})
        self.assertEqual(resp["statusCode"], 200)

    def test_admin_tier_via_authorizer_claims(self):
        event = self._event(
            qs={"project_id": "enceladus", "record_ids": "ENC-TSK-001"},
            headers={},
        )
        event["requestContext"]["authorizer"] = {"jwt": {"claims": {"enc:agent_tier": "admin"}}}
        resp = lf._handle_embeddings_for(event)
        self.assertEqual(resp["statusCode"], 200)

    def test_standard_agent_rejected_403(self):
        token = _jwt({"enc:agent_tier": "standard"})
        resp = self._call({"Authorization": f"Bearer {token}"})
        self.assertEqual(resp["statusCode"], 403)
        self.assertEqual(self._body(resp)["error_envelope"]["code"], "PERMISSION_DENIED")

    def test_elevated_agent_rejected_403(self):
        token = _jwt({"enc:agent_tier": "elevated"})
        resp = self._call({"Authorization": f"Bearer {token}"})
        self.assertEqual(resp["statusCode"], 403)

    def test_observe_agent_rejected_403(self):
        token = _jwt({"enc:agent_tier": "observe"})
        resp = self._call({"Authorization": f"Bearer {token}"})
        self.assertEqual(resp["statusCode"], 403)

    def test_anonymous_rejected_403(self):
        resp = self._call({})
        self.assertEqual(resp["statusCode"], 403)

    def test_wrong_internal_key_rejected_403(self):
        resp = self._call({"X-Coordination-Internal-Key": "wrong-key"})
        self.assertEqual(resp["statusCode"], 403)


class TestEgressResponseShape(_EmbeddingsForTestBase):
    def _admin_headers(self):
        return {"X-Coordination-Internal-Key": "test-internal-key"}

    def test_three_vectors_length_256_no_nulls(self):
        ids = ["ENC-TSK-001", "ENC-ISS-002", "ENC-FTR-003"]
        self._install_driver([
            {"record_id": ids[0], "embedding": _vec(0.1), "labels": ["Task"]},
            {"record_id": ids[1], "embedding": _vec(0.2), "labels": ["Issue"]},
            {"record_id": ids[2], "embedding": _vec(0.3), "labels": ["Feature"]},
        ])
        event = self._event(
            qs={"project_id": "enceladus", "record_ids": ",".join(ids)},
            headers=self._admin_headers(),
        )
        resp = lf._handle_embeddings_for(event)
        body = self._body(resp)
        self.assertEqual(resp["statusCode"], 200)
        self.assertEqual(body["returned_count"], 3)
        self.assertEqual(body["dimension"], 256)
        self.assertEqual(body["model_id"], "amazon.titan-embed-text-v2:0")
        self.assertEqual(len(body["embeddings"]), 3)
        self.assertEqual(body["missing"], [])
        for item in body["embeddings"]:
            self.assertIsNotNone(item["embedding"])
            self.assertEqual(len(item["embedding"]), 256)
            self.assertEqual(item["dimension"], 256)

    def test_matrix_supports_centroid_mean(self):
        ids = ["A", "B"]
        self._install_driver([
            {"record_id": "A", "embedding": [1.0] * 256, "labels": ["Task"]},
            {"record_id": "B", "embedding": [3.0] * 256, "labels": ["Task"]},
        ])
        event = self._event(
            qs={"project_id": "enceladus", "record_ids": ",".join(ids)},
            headers=self._admin_headers(),
        )
        body = self._body(lf._handle_embeddings_for(event))
        matrix = body["matrix"]
        self.assertEqual(len(matrix), 2)
        self.assertEqual(len(matrix[0]), 256)
        # np.mean(matrix, axis=0) equivalent — column-wise mean is (1+3)/2 = 2.0.
        centroid = [sum(col) / len(col) for col in zip(*matrix)]
        self.assertEqual(len(centroid), 256)
        self.assertTrue(all(abs(v - 2.0) < 1e-9 for v in centroid))

    def test_missing_records_excluded_from_matrix(self):
        self._install_driver([
            {"record_id": "A", "embedding": _vec(0.1), "labels": ["Task"]},
            # B has no stored embedding (null vector).
            {"record_id": "B", "embedding": None, "labels": ["Task"]},
        ])
        event = self._event(
            qs={"project_id": "enceladus", "record_ids": "A,B,C"},
            headers=self._admin_headers(),
        )
        body = self._body(lf._handle_embeddings_for(event))
        self.assertEqual(body["returned_count"], 1)
        self.assertEqual(sorted(body["missing"]), ["B", "C"])
        self.assertEqual(len(body["matrix"]), 1)

    def test_wrong_dimension_treated_as_missing(self):
        self._install_driver([
            {"record_id": "A", "embedding": [0.1, 0.2, 0.3], "labels": ["Task"]},
        ])
        event = self._event(
            qs={"project_id": "enceladus", "record_ids": "A"},
            headers=self._admin_headers(),
        )
        body = self._body(lf._handle_embeddings_for(event))
        self.assertEqual(body["returned_count"], 0)
        self.assertEqual(body["missing"], ["A"])


class TestEgressInputParsing(_EmbeddingsForTestBase):
    def _admin_headers(self):
        return {"X-Coordination-Internal-Key": "test-internal-key"}

    def test_missing_project_id(self):
        self._install_driver([])
        resp = lf._handle_embeddings_for(
            self._event(qs={"record_ids": "A"}, headers=self._admin_headers())
        )
        self.assertEqual(resp["statusCode"], 400)

    def test_missing_record_ids(self):
        self._install_driver([])
        resp = lf._handle_embeddings_for(
            self._event(qs={"project_id": "enceladus"}, headers=self._admin_headers())
        )
        self.assertEqual(resp["statusCode"], 400)

    def test_record_ids_dedupe_and_csv(self):
        ids = lf._parse_egress_record_ids(
            self._event(qs={"record_ids": "A, B ,A,, C"})
        )
        self.assertEqual(ids, ["A", "B", "C"])

    def test_record_ids_multivalue(self):
        ids = lf._parse_egress_record_ids(
            self._event(multi={"record_ids": ["A,B", "C"]})
        )
        self.assertEqual(ids, ["A", "B", "C"])

    def test_singular_record_id_supported(self):
        ids = lf._parse_egress_record_ids(self._event(qs={"record_id": "ENC-TSK-009"}))
        self.assertEqual(ids, ["ENC-TSK-009"])

    def test_too_many_record_ids_rejected(self):
        many = ",".join(f"ENC-TSK-{i:04d}" for i in range(lf.MAX_EMBEDDING_EGRESS_RECORD_IDS + 1))
        self._install_driver([])
        resp = lf._handle_embeddings_for(
            self._event(qs={"project_id": "enceladus", "record_ids": many}, headers=self._admin_headers())
        )
        self.assertEqual(resp["statusCode"], 400)


class TestEgressRouting(_EmbeddingsForTestBase):
    def test_lambda_handler_routes_embeddings_for(self):
        self._install_driver([
            {"record_id": "ENC-TSK-001", "embedding": _vec(0.5), "labels": ["Task"]},
        ])
        event = self._event(
            qs={"search_type": "embeddings_for", "project_id": "enceladus", "record_ids": "ENC-TSK-001"},
            headers={"X-Coordination-Internal-Key": "test-internal-key"},
        )
        resp = lf.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 200)
        body = self._body(resp)
        self.assertEqual(body["returned_count"], 1)

    def test_lambda_handler_standard_token_403(self):
        self._install_driver([
            {"record_id": "ENC-TSK-001", "embedding": _vec(0.5), "labels": ["Task"]},
        ])
        token = _jwt({"enc:agent_tier": "standard"})
        event = self._event(
            qs={"search_type": "embeddings_for", "project_id": "enceladus", "record_ids": "ENC-TSK-001"},
            headers={"Authorization": f"Bearer {token}"},
        )
        resp = lf.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 403)


if __name__ == "__main__":
    unittest.main()
