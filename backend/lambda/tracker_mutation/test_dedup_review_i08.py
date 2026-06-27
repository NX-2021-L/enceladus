"""ENC-TSK-I08 (Dedup P4): tier-review surface unit tests.

Pure-logic coverage in the established tracker_mutation house style (no DDB
round-trip): the tier-ladder mapping from I06 verdicts (DOC-DF651F07D5C2 §5),
conservative cluster-tier derivation, the hard-floor homogeneity guard (§4.0),
proposal assembly (T-MID plan / T-LOW per-record / T-HIGH deferred-to-I09), the
mutation-free op=propose handler, and the op=approve guards that short-circuit
BEFORE any DynamoDB write — including the io-Cognito gate that forbids the
agent/internal-key path from self-authorizing a merge (§8).

The op=approve execution path (per-duplicate supersession) is exercised with a
stubbed _handle_create_relationship so the orchestration/aggregation is unit
tested without the live DynamoDB + Neo4j projection. The full superseded-by ->
edge-migration -> evidence-freeze round trip is I07's primitive, covered by
test_supersession_i07.py and validated live on gamma.
"""
import json
import unittest


def _verdict(a, b, prob, cert_passed=False, tier=None, rtype="issue", cosine=0.999):
    return {
        "a": a, "b": b, "record_type": rtype,
        "signals": {"cosine": cosine, "lexical": 0.8, "structural": 0.5, "metadata": 0.7},
        "calibrated_prob": prob,
        "tier": tier if tier is not None else ("auto-merge" if cert_passed else "review"),
        "certificate": {"passed": cert_passed},
    }


def _cluster(cid, canonical, members, rtype="issue", project="enceladus"):
    return {
        "cluster_id": cid, "record_type": rtype, "project_id": project,
        "size": len(members), "members": members, "canonical": canonical,
        "duplicates": [m for m in members if m != canonical],
    }


class TestPairTierMapping(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf
        self.tau, self.floor = lf._DEDUP_TAU_MID, lf._DEDUP_REVIEW_FLOOR

    def test_certificate_passed_is_t_high(self):
        v = _verdict("A", "B", 0.999, cert_passed=True)
        self.assertEqual(self.lf._dedup_pair_tier(v, self.tau, self.floor), "T-HIGH")

    def test_auto_merge_tier_without_explicit_cert_is_t_high(self):
        v = {"tier": "auto-merge", "calibrated_prob": 0.999}
        self.assertEqual(self.lf._dedup_pair_tier(v, self.tau, self.floor), "T-HIGH")

    def test_high_prob_cert_not_passed_is_t_mid(self):
        v = _verdict("A", "B", 0.97, cert_passed=False)
        self.assertEqual(self.lf._dedup_pair_tier(v, self.tau, self.floor), "T-MID")

    def test_mid_prob_is_t_low(self):
        v = _verdict("A", "B", 0.70, cert_passed=False)
        self.assertEqual(self.lf._dedup_pair_tier(v, self.tau, self.floor), "T-LOW")

    def test_low_prob_is_distinct(self):
        v = _verdict("A", "B", 0.20, cert_passed=False)
        self.assertEqual(self.lf._dedup_pair_tier(v, self.tau, self.floor), "distinct")

    def test_missing_verdict_is_distinct(self):
        self.assertEqual(self.lf._dedup_pair_tier(None, self.tau, self.floor), "distinct")

    def test_none_prob_is_distinct(self):
        v = {"certificate": {"passed": False}, "calibrated_prob": None}
        self.assertEqual(self.lf._dedup_pair_tier(v, self.tau, self.floor), "distinct")

    def test_boundary_exactly_tau_mid_is_t_mid(self):
        v = _verdict("A", "B", self.tau, cert_passed=False)
        self.assertEqual(self.lf._dedup_pair_tier(v, self.tau, self.floor), "T-MID")

    def test_boundary_exactly_review_floor_is_t_low(self):
        v = _verdict("A", "B", self.floor, cert_passed=False)
        self.assertEqual(self.lf._dedup_pair_tier(v, self.tau, self.floor), "T-LOW")


class TestClusterTier(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def test_all_high_is_high(self):
        self.assertEqual(self.lf._dedup_cluster_tier(["T-HIGH", "T-HIGH"]), "T-HIGH")

    def test_high_and_mid_is_mid(self):
        self.assertEqual(self.lf._dedup_cluster_tier(["T-HIGH", "T-MID"]), "T-MID")

    def test_any_low_pulls_to_low(self):
        self.assertEqual(self.lf._dedup_cluster_tier(["T-HIGH", "T-MID", "T-LOW"]), "T-LOW")

    def test_empty_is_none(self):
        self.assertIsNone(self.lf._dedup_cluster_tier([]))
        self.assertIsNone(self.lf._dedup_cluster_tier(["distinct"]))


class TestHomogeneityHardFloor(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def test_all_issue_homogeneous(self):
        ok, t = self.lf._dedup_homogeneous(["ENC-ISS-1", "ENC-ISS-2", "ENC-ISS-3"])
        self.assertTrue(ok)
        self.assertEqual(t, "issue")

    def test_cross_type_not_homogeneous(self):
        ok, t = self.lf._dedup_homogeneous(["ENC-ISS-1", "ENC-TSK-2"])
        self.assertFalse(ok)
        self.assertIsNone(t)

    def test_all_task_homogeneous(self):
        ok, t = self.lf._dedup_homogeneous(["ENC-TSK-1", "ENC-TSK-2"])
        self.assertTrue(ok)
        self.assertEqual(t, "task")


class TestPairKey(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def test_orientation_stable(self):
        self.assertEqual(self.lf._dedup_pair_key("ENC-ISS-2", "ENC-ISS-1"),
                         self.lf._dedup_pair_key("ENC-ISS-1", "ENC-ISS-2"))
        self.assertEqual(self.lf._dedup_pair_key("enc-iss-1", "ENC-ISS-2"),
                         ("ENC-ISS-1", "ENC-ISS-2"))


class TestBuildProposal(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf
        self.tau, self.floor = lf._DEDUP_TAU_MID, lf._DEDUP_REVIEW_FLOOR

    def _index(self, verdicts):
        return {self.lf._dedup_pair_key(v["a"], v["b"]): v for v in verdicts}

    def test_t_mid_cluster_is_plan(self):
        c = _cluster("c1", "ENC-ISS-1", ["ENC-ISS-1", "ENC-ISS-2", "ENC-ISS-3"])
        idx = self._index([
            _verdict("ENC-ISS-1", "ENC-ISS-2", 0.97),
            _verdict("ENC-ISS-1", "ENC-ISS-3", 0.96),
        ])
        p = self.lf._dedup_build_proposal(c, idx, self.tau, self.floor)
        self.assertFalse(p["excluded"])
        self.assertEqual(p["cluster_tier"], "T-MID")
        self.assertTrue(p["actionable"])
        self.assertEqual(p["granularity"], "plan")
        self.assertEqual({d["record_id"] for d in p["duplicates"]}, {"ENC-ISS-2", "ENC-ISS-3"})

    def test_t_low_cluster_is_per_record(self):
        c = _cluster("c2", "ENC-ISS-1", ["ENC-ISS-1", "ENC-ISS-2", "ENC-ISS-3"])
        idx = self._index([
            _verdict("ENC-ISS-1", "ENC-ISS-2", 0.97),   # T-MID
            _verdict("ENC-ISS-1", "ENC-ISS-3", 0.70),   # T-LOW pulls cluster down
        ])
        p = self.lf._dedup_build_proposal(c, idx, self.tau, self.floor)
        self.assertEqual(p["cluster_tier"], "T-LOW")
        self.assertTrue(p["actionable"])
        self.assertEqual(p["granularity"], "per-record")

    def test_t_high_cluster_deferred_to_i09(self):
        c = _cluster("c3", "ENC-ISS-1", ["ENC-ISS-1", "ENC-ISS-2"])
        idx = self._index([_verdict("ENC-ISS-1", "ENC-ISS-2", 0.999, cert_passed=True)])
        p = self.lf._dedup_build_proposal(c, idx, self.tau, self.floor)
        self.assertEqual(p["cluster_tier"], "T-HIGH")
        self.assertFalse(p["actionable"])
        self.assertEqual(p["granularity"], "deferred")
        self.assertEqual(p["defer_to"], "ENC-TSK-I09")

    def test_distinct_duplicates_dropped(self):
        c = _cluster("c4", "ENC-ISS-1", ["ENC-ISS-1", "ENC-ISS-2", "ENC-ISS-3"])
        idx = self._index([
            _verdict("ENC-ISS-1", "ENC-ISS-2", 0.97),   # T-MID kept
            _verdict("ENC-ISS-1", "ENC-ISS-3", 0.10),   # distinct dropped
        ])
        p = self.lf._dedup_build_proposal(c, idx, self.tau, self.floor)
        self.assertEqual({d["record_id"] for d in p["duplicates"]}, {"ENC-ISS-2"})
        self.assertEqual(p["dropped_distinct"], ["ENC-ISS-3"])

    def test_cross_type_cluster_excluded_hard_floor(self):
        # Defensive: a (malformed) cross-type cluster is never surfaced (§4.0).
        c = _cluster("c5", "ENC-ISS-1", ["ENC-ISS-1", "ENC-TSK-2"])
        p = self.lf._dedup_build_proposal(c, {}, self.tau, self.floor)
        self.assertTrue(p["excluded"])
        self.assertIn("hard-floor", p["reason"])

    def test_missing_canonical_excluded(self):
        c = {"cluster_id": "c6", "record_type": "issue", "project_id": "enceladus",
             "members": ["ENC-ISS-1", "ENC-ISS-2"], "canonical": ""}
        p = self.lf._dedup_build_proposal(c, {}, self.tau, self.floor)
        self.assertTrue(p["excluded"])


class TestProposeHandler(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def _call(self, body):
        resp = self.lf._handle_dedup_propose("enceladus", body)
        return resp["statusCode"], json.loads(resp["body"])

    def test_propose_counts_tiers(self):
        body = {
            "clusters": [
                _cluster("c1", "ENC-ISS-1", ["ENC-ISS-1", "ENC-ISS-2"]),          # T-MID
                _cluster("c2", "ENC-ISS-3", ["ENC-ISS-3", "ENC-ISS-4"]),          # T-LOW
                _cluster("c3", "ENC-ISS-5", ["ENC-ISS-5", "ENC-ISS-6"]),          # T-HIGH
            ],
            "verdicts": [
                _verdict("ENC-ISS-1", "ENC-ISS-2", 0.97),
                _verdict("ENC-ISS-3", "ENC-ISS-4", 0.70),
                _verdict("ENC-ISS-5", "ENC-ISS-6", 0.999, cert_passed=True),
            ],
        }
        code, data = self._call(body)
        self.assertEqual(code, 200)
        self.assertEqual(data["counts"]["T-MID"], 1)
        self.assertEqual(data["counts"]["T-LOW"], 1)
        self.assertEqual(data["counts"]["T-HIGH_deferred"], 1)
        self.assertEqual(data["proposal_count"], 3)

    def test_propose_is_mutation_free_shape(self):
        code, data = self._call({"clusters": [], "verdicts": []})
        self.assertEqual(code, 200)
        self.assertEqual(data["proposals"], [])

    def test_propose_missing_clusters_400(self):
        code, data = self._call({"verdicts": []})
        self.assertEqual(code, 400)

    def test_propose_bad_thresholds_400(self):
        code, _ = self._call({"clusters": [], "verdicts": [], "tau_mid": 0.3, "review_floor": 0.9})
        self.assertEqual(code, 400)


class TestApproveGuards(unittest.TestCase):
    """op=approve guards that short-circuit BEFORE any DynamoDB write."""
    def setUp(self):
        import lambda_function as lf
        self.lf = lf
        self.io = {"cognito:username": "io", "sub": "io-sub"}      # Cognito (human)
        self.agent = {"auth_mode": "internal-key"}                  # internal key (agent)

    def _call(self, body, claims):
        resp = self.lf._handle_dedup_approve("enceladus", body, claims)
        return resp["statusCode"], json.loads(resp["body"])

    def test_internal_key_rejected_403(self):
        code, data = self._call(
            {"canonical_id": "ENC-ISS-1", "superseded_ids": ["ENC-ISS-2"], "tier": "T-MID"},
            self.agent)
        self.assertEqual(code, 403)
        self.assertIn("cannot self-authorize", data["error"])

    def test_no_claims_rejected_403(self):
        code, _ = self._call(
            {"canonical_id": "ENC-ISS-1", "superseded_ids": ["ENC-ISS-2"], "tier": "T-MID"},
            None)
        self.assertEqual(code, 403)

    def test_t_high_tier_rejected_400(self):
        code, data = self._call(
            {"canonical_id": "ENC-ISS-1", "superseded_ids": ["ENC-ISS-2"], "tier": "T-HIGH"},
            self.io)
        self.assertEqual(code, 400)
        self.assertIn("I09", data["error"])

    def test_cross_type_set_rejected_400(self):
        code, data = self._call(
            {"canonical_id": "ENC-ISS-1", "superseded_ids": ["ENC-TSK-2"], "tier": "T-MID"},
            self.io)
        self.assertEqual(code, 400)
        self.assertIn("category error", data["error"])

    def test_canonical_in_superseded_rejected_400(self):
        code, _ = self._call(
            {"canonical_id": "ENC-ISS-1", "superseded_ids": ["ENC-ISS-1"], "tier": "T-MID"},
            self.io)
        self.assertEqual(code, 400)

    def test_empty_superseded_rejected_400(self):
        code, _ = self._call(
            {"canonical_id": "ENC-ISS-1", "superseded_ids": [], "tier": "T-MID"},
            self.io)
        self.assertEqual(code, 400)

    def test_missing_canonical_rejected_400(self):
        code, _ = self._call(
            {"superseded_ids": ["ENC-ISS-2"], "tier": "T-MID"},
            self.io)
        self.assertEqual(code, 400)


class TestApproveExecutionStubbed(unittest.TestCase):
    """op=approve orchestration with a stubbed I07 primitive (no DDB)."""
    def setUp(self):
        import lambda_function as lf
        self.lf = lf
        self.io = {"cognito:username": "io", "sub": "io-sub"}
        self._orig = lf._handle_create_relationship
        self.calls = []

        def _stub(project_id, body):
            self.calls.append(body)
            return {"statusCode": 201, "headers": {}, "body": json.dumps({
                "success": True,
                "supersession": {"superseded_id": body["source_id"],
                                 "canonical_id": body["target_id"], "reversible": True},
            })}

        lf._handle_create_relationship = _stub

    def tearDown(self):
        self.lf._handle_create_relationship = self._orig

    def test_approve_supersedes_each_duplicate_into_canonical(self):
        resp = self.lf._handle_dedup_approve("enceladus", {
            "canonical_id": "ENC-ISS-1",
            "superseded_ids": ["ENC-ISS-2", "ENC-ISS-3"],
            "tier": "T-MID", "cluster_id": "c1",
        }, self.io)
        data = json.loads(resp["body"])
        self.assertEqual(resp["statusCode"], 200)
        self.assertEqual(data["superseded_count"], 2)
        self.assertEqual(data["rejected_count"], 0)
        self.assertEqual(data["approved_by"], "io")
        # Each call supersedes the duplicate (source) INTO the canonical (target)
        # via the superseded-by primitive, provenance human.
        self.assertEqual(len(self.calls), 2)
        for call in self.calls:
            self.assertEqual(call["relationship_type"], "superseded-by")
            self.assertEqual(call["target_id"], "ENC-ISS-1")
            self.assertEqual(call["provenance"], "human")
            self.assertIn("ENC-TSK-I08", call["reason"])
        self.assertEqual({c["source_id"] for c in self.calls}, {"ENC-ISS-2", "ENC-ISS-3"})

    def test_approve_per_record_subset_t_low(self):
        # T-LOW per-record: io approves only a subset of the cluster's duplicates.
        resp = self.lf._handle_dedup_approve("enceladus", {
            "canonical_id": "ENC-ISS-1",
            "superseded_ids": ["ENC-ISS-3"],
            "tier": "T-LOW", "cluster_id": "c2",
        }, self.io)
        data = json.loads(resp["body"])
        self.assertEqual(data["superseded_count"], 1)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0]["source_id"], "ENC-ISS-3")

    def test_approve_surfaces_per_record_failure(self):
        # A per-duplicate evidence-orphan 409 is surfaced, not forced; the batch
        # continues and reports mixed outcomes.
        def _mixed(project_id, body):
            self.calls.append(body)
            if body["source_id"] == "ENC-ISS-2":
                return {"statusCode": 409, "headers": {}, "body": json.dumps({
                    "success": False, "error": "Evidence-orphan conflict"})}
            return {"statusCode": 201, "headers": {}, "body": json.dumps({
                "success": True, "supersession": {"superseded_id": body["source_id"]}})}
        self.lf._handle_create_relationship = _mixed
        resp = self.lf._handle_dedup_approve("enceladus", {
            "canonical_id": "ENC-ISS-1",
            "superseded_ids": ["ENC-ISS-2", "ENC-ISS-3"],
            "tier": "T-MID",
        }, self.io)
        data = json.loads(resp["body"])
        self.assertEqual(data["superseded_count"], 1)
        self.assertEqual(data["rejected_count"], 1)
        failed = [r for r in data["results"] if not r["ok"]]
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["superseded_id"], "ENC-ISS-2")
        self.assertIn("Evidence-orphan", failed[0]["detail"])


if __name__ == "__main__":
    unittest.main()
