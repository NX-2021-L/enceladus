"""ENC-TSK-I09 (Dedup P5): MECHANICAL arc-walker auto-merge unit tests.

Pure-logic + stubbed-orchestration coverage in the established tracker_mutation
house style (no live DDB / EventBridge). Covers every acceptance-criterion rail
of DOC-DF651F07D5C2 §P5:

  * the P2 certificate gate that licenses a mechanical merge (passed + precision
    LCB >= 0.999), and the no-transitive-chain-drag guarantee (§4.3/§4.4),
  * the feature flag — dark/shadow until enabled (no writes when off),
  * the global kill switch — instant halt before any evaluation/write (§8),
  * the auto_walk_opt_out latch — a latched member is demoted to ATTESTATION and
    skipped by the walker (§6), and an io walk-back of an auto-merge latches it,
  * the io-reviewable audit feed (one event per executed merge),
  * each superseded member individually certified against the CHOSEN canonical.

Runs standalone (python test_dedup_auto_merge_i09.py) or under pytest.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lambda_function as lf  # noqa: E402


def _verdict(a, b, prob=0.9999, passed=True, lcb=0.9995, cosine=0.9998):
    return {
        "a": a, "b": b,
        "signals": {"cosine": cosine},
        "calibrated_prob": prob,
        "certificate": {"passed": passed, "precision_lcb": lcb},
    }


def _cluster(cid, canonical, members):
    return {"cluster_id": cid, "record_type": "issue", "project_id": "enceladus",
            "canonical": canonical, "members": members}


# ---------------------------------------------------------------------------
# Pure logic: the certificate gate (Rail 3) + chain-drag guarantee
# ---------------------------------------------------------------------------
class TestCertHolds(unittest.TestCase):
    def setUp(self):
        self.floor = lf._DEDUP_CERT_PRECISION_LCB_FLOOR

    def test_passing_cert_above_floor_holds(self):
        ok, _ = lf._dedup_auto_merge_cert_holds(_verdict("A", "B", lcb=0.9995), self.floor)
        self.assertTrue(ok)

    def test_exactly_floor_holds(self):
        ok, _ = lf._dedup_auto_merge_cert_holds(_verdict("A", "B", lcb=0.999), self.floor)
        self.assertTrue(ok)

    def test_below_floor_rejected(self):
        ok, why = lf._dedup_auto_merge_cert_holds(_verdict("A", "B", lcb=0.998), self.floor)
        self.assertFalse(ok)
        self.assertIn("LCB", why)

    def test_cert_not_passed_rejected(self):
        ok, why = lf._dedup_auto_merge_cert_holds(_verdict("A", "B", passed=False), self.floor)
        self.assertFalse(ok)
        self.assertIn("not passed", why)

    def test_missing_lcb_rejected(self):
        v = {"certificate": {"passed": True}}  # no precision_lcb
        ok, why = lf._dedup_auto_merge_cert_holds(v, self.floor)
        self.assertFalse(ok)
        self.assertIn("precision_lcb", why)

    def test_no_verdict_rejected_chain_drag_guard(self):
        ok, why = lf._dedup_auto_merge_cert_holds(None, self.floor)
        self.assertFalse(ok)
        self.assertIn("chain-drag", why)

    def test_floor_constant_is_999(self):
        self.assertEqual(lf._DEDUP_CERT_PRECISION_LCB_FLOOR, 0.999)


# ---------------------------------------------------------------------------
# Handler harness — stub the I07 primitive, the opt-out read, and the audit feed.
# ---------------------------------------------------------------------------
class _HandlerBase(unittest.TestCase):
    def setUp(self):
        self.lf = lf
        self.calls = []          # supersession (create_relationship) calls
        self.events = []         # audit-feed events
        self.latched_ids = set() # member ids whose opt-out is latched

        self._orig_rel = lf._handle_create_relationship
        self._orig_optout = lf._dedup_member_opt_out_latched
        self._orig_emit = lf._emit_auto_merge_event
        self._orig_enabled = lf._dedup_auto_merge_enabled
        self._orig_kill = lf._dedup_auto_merge_kill_switch

        def _stub_rel(project_id, body):
            self.calls.append(body)
            return {"statusCode": 201, "headers": {}, "body": json.dumps({
                "success": True,
                "supersession": {"superseded_id": body["source_id"],
                                 "canonical_id": body["target_id"], "reversible": True},
            })}

        def _stub_optout(project_id, member_id):
            return (member_id.upper() in self.latched_ids), None

        def _stub_emit(*a, **k):
            self.events.append((a, k))

        lf._handle_create_relationship = _stub_rel
        lf._dedup_member_opt_out_latched = _stub_optout
        lf._emit_auto_merge_event = _stub_emit
        # default: enabled, kill switch off
        lf._dedup_auto_merge_enabled = lambda: True
        lf._dedup_auto_merge_kill_switch = lambda: False

    def tearDown(self):
        lf._handle_create_relationship = self._orig_rel
        lf._dedup_member_opt_out_latched = self._orig_optout
        lf._emit_auto_merge_event = self._orig_emit
        lf._dedup_auto_merge_enabled = self._orig_enabled
        lf._dedup_auto_merge_kill_switch = self._orig_kill

    def _call(self, body):
        resp = lf._handle_dedup_auto_merge("enceladus", body, {"auth_mode": "internal-key"})
        return resp["statusCode"], json.loads(resp["body"])


class TestAutoMergeExecution(_HandlerBase):
    def test_enabled_executes_merge_and_audits(self):
        body = {"clusters": [_cluster("c1", "ENC-ISS-1", ["ENC-ISS-1", "ENC-ISS-2", "ENC-ISS-3"])],
                "verdicts": [_verdict("ENC-ISS-1", "ENC-ISS-2"), _verdict("ENC-ISS-1", "ENC-ISS-3")]}
        code, data = self._call(body)
        self.assertEqual(code, 200)
        self.assertFalse(data["shadow"])
        self.assertEqual(data["merged_count"], 2)
        self.assertEqual(len(self.calls), 2)
        # supersession source=duplicate, target=canonical, arc-walker attribution.
        for c in self.calls:
            self.assertEqual(c["relationship_type"], "superseded-by")
            self.assertEqual(c["target_id"], "ENC-ISS-1")
            self.assertEqual(c["provenance"], "system")
            self.assertEqual(c["write_source"]["provider"], lf.ARC_WALKER_ACTOR)
        self.assertEqual({c["source_id"] for c in self.calls}, {"ENC-ISS-2", "ENC-ISS-3"})
        # audit feed: one event per executed merge.
        self.assertEqual(len(self.events), 2)
        self.assertEqual(data["advanced_by"], lf.ARC_WALKER_ACTOR)

    def test_member_without_passing_cert_skipped(self):
        body = {"clusters": [_cluster("c1", "ENC-ISS-1", ["ENC-ISS-1", "ENC-ISS-2", "ENC-ISS-3"])],
                "verdicts": [_verdict("ENC-ISS-1", "ENC-ISS-2"),
                             _verdict("ENC-ISS-1", "ENC-ISS-3", passed=False)]}
        code, data = self._call(body)
        self.assertEqual(data["merged_count"], 1)
        self.assertEqual(data["skipped_count"], 1)
        self.assertEqual({c["source_id"] for c in self.calls}, {"ENC-ISS-2"})

    def test_no_chain_drag_only_direct_canonical_cert_counts(self):
        # ENC-ISS-3 has NO direct (canonical, member) verdict — only a verdict against a
        # neighbor (ENC-ISS-2). It must NOT be pulled in transitively (§4.4).
        body = {"clusters": [_cluster("c1", "ENC-ISS-1", ["ENC-ISS-1", "ENC-ISS-2", "ENC-ISS-3"])],
                "verdicts": [_verdict("ENC-ISS-1", "ENC-ISS-2"),
                             _verdict("ENC-ISS-2", "ENC-ISS-3")]}  # neighbor pair, not canonical
        code, data = self._call(body)
        self.assertEqual(data["merged_count"], 1)
        self.assertEqual({c["source_id"] for c in self.calls}, {"ENC-ISS-2"})
        res3 = next(r for cl in data["clusters"] for r in cl["results"] if r["member"] == "ENC-ISS-3")
        self.assertEqual(res3["action"], "skipped")
        self.assertIn("chain-drag", res3["reason"])

    def test_opt_out_latched_member_skipped_attestation(self):
        self.latched_ids = {"ENC-ISS-2"}
        body = {"clusters": [_cluster("c1", "ENC-ISS-1", ["ENC-ISS-1", "ENC-ISS-2", "ENC-ISS-3"])],
                "verdicts": [_verdict("ENC-ISS-1", "ENC-ISS-2"), _verdict("ENC-ISS-1", "ENC-ISS-3")]}
        code, data = self._call(body)
        self.assertEqual(data["merged_count"], 1)
        self.assertEqual({c["source_id"] for c in self.calls}, {"ENC-ISS-3"})
        res2 = next(r for cl in data["clusters"] for r in cl["results"] if r["member"] == "ENC-ISS-2")
        self.assertIn("ATTESTATION", res2["reason"])

    def test_cross_type_cluster_hard_floor_excluded(self):
        body = {"clusters": [_cluster("c1", "ENC-ISS-1", ["ENC-ISS-1", "ENC-TSK-2"])],
                "verdicts": [_verdict("ENC-ISS-1", "ENC-TSK-2")]}
        code, data = self._call(body)
        self.assertEqual(data["merged_count"], 0)
        self.assertTrue(data["clusters"][0]["excluded"])
        self.assertEqual(len(self.calls), 0)

    def test_evidence_orphan_409_surfaced_not_forced(self):
        def _mixed(project_id, body):
            self.calls.append(body)
            if body["source_id"] == "ENC-ISS-2":
                return {"statusCode": 409, "headers": {}, "body": json.dumps(
                    {"success": False, "error": "Evidence-orphan conflict"})}
            return {"statusCode": 201, "headers": {}, "body": json.dumps(
                {"success": True, "supersession": {"superseded_id": body["source_id"]}})}
        lf._handle_create_relationship = _mixed
        body = {"clusters": [_cluster("c1", "ENC-ISS-1", ["ENC-ISS-1", "ENC-ISS-2", "ENC-ISS-3"])],
                "verdicts": [_verdict("ENC-ISS-1", "ENC-ISS-2"), _verdict("ENC-ISS-1", "ENC-ISS-3")]}
        code, data = self._call(body)
        self.assertEqual(data["merged_count"], 1)
        self.assertEqual(data["skipped_count"], 1)
        failed = [r for cl in data["clusters"] for r in cl["results"] if r["action"] == "failed"]
        self.assertEqual(len(failed), 1)
        self.assertIn("Evidence-orphan", failed[0]["detail"])
        # only the canonical's own audit fires (the 409 member is not audited as merged)
        self.assertEqual(len(self.events), 1)


class TestShadowAndKillSwitch(_HandlerBase):
    def test_shadow_when_flag_disabled_writes_nothing(self):
        lf._dedup_auto_merge_enabled = lambda: False
        body = {"clusters": [_cluster("c1", "ENC-ISS-1", ["ENC-ISS-1", "ENC-ISS-2"])],
                "verdicts": [_verdict("ENC-ISS-1", "ENC-ISS-2")]}
        code, data = self._call(body)
        self.assertEqual(code, 200)
        self.assertTrue(data["shadow"])
        self.assertEqual(data["merged_count"], 0)
        self.assertEqual(len(self.calls), 0)       # NO writes in shadow
        self.assertEqual(len(self.events), 0)      # NO audit emits in shadow
        res = data["clusters"][0]["results"][0]
        self.assertEqual(res["action"], "would-merge")

    def test_kill_switch_halts_instantly(self):
        lf._dedup_auto_merge_kill_switch = lambda: True
        body = {"clusters": [_cluster("c1", "ENC-ISS-1", ["ENC-ISS-1", "ENC-ISS-2"])],
                "verdicts": [_verdict("ENC-ISS-1", "ENC-ISS-2")]}
        code, data = self._call(body)
        self.assertEqual(code, 200)
        self.assertTrue(data["halted"])
        self.assertTrue(data["kill_switch"])
        self.assertEqual(data["merged_count"], 0)
        self.assertEqual(len(self.calls), 0)
        self.assertEqual(data["clusters"], [])


class TestPrecisionFloorDiscipline(_HandlerBase):
    def test_floor_cannot_be_lowered_below_999(self):
        body = {"clusters": [], "verdicts": [], "precision_lcb_floor": 0.99}
        code, data = self._call(body)
        self.assertEqual(code, 400)
        self.assertIn("0.999", data["error"])

    def test_floor_may_be_raised(self):
        # Raise the floor to 0.9999 — a 0.9995-LCB cert no longer qualifies.
        body = {"clusters": [_cluster("c1", "ENC-ISS-1", ["ENC-ISS-1", "ENC-ISS-2"])],
                "verdicts": [_verdict("ENC-ISS-1", "ENC-ISS-2", lcb=0.9995)],
                "precision_lcb_floor": 0.9999}
        code, data = self._call(body)
        self.assertEqual(code, 200)
        self.assertEqual(data["merged_count"], 0)
        self.assertEqual(data["precision_lcb_floor"], 0.9999)

    def test_missing_clusters_400(self):
        resp = lf._handle_dedup_auto_merge("enceladus", {"verdicts": []}, None)
        self.assertEqual(resp["statusCode"], 400)


# ---------------------------------------------------------------------------
# Walk-back latch in _revert_supersession (AC: opt-out latches on io walk-back)
# ---------------------------------------------------------------------------
class _FakeDDB:
    def __init__(self):
        self.updates = []

    def update_item(self, **kw):
        self.updates.append(kw)
        return {}


class _FakeEvents:
    def __init__(self):
        self.events = []

    def put_events(self, **kw):
        self.events.append(kw)
        return {"FailedEntryCount": 0}


class TestWalkBackLatch(unittest.TestCase):
    def setUp(self):
        self.ddb = _FakeDDB()
        self.events = _FakeEvents()
        self._orig = {n: getattr(lf, n) for n in
                      ("_get_ddb", "_get_events", "_build_key", "_get_record_raw",
                       "_unarchive_relationship_edge")}
        lf._get_ddb = lambda: self.ddb
        lf._get_events = lambda: self.events
        lf._build_key = lambda p, t, r: {"project_id": {"S": p}, "record_id": {"S": f"{t}#{r}"}}
        lf._unarchive_relationship_edge = lambda *a, **k: True

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(lf, n, v)

    def _raw(self, provider):
        return {
            "status": {"S": "superseded"},
            "superseded_by": {"S": "ENC-ISS-1"},
            "pre_supersession_status": {"S": "open"},
            "superseded_migrated_edges": {"L": []},
            "write_source": {"M": {"provider": {"S": provider}, "channel": {"S": provider}}},
        }

    def _status_update(self):
        for u in self.ddb.updates:
            if "REMOVE superseded_by" in u.get("UpdateExpression", ""):
                return u
        return None

    def test_walk_back_of_arc_walker_merge_latches_opt_out(self):
        lf._get_record_raw = lambda p, t, r: self._raw(lf.ARC_WALKER_ACTOR)
        out = lf._revert_supersession("enceladus", "ENC-ISS-2", {})
        self.assertTrue(out["auto_walk_opt_out_latched"])
        su = self._status_update()
        self.assertIn("auto_walk_opt_out = :optout", su["UpdateExpression"])
        self.assertEqual(su["ExpressionAttributeValues"][":optout"], {"BOOL": True})
        # Artifact-Genesis: latch history entry + telemetry event.
        hist = su["ExpressionAttributeValues"][":h"]["L"]
        self.assertTrue(any("[ARC-WALKER][OPT-OUT-LATCH]" in h["M"]["description"]["S"] for h in hist))
        self.assertEqual(len(self.events.events), 1)
        detail = json.loads(self.events.events[0]["Entries"][0]["Detail"])
        self.assertEqual(detail["trigger"], "auto-merge walk-back")

    def test_walk_back_of_human_merge_does_not_latch(self):
        # An ENC-TSK-I08 io-approved supersession (provider=human, not the walker) is
        # un-superseded without latching the circuit breaker.
        lf._get_record_raw = lambda p, t, r: self._raw("io")
        out = lf._revert_supersession("enceladus", "ENC-ISS-2", {})
        self.assertFalse(out["auto_walk_opt_out_latched"])
        su = self._status_update()
        self.assertNotIn(":optout", su["ExpressionAttributeValues"])
        self.assertEqual(self.events.events, [])


if __name__ == "__main__":
    unittest.main()
