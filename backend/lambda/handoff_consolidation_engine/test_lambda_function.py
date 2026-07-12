"""Unit tests for the Handoff Consolidation Engine (ENC-TSK-C08).

Covers the pure-function core: FSRS-6 stability init monotonicity (AC-5), the
co-citation and error-recurrence extractors (AC-1 scan-cluster-propose), the
adaptive trigger (AC-1), GDMP Stage 2 provenance clustering (AC-3), and the
candidate-document provenance fields that feed the OGTM edges (AC-4).
"""
import unittest

import lambda_function as hce


def _handoff(doc_id, anchor=None, related=None, content="", created="2026-06-01T00:00:00Z"):
    return {
        "document_id": doc_id,
        "document_subtype": "handoff",
        "plan_anchor_id": anchor or "",
        "related_items": related or [],
        "content": content,
        "title": "",
        "description": "",
        "created_at": created,
        "status": "active",
    }


class TestFsrsInitialStability(unittest.TestCase):
    def test_strictly_increasing_in_recurrence(self):
        prev = -1.0
        for r in range(1, 30):
            s = hce.initial_stability_from_recurrence(r)
            self.assertGreater(s, prev, f"S_0 not increasing at recurrence={r}")
            prev = s

    def test_floor_at_single_occurrence(self):
        self.assertAlmostEqual(
            hce.initial_stability_from_recurrence(1, floor=2.0, ceil=15.0, growth=0.35),
            2.0, places=4,
        )

    def test_saturates_at_or_below_ceiling(self):
        # The mapping approaches but never exceeds the ceiling (it may round to
        # the ceiling at very high recurrence, which is the intended bound).
        for r in range(1, 200):
            self.assertLessEqual(
                hce.initial_stability_from_recurrence(r, floor=2.0, ceil=15.0, growth=0.35),
                15.0,
            )

    def test_higher_recurrence_higher_stability(self):
        # The headline AC-5 invariant.
        self.assertLess(
            hce.initial_stability_from_recurrence(2),
            hce.initial_stability_from_recurrence(8),
        )

    def test_degenerate_params_return_floor(self):
        self.assertEqual(hce.initial_stability_from_recurrence(5, floor=3.0, ceil=3.0, growth=0.3), 3.0)
        self.assertEqual(hce.initial_stability_from_recurrence(5, floor=3.0, ceil=9.0, growth=0.0), 3.0)


class TestCoCitationExtractor(unittest.TestCase):
    def test_pair_across_distinct_waves(self):
        handoffs = [
            _handoff("DOC-1", anchor="ENC-PLN-006", related=["ENC-TSK-A1", "ENC-ISS-B2"]),
            _handoff("DOC-2", anchor="ENC-PLN-007", related=["ENC-TSK-A1", "ENC-ISS-B2"]),
            _handoff("DOC-3", anchor="ENC-PLN-008", related=["ENC-TSK-A1", "ENC-ISS-B2"]),
        ]
        cands = hce.extract_co_citation_candidates(handoffs)
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0]["recurrence_count"], 3)
        self.assertEqual(sorted(cands[0]["record_pair"]), ["ENC-ISS-B2", "ENC-TSK-A1"])

    def test_same_wave_does_not_qualify(self):
        # Three docs but all in one wave -> distinct_waves=1 < 2.
        handoffs = [
            _handoff("DOC-1", anchor="ENC-PLN-006", related=["ENC-TSK-A1", "ENC-ISS-B2"]),
            _handoff("DOC-2", anchor="ENC-PLN-006", related=["ENC-TSK-A1", "ENC-ISS-B2"]),
            _handoff("DOC-3", anchor="ENC-PLN-006", related=["ENC-TSK-A1", "ENC-ISS-B2"]),
        ]
        self.assertEqual(hce.extract_co_citation_candidates(handoffs), [])

    def test_below_pair_count_excluded(self):
        handoffs = [
            _handoff("DOC-1", anchor="ENC-PLN-006", related=["ENC-TSK-A1", "ENC-ISS-B2"]),
            _handoff("DOC-2", anchor="ENC-PLN-007", related=["ENC-TSK-A1", "ENC-ISS-B2"]),
        ]
        # 2 docs / 2 waves but min_pair_count default is 3.
        self.assertEqual(hce.extract_co_citation_candidates(handoffs), [])


class TestErrorRecurrenceExtractor(unittest.TestCase):
    def test_iss_token_recurs_across_waves(self):
        handoffs = [
            _handoff("DOC-1", anchor="ENC-PLN-006", content="hit ENC-ISS-197 again"),
            _handoff("DOC-2", anchor="ENC-PLN-007", content="ENC-ISS-197 recurred [ERROR]"),
        ]
        cands = hce.extract_error_recurrence_candidates(handoffs)
        tokens = {c["error_class"] for c in cands}
        self.assertIn("ENC-ISS-197", tokens)

    def test_single_wave_not_recurring(self):
        handoffs = [_handoff("DOC-1", anchor="ENC-PLN-006", content="ENC-ISS-197")]
        self.assertEqual(hce.extract_error_recurrence_candidates(handoffs), [])

    def test_normalize_error_tokens(self):
        toks = hce.normalize_error_tokens("[ERROR] boom ENC-ISS-001 Sev1 [WARN]")
        self.assertIn("ENC-ISS-001", toks)
        self.assertIn("TAG:ERROR", toks)
        self.assertIn("TAG:WARN", toks)
        self.assertIn("SEV1", toks)


class TestAdaptiveTrigger(unittest.TestCase):
    def test_force_always_runs(self):
        run, reason = hce.should_run_cycle([], since_iso=None, force=True)
        self.assertTrue(run)
        self.assertEqual(reason, "forced")

    def test_no_handoffs_does_not_run(self):
        run, _ = hce.should_run_cycle([], since_iso=None, force=False)
        self.assertFalse(run)

    def test_threshold_gate(self):
        handoffs = [_handoff(f"DOC-{i}", created="2026-06-10T00:00:00Z") for i in range(5)]
        run, _ = hce.should_run_cycle(
            handoffs, since_iso="2026-06-01T00:00:00Z", min_new_handoffs=3
        )
        self.assertTrue(run)
        run2, _ = hce.should_run_cycle(
            handoffs, since_iso="2026-06-09T00:00:00Z", min_new_handoffs=10
        )
        self.assertFalse(run2)


class TestProvenanceClustering(unittest.TestCase):
    def test_shared_refs_form_context(self):
        docs = [
            {"document_id": "DOC-A", "related_items": ["ENC-TSK-1", "ENC-ISS-2"]},
            {"document_id": "DOC-B", "related_items": ["ENC-TSK-1", "ENC-FTR-3"]},
            {"document_id": "DOC-C", "related_items": ["ENC-PLN-9"]},
        ]
        prov = hce.cluster_provenance_context(docs, min_shared_refs=1)
        self.assertIn("DOC-A", prov)
        self.assertIn("DOC-B", prov["DOC-A"])
        self.assertNotIn("DOC-C", prov)

    def test_no_shared_refs_no_context(self):
        docs = [
            {"document_id": "DOC-A", "related_items": ["ENC-TSK-1"]},
            {"document_id": "DOC-B", "related_items": ["ENC-TSK-9"]},
        ]
        self.assertEqual(hce.cluster_provenance_context(docs, min_shared_refs=1), {})


class TestCandidateAssembly(unittest.TestCase):
    def test_candidate_carries_ogtm_fields(self):
        cand = {
            "extractor": "co-citation",
            "pattern_token": "ENC-TSK-A1+ENC-ISS-B2",
            "record_pair": ["ENC-TSK-A1", "ENC-ISS-B2"],
            "recurrence_count": 4,
            "distinct_waves": ["ENC-PLN-006", "ENC-PLN-007"],
            "source_doc_ids": ["DOC-1", "DOC-2", "DOC-3", "DOC-4"],
        }
        spec = hce.build_candidate_document(
            cand, lookback_start="2026-03-01T00:00:00Z", lookback_end="2026-06-01T00:00:00Z"
        )
        self.assertEqual(spec["consolidated_from"], cand["source_doc_ids"])
        self.assertEqual(spec["proposed_by"], hce.PROPOSER_ID)
        self.assertEqual(spec["fsrs_initial_stability"],
                         hce.initial_stability_from_recurrence(4))
        self.assertIn(hce.CANDIDATE_KEYWORD, spec["keywords"])
        self.assertIn("LESSON CANDIDATE", spec["title"])

    def test_source_hash_stable_and_order_independent(self):
        self.assertEqual(
            hce.source_hash(["DOC-1", "DOC-2"]),
            hce.source_hash(["DOC-2", "DOC-1"]),
        )


class RhythmStanzaTests(unittest.TestCase):
    """ENC-TSK-N23: heavy-beat completion-stanza contract (tenant_invoker.py)."""

    def test_no_result_key_is_noop(self):
        from unittest import mock

        with mock.patch.object(hce.boto3, "client") as client:
            self.assertFalse(hce._write_rhythm_stanza({}, "completed", {}))
            client.assert_not_called()

    def test_result_key_writes_contract_stanza(self):
        import json
        from unittest import mock

        key = "gamma/rhythm-cycle/heavy_integrate/tenant-results/20260712-000000/handoff_consolidation_engine.json"
        with mock.patch.object(hce.boto3, "client") as client:
            ok = hce._write_rhythm_stanza({"result_key": key}, "skipped", {"reason": "adaptive"})
        self.assertTrue(ok)
        kwargs = client.return_value.put_object.call_args.kwargs
        self.assertEqual(kwargs["Bucket"], hce.RHYTHM_RESULTS_BUCKET)
        self.assertEqual(kwargs["Key"], key)
        stanza = json.loads(kwargs["Body"].decode("utf-8"))
        self.assertEqual(stanza["tenant"], "handoff_consolidation_engine")
        self.assertEqual(stanza["status"], "skipped")
        self.assertEqual(stanza["detail"], {"reason": "adaptive"})

    def test_handler_reports_skip_as_explicit_stanza(self):
        import json
        from unittest import mock

        skipped = {"statusCode": 200, "body": json.dumps({"skipped": True, "adaptive_trigger": "too few"})}
        with mock.patch.object(hce, "_run_cycle", return_value=skipped):
            with mock.patch.object(hce, "_write_rhythm_stanza") as stanza:
                resp = hce.handler({"result_key": "k"}, None)
        self.assertEqual(resp["statusCode"], 200)
        args = stanza.call_args.args
        self.assertEqual(args[1], "skipped")


if __name__ == "__main__":
    unittest.main()
