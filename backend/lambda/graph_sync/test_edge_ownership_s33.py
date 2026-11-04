"""ENC-TSK-S33 / ENC-ISS-890 (ENC-PLN-104 W5): owner-scoped edge reconcile.

Spec: DOC-CC14B0A7C4BC. Landed before the fix (red first). Covers the ENC-ISS-890
repro, inverse-edge survival, relationship-record edge survival, scoped
relationship delete, the ``source: 'field'`` marker, D2 (superseded nodes keep
other records' edges), a source-scan drift guard over every edge emitter, and an
executable convergence model (200 random replay orders).
"""
import random
import re
import unittest
from collections import Counter
from unittest.mock import MagicMock

# Independent oracle: the ownership table as written in the spec (section 2.1).
SPEC_START_OWNED = {
    "BELONGS_TO", "CHILD_OF", "RELATED_TO", "ADDRESSES", "IMPLEMENTS",
    "PLAN_CONTAINS", "PLAN_ATTACHED_DOC", "PLAN_IMPLEMENTS", "LEARNED_FROM",
    "INFORMED_BY", "INVESTIGATES", "TRACKS_WAVE_OF", "HANDS_OFF",
    "CONSOLIDATED_FROM", "PROPOSED_BY", "SUCCEEDS", "TARGETS_GENERATION",
    "BELONGS_TO_GENERATION", "EXECUTES_WITHIN", "MENTIONS",
}
SPEC_END_OWNED = {
    "Plan": {"DOC_ATTACHED_TO_PLAN"},
    "Document": {"INFORMS", "INVESTIGATED_BY", "HAS_WAVE_DOC", "HANDED_OFF_BY",
                 "CONSOLIDATES", "PROPOSES"},
}
SHARED_19 = {
    "RELATED_TO", "IMPLEMENTS", "PLAN_CONTAINS", "PLAN_ATTACHED_DOC", "PLAN_IMPLEMENTS",
    "DOC_ATTACHED_TO_PLAN", "LEARNED_FROM", "HANDS_OFF", "HANDED_OFF_BY", "INFORMED_BY",
    "INFORMS", "INVESTIGATES", "INVESTIGATED_BY", "TRACKS_WAVE_OF", "HAS_WAVE_DOC",
    "SUCCEEDS", "BELONGS_TO_GENERATION", "TARGETS_GENERATION", "EXECUTES_WITHIN",
}

_EDGE_RE = re.compile(
    r"MERGE\s*\([^()]*\)\s*-\s*\[\s*(?P<var>\w*)\s*:\s*(?P<type>\{\w+\}|[A-Z][A-Z_]+)(?P<props>[^\]]*)\]"
)


def _lf():
    import lambda_function as lf
    return lf


def _calls(tx):
    return [(c.args[0], c.kwargs) for c in tx.run.call_args_list]


def _reconcile(record):
    tx = MagicMock()
    _lf()._reconcile_edges(tx, record)
    return _calls(tx)


def _deletes(calls):
    return [(q, k) for q, k in calls if "DELETE" in q]


def _inbound_deletes(calls):
    return [(q, k) for q, k in _deletes(calls) if re.search(r"MATCH\s*\(\)\s*-\s*\[", q)
            or re.search(r"\(\)\s*-\s*\[\w*[^\]]*\]\s*->\s*\(n", q)]


def _outbound_deletes(calls):
    return [(q, k) for q, k in _deletes(calls) if (q, k) not in _inbound_deletes(calls)]


# --- representative records covering every emitter ---------------------------------
TASK = {"record_type": "task", "record_id": "ENC-TSK-A01", "project_id": "enceladus",
        "parent": "ENC-TSK-A00", "related_task_ids": ["ENC-TSK-B01"],
        "related_issue_ids": ["ENC-ISS-001"], "related_feature_ids": ["ENC-FTR-001"],
        "target_generation": "GEN-001"}
ISSUE = {"record_type": "issue", "record_id": "ENC-ISS-002", "project_id": "enceladus",
         "related_task_ids": ["ENC-TSK-B01"]}
FEATURE = {"record_type": "feature", "record_id": "ENC-FTR-002", "project_id": "enceladus",
           "related_task_ids": ["ENC-TSK-B01"], "target_generation": "GEN-001"}
LESSON = {"record_type": "lesson", "record_id": "ENC-LSN-001", "project_id": "enceladus",
          "evidence_chain": ["ENC-TSK-B01"], "target_generation": "GEN-001"}
GENERATION = {"record_type": "generation", "record_id": "GEN-002", "project_id": "enceladus",
              "parent_generation_id": "GEN-001"}
PLAN = {"record_type": "plan", "record_id": "ENC-PLN-001", "project_id": "enceladus",
        "objectives_set": ["ENC-TSK-B01"], "attached_documents": ["DOC-AAAA00000001"],
        "related_feature_id": "ENC-FTR-001", "target_generation": "GEN-001"}


def _doc(subtype="doc", **extra):
    base = {"record_type": "document", "record_id": "DOC-BBBB00000001", "project_id": "enceladus",
            "document_subtype": subtype, "related_items": ["ENC-TSK-B01"],
            "informed_by": ["DOC-CCCC00000001"], "consolidated_from": ["DOC-CCCC00000002"],
            "proposed_by": "ENC-FTR-064"}
    base.update(extra)
    return base


DOC_PLAIN = _doc()
DOC_COE = _doc("coe", source_incident_id="ENC-ISS-001")
DOC_WAVE = _doc("wave", plan_anchor_id="ENC-PLN-001")
DOC_HANDOFF = _doc("handoff", source_record_id="ENC-TSK-B01")
ALL_RECORDS = [TASK, ISSUE, FEATURE, LESSON, GENERATION, PLAN, DOC_PLAIN, DOC_COE, DOC_WAVE, DOC_HANDOFF]


class TestIss890Repro(unittest.TestCase):
    """ENC-ISS-890: PATCH B must not erase A->B RELATED_TO."""

    def test_task_issue_feature_lesson_generation_have_no_inbound_delete(self):
        for rec in (TASK, ISSUE, FEATURE, LESSON, GENERATION):
            calls = _reconcile(rec)
            self.assertEqual(_inbound_deletes(calls), [],
                             f"{rec['record_type']} reconcile must not delete inbound edges: {_deletes(calls)}")

    def test_no_related_to_inbound_delete_anywhere(self):
        for rec in ALL_RECORDS:
            for q, _ in _deletes(_reconcile(rec)):
                self.assertNotRegex(q, r"\(\)\s*-\s*\[\w*:RELATED_TO\]",
                                    f"{rec['record_type']}: incoming RELATED_TO delete is the ENC-ISS-890 bug")

    def test_document_inbound_delete_names_only_document_end_owned_set(self):
        calls = _reconcile(DOC_PLAIN)
        inbound = _inbound_deletes(calls)
        self.assertEqual(len(inbound), 1, inbound)
        q, k = inbound[0]
        self.assertNotIn("RELATED_TO", q)
        self.assertEqual(set(k.get("end_owned", [])), SPEC_END_OWNED["Document"])


class TestInverseEdgesSurvive(unittest.TestCase):
    def test_document_reconcile_never_deletes_doc_attached_to_plan(self):
        calls = _reconcile(DOC_PLAIN)
        for q, k in _deletes(calls):
            self.assertNotIn("DOC_ATTACHED_TO_PLAN", q)
            for key in ("start_owned", "end_owned"):
                self.assertNotIn("DOC_ATTACHED_TO_PLAN", k.get(key, []))

    def test_plan_reconcile_deletes_doc_attached_to_plan_inbound_only(self):
        calls = _reconcile(PLAN)
        inbound = _inbound_deletes(calls)
        self.assertEqual(len(inbound), 1, inbound)
        self.assertEqual(set(inbound[0][1].get("end_owned", [])), SPEC_END_OWNED["Plan"])

    def test_plan_reconcile_never_deletes_informs(self):
        calls = _reconcile(PLAN)
        for q, k in _deletes(calls):
            self.assertNotIn("INFORMS", q)
            for key in ("start_owned", "end_owned"):
                self.assertNotIn("INFORMS", k.get(key, []))

    def test_document_start_owned_excludes_inverse_edges(self):
        out = _outbound_deletes(_reconcile(DOC_PLAIN))
        self.assertEqual(len(out), 1, out)
        start = set(out[0][1].get("start_owned", []))
        self.assertEqual(start, SPEC_START_OWNED)
        self.assertFalse(start & SPEC_END_OWNED["Document"])
        self.assertFalse(start & SPEC_END_OWNED["Plan"])


class TestRelationshipRecordEdgesSurviveSourceModify(unittest.TestCase):
    def test_out_delete_is_type_scoped_and_skips_source_id_edges(self):
        for rec in ALL_RECORDS:
            out = _outbound_deletes(_reconcile(rec))
            self.assertEqual(len(out), 1, (rec["record_type"], out))
            q, k = out[0]
            self.assertIn("r.source_id IS NULL", q)
            self.assertIn("$start_owned", q)
            self.assertIn("SUPERSEDED_BY", q)  # exclusion kept as defense in depth
            self.assertNotIn("SUPERSEDED_BY", k["start_owned"])

    def test_in_delete_skips_source_id_edges(self):
        for rec in (PLAN, DOC_PLAIN):
            q, _ = _inbound_deletes(_reconcile(rec))[0]
            self.assertIn("r.source_id IS NULL", q)
            self.assertIn("$end_owned", q)


class TestScopedRelationshipDelete(unittest.TestCase):
    def test_matches_source_id_and_target_id(self):
        tx = MagicMock()
        _lf()._delete_relationship_edge(tx, "rel#ENC-TSK-A01#relates-to#ENC-TSK-B01")
        q, k = _calls(tx)[0]
        self.assertRegex(q, r"\[r:RELATED_TO \{source_id: \$source_id, target_id: \$target_id\}\]")
        self.assertEqual((k["source_id"], k["target_id"]), ("ENC-TSK-A01", "ENC-TSK-B01"))

    def test_supersession_tombstone_delete_is_scoped_too(self):
        tx = MagicMock()
        _lf()._delete_relationship_edge(tx, "rel#ENC-ISS-002#superseded-by#ENC-ISS-001")
        q, _ = _calls(tx)[0]
        self.assertRegex(q, r"\[r:SUPERSEDED_BY \{source_id: \$source_id, target_id: \$target_id\}\]")


class TestFieldMarker(unittest.TestCase):
    def _edge_merges(self, record):
        found = []
        for q, _ in _calls_for(record):
            if "MENTIONS" in q:
                continue
            for m in _EDGE_RE.finditer(q):
                found.append((m.group("type"), m.group("props")))
        return found

    def test_every_field_merge_carries_source_field(self):
        seen = set()
        for rec in ALL_RECORDS:
            for edge_type, props in self._edge_merges(rec):
                seen.add(edge_type)
                self.assertIn("source: 'field'", props, f"{edge_type} MERGE lacks the field marker")
        self.assertTrue(SHARED_19 <= seen, f"corpus misses shared types: {SHARED_19 - seen}")

    def test_field_marker_is_distinct_from_relationship_record_props(self):
        tx = MagicMock()
        _lf()._upsert_relationship_edge(tx, {
            "relationship_type": "relates-to", "source_id": "ENC-TSK-A01", "target_id": "ENC-TSK-B01"})
        merge = [q for q, _ in _calls(tx) if "MERGE (s)-[r:" in q][0]
        self.assertIn("source_id: $source_id, target_id: $target_id", merge)
        self.assertNotIn("source: 'field'", merge)


def _calls_for(record):
    return _reconcile(record)


class TestSupersededD2(unittest.TestCase):
    def test_superseded_record_deletes_only_owned_sets(self):
        rec = dict(ISSUE, status="superseded", related_task_ids=["ENC-TSK-B01"])
        calls = _reconcile(rec)
        for q, k in _deletes(calls):
            self.assertIn("r.source_id IS NULL", q)
            self.assertTrue("$start_owned" in q or "$end_owned" in q, q)
        self.assertEqual(_inbound_deletes(calls), [])
        merges = [m.group("type") for q, _ in calls for m in _EDGE_RE.finditer(q)]
        self.assertEqual(merges, ["BELONGS_TO"])  # nothing re-projected but membership

    def test_superseded_document_keeps_inbound_outside_end_owned(self):
        rec = dict(DOC_PLAIN, status="superseded")
        for q, k in _inbound_deletes(_reconcile(rec)):
            self.assertEqual(set(k["end_owned"]), SPEC_END_OWNED["Document"])


# --- drift guard ----------------------------------------------------------------------

def _drift_violations(source, ownership, rel_labels, generation_edges):
    """Scan graph_sync source: every MERGEd edge type needs exactly one owner class and,
    when it is also a relationship-record label, field emitters must carry the marker."""
    text = source.replace("{{", "{").replace("}}", "}")
    start = set(ownership["start"])
    end = set().union(*ownership["end"].values())
    external = set(ownership["external"])
    out = []
    for m in _EDGE_RE.finditer(text):
        etype, props = m.group("type"), m.group("props")
        if etype == "{edge_label}":  # the relationship-record upsert
            if "source_id: $source_id" not in props or "target_id: $target_id" not in props:
                out.append("relationship-record MERGE must carry source_id and target_id")
            continue
        types = set(generation_edges) if etype == "{edge_type}" else {etype}
        if etype.startswith("{") and etype not in ("{edge_type}",):
            out.append(f"unresolvable dynamic edge type {etype}")
            continue
        for t in sorted(types):
            owners = [name for name, s in (("start", start), ("end", end), ("external", external)) if t in s]
            if not owners:
                out.append(f"{t}: no declared owner side")
            elif len(owners) > 1:
                out.append(f"{t}: emitted by multiple owner classes {owners}")
            elif owners[0] in ("start", "end") and t in rel_labels and "source: 'field'" not in props:
                out.append(f"{t}: field emitter shares a relationship label but lacks source: 'field'")
    return out


class TestDriftGuard(unittest.TestCase):
    def setUp(self):
        self.lf = _lf()
        with open(self.lf.__file__, encoding="utf-8") as fh:
            self.source = fh.read()

    def _check(self, source):
        return _drift_violations(
            source, self.lf.EDGE_OWNERSHIP, set(self.lf.RELATIONSHIP_TYPE_TO_EDGE_LABEL.values()),
            set(self.lf.TARGET_GENERATION_EDGE_BY_RECORD_TYPE.values()))

    def test_every_emitter_in_graph_sync_has_exactly_one_declared_owner(self):
        self.assertEqual(self._check(self.source), [])

    def test_ownership_table_matches_spec(self):
        own = self.lf.EDGE_OWNERSHIP
        self.assertEqual(set(own["start"]), SPEC_START_OWNED)
        self.assertEqual({k: set(v) for k, v in own["end"].items()}, SPEC_END_OWNED)
        self.assertFalse(set(own["start"]) & set(own["external"]))
        self.assertTrue({"MUTATED", "RECIPE_SERVES_PROJECT", "IMPLEMENTED_BY_RECIPE", "AUTHENTICATED_AS"}
                        <= set(own["external"]))

    def test_guard_flags_undeclared_emitter(self):
        rogue = self.source + '\nX = "MATCH (a),(b) MERGE (a)-[:ROGUE_EDGE]->(b)"\n'
        self.assertTrue(any("ROGUE_EDGE: no declared owner" in v for v in self._check(rogue)))

    def test_guard_flags_two_owner_classes(self):
        rogue = self.source + '\nX = "MATCH (a),(b) MERGE (a)-[:MUTATED]->(b)"\nY = "MERGE (a)-[:MUTATED]->(b)"\n'
        own = self.lf.EDGE_OWNERSHIP
        tampered = {"start": set(own["start"]) | {"MUTATED"}, "end": own["end"], "external": own["external"]}
        v = _drift_violations(rogue, tampered, set(), set())
        self.assertTrue(any("multiple owner classes" in x for x in v), v)

    def test_guard_flags_unmarked_shared_field_emitter(self):
        rogue = self.source + '\nX = "MERGE (a)-[:RELATED_TO]->(b)"\n'
        self.assertTrue(any("RELATED_TO" in v and "lacks source" in v for v in self._check(rogue)))


# --- executable convergence model ---------------------------------------------------------

class _Graph:
    """Edge multiset with Neo4j MERGE semantics: a property-less MERGE matches ANY edge of
    (type, src, dst); a MERGE with props matches only an edge carrying exactly those props."""

    def __init__(self):
        self.edges = Counter()

    def merge(self, etype, src, dst, props=None):
        if props is None:
            if any(k[:3] == (etype, src, dst) for k in self.edges):
                return
            self.edges[(etype, src, dst, frozenset())] += 1
        else:
            key = (etype, src, dst, frozenset(props.items()))
            if key not in self.edges:
                self.edges[key] = 1

    def delete_where(self, pred):
        for k in [k for k in self.edges if pred(k)]:
            del self.edges[k]

    def snapshot(self):
        return tuple(sorted((k[0], k[1], k[2], tuple(sorted(k[3])), c) for k, c in self.edges.items()))


def _field_edges(rec):
    """Mirror of the production emitters: yields (type, src, dst) for one record."""
    rid, kind = rec["id"], rec["kind"]
    out = [("BELONGS_TO", rid, "PRJ")]
    if rec.get("status") == "superseded":
        return out
    if rec.get("parent"):
        out.append(("CHILD_OF", rid, rec["parent"]))
    for t in rec.get("rel_tasks", []):
        out.append(("RELATED_TO", rid, t))
    for i in rec.get("rel_issues", []):
        out.append(("RELATED_TO", rid, i))
        if kind == "task":
            out.append(("ADDRESSES", rid, i))
    for f in rec.get("rel_features", []):
        out.append(("RELATED_TO", rid, f))
        if kind == "task":
            out.append(("IMPLEMENTS", rid, f))
    if kind == "plan":
        out += [("PLAN_CONTAINS", rid, o) for o in rec.get("objectives", [])]
        for d in rec.get("attached", []):
            out += [("PLAN_ATTACHED_DOC", rid, d), ("DOC_ATTACHED_TO_PLAN", d, rid)]
        if rec.get("feature"):
            out.append(("PLAN_IMPLEMENTS", rid, rec["feature"]))
    if kind == "lesson":
        out += [("LEARNED_FROM", rid, e) for e in rec.get("evidence", [])]
    if kind == "document":
        out += [("RELATED_TO", rid, t) for t in rec.get("related_items", [])]
        for s in rec.get("informed_by", []):
            out += [("INFORMED_BY", rid, s), ("INFORMS", s, rid)]
        if rec.get("incident"):
            out += [("INVESTIGATES", rid, rec["incident"]), ("INVESTIGATED_BY", rec["incident"], rid)]
        if rec.get("anchor"):
            out += [("TRACKS_WAVE_OF", rid, rec["anchor"]), ("HAS_WAVE_DOC", rec["anchor"], rid)]
        if rec.get("handoff"):
            out += [("HANDS_OFF", rid, rec["handoff"]), ("HANDED_OFF_BY", rec["handoff"], rid)]
        for s in rec.get("consolidated", []):
            out += [("CONSOLIDATED_FROM", rid, s), ("CONSOLIDATES", s, rid)]
        if rec.get("proposer"):
            out += [("PROPOSED_BY", rid, rec["proposer"]), ("PROPOSES", rec["proposer"], rid)]
    if kind == "generation" and rec.get("parent_gen"):
        out.append(("SUCCEEDS", rid, rec["parent_gen"]))
    if rec.get("target_gen"):
        etype = {"task": "TARGETS_GENERATION", "feature": "BELONGS_TO_GENERATION",
                 "plan": "EXECUTES_WITHIN", "lesson": "TARGETS_GENERATION"}.get(kind)
        if etype:
            out.append((etype, rid, rec["target_gen"]))
    return out


def _mentions(rec):
    return [("MENTIONS", rec["id"], m) for m in rec.get("mentions", [])]


def _reconcile_model(graph, rec, ownership):
    """ownership None = pre-fix behaviour; otherwise the EDGE_OWNERSHIP table."""
    rid = rec["id"]
    if ownership is None:
        graph.delete_where(lambda k: k[1] == rid and k[0] != "SUPERSEDED_BY")
        graph.delete_where(lambda k: k[0] == "RELATED_TO" and k[2] == rid)
        marker = None
    else:
        start = set(ownership["start"])
        end = set(ownership["end"].get(rec["label"], ()))
        graph.delete_where(lambda k: k[1] == rid and k[0] in start and k[0] != "SUPERSEDED_BY"
                           and not any(p == "source_id" for p, _ in k[3]))
        if end:
            graph.delete_where(lambda k: k[2] == rid and k[0] in end
                               and not any(p == "source_id" for p, _ in k[3]))
        marker = {"source": "field"}
    for etype, s, d in _field_edges(rec):
        graph.merge(etype, s, d, marker)
    for etype, s, d in _mentions(rec):
        graph.merge(etype, s, d, {"source": "auto_mention"})


def _rel_props(s, d):
    return {"source_id": s, "target_id": d}


def _apply_rel(graph, rel, scoped):
    etype, s, d, status = rel
    if status == "archived":
        if scoped:
            graph.delete_where(lambda k: k[:3] == (etype, s, d) and k[3] == frozenset(_rel_props(s, d).items()))
        else:
            graph.delete_where(lambda k: k[:3] == (etype, s, d))
    else:
        graph.merge(etype, s, d, _rel_props(s, d))


def _corpus():
    R = lambda i, label, kind, **kw: dict(id=i, label=label, kind=kind, **kw)  # noqa: E731
    recs = [
        R("T1", "Task", "task", parent="T0", rel_tasks=["T2", "T3"], rel_issues=["I1"], rel_features=["F1"],
          target_gen="G1", mentions=["T4"]),
        R("T2", "Task", "task", rel_tasks=["T1"], rel_issues=["I2"]),
        R("T3", "Task", "task", rel_tasks=["T4"]),
        R("T4", "Task", "task", rel_features=["F2"]),
        R("T5", "Task", "task", rel_tasks=["T2"], target_gen="G2"),
        R("I1", "Issue", "issue", rel_tasks=["T1"]),
        R("I2", "Issue", "issue", status="superseded", rel_tasks=["T1"]),
        R("F1", "Feature", "feature", rel_tasks=["T1"], target_gen="G1"),
        R("F2", "Feature", "feature"),
        R("P1", "Plan", "plan", objectives=["T1", "T2"], attached=["D1", "D2"], feature="F1", target_gen="G1"),
        R("P2", "Plan", "plan", objectives=["I1"], attached=["D3"]),
        R("L1", "Lesson", "lesson", evidence=["T1", "D1"], target_gen="G1"),
        R("G1", "Generation", "generation"),
        R("G2", "Generation", "generation", parent_gen="G1"),
        R("D1", "Document", "document", related_items=["T1"], informed_by=["D2"], consolidated=["D3"]),
        R("D2", "Document", "document", related_items=["P1"], proposer="F1"),
        R("D3", "Document", "document", incident="I1", informed_by=["D1"]),
        R("D4", "Document", "document", anchor="P1"),
        R("D5", "Document", "document", handoff="T2", related_items=["T5"]),
        R("D6", "Document", "document", informed_by=["D1", "D2"], anchor="P2", incident="T3"),
    ]
    # ~30 events: 20 records above + relationship records (active and archived).
    rels = [
        ("RELATED_TO", "T1", "T2", "active"),        # shares a triple with T1.rel_tasks
        ("RELATED_TO", "T3", "T4", "archived"),      # archive must not delete T3's field edge
        ("RELATED_TO", "T1", "T3", "archived"),
        ("SUPERSEDED_BY", "I2", "I1", "active"),
        ("PLAN_ATTACHED_DOC", "P1", "D1", "active"),
        ("DOC_ATTACHED_TO_PLAN", "D2", "P1", "active"),
        ("INFORMS", "D2", "D1", "active"),
        ("INFORMED_BY", "D1", "D2", "archived"),
        ("HANDED_OFF_BY", "T2", "D5", "active"),
        ("IMPLEMENTS", "F1", "T5", "active"),
        ("LEARNED_FROM", "L1", "T1", "active"),
        ("SUCCEEDS", "G2", "G1", "archived"),
    ]
    return recs, rels


EXTERNAL_SEEDS = [("MUTATED", "SES-1", "T1"), ("IMPLEMENTED_BY_RECIPE", "F1", "REC-1"),
                  ("RECIPE_SERVES_PROJECT", "REC-1", "PRJ"), ("AUTHENTICATED_AS", "SES-1", "AGT-1")]


def _replay(order_seed, ownership):
    recs, rels = _corpus()
    events = [("rec", r) for r in recs] + [("rel", r) for r in rels]
    random.Random(order_seed).shuffle(events)
    g = _Graph()
    for etype, s, d in EXTERNAL_SEEDS:
        g.merge(etype, s, d, None)
    for kind, payload in events:
        if kind == "rec":
            _reconcile_model(g, payload, ownership)
        else:
            _apply_rel(g, payload, scoped=ownership is not None)
    return g


class TestConvergenceModel(unittest.TestCase):
    ORDERS = range(200)

    def test_corpus_covers_every_declared_field_emitter(self):
        recs, _ = _corpus()
        emitted = {e[0] for r in recs for e in _field_edges(r)}
        declared = SPEC_START_OWNED | set().union(*SPEC_END_OWNED.values())
        self.assertEqual(declared - emitted - {"MENTIONS"}, set(), "model corpus misses an owned edge type")

    def test_prefix_semantics_diverge_across_replay_orders(self):
        snaps = {_replay(s, None).snapshot() for s in self.ORDERS}
        self.assertGreater(len(snaps), 1, "pre-fix model should be order dependent (ENC-ISS-890)")

    def test_owner_scoped_semantics_converge_in_every_order(self):
        own = _lf().EDGE_OWNERSHIP
        snaps = {_replay(s, own).snapshot() for s in self.ORDERS}
        self.assertEqual(len(snaps), 1, f"owner-scoped reconcile must be order independent; got {len(snaps)} states")

    def test_converged_graph_keeps_expected_edges(self):
        own = _lf().EDGE_OWNERSHIP
        g = _replay(7, own)
        keys = {k[:3] for k in g.edges}
        self.assertIn(("RELATED_TO", "T1", "T2"), keys)           # ISS-890: A->B survives B's PATCH
        self.assertIn(("RELATED_TO", "T3", "T4"), keys)           # field edge survives rel archive
        self.assertIn(("DOC_ATTACHED_TO_PLAN", "D1", "P1"), keys)  # inverse owned by the plan
        self.assertIn(("INFORMS", "D2", "D1"), keys)
        for etype, s, d in EXTERNAL_SEEDS:
            self.assertIn((etype, s, d), keys)
        shared = [k for k, c in g.edges.items() if k[:3] == ("RELATED_TO", "T1", "T2")]
        self.assertEqual(len(shared), 2)  # parallel field + relationship-record edge


if __name__ == "__main__":
    unittest.main()
