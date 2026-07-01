"""Tests for ENC-TSK-J04 / ENC-FTR-074 Ph3: agent identity/session/credential graph
projection — node upserts (:AgentIdentity/:AgentSession/:AgentCredential) and the five
typed lifecycle edges (AUTHENTICATED_AS, OWNED_BY, DERIVED_FROM, TRIGGERED_BY, MUTATED).

Mirrors the style of test_edge_projection_f45.py: mock the Neo4j tx/session and assert on
the Cypher emitted, without a live database.
"""
import os
import re
import unittest
from unittest.mock import MagicMock


class _CypherCaptureMixin:
    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    @staticmethod
    def _calls(tx):
        return [str(c) for c in tx.run.call_args_list]

    def _run_session_capture(self, fn, record):
        """Invoke a hook that takes (session, record) and drives session.execute_write with
        a lambda; return the list of tx MagicMocks that were driven."""
        session = MagicMock()
        driven_tx = []

        def _execute_write(callable_):
            tx = MagicMock()
            callable_(tx)
            driven_tx.append(tx)
            return None

        session.execute_write.side_effect = _execute_write
        fn(session, record)
        return driven_tx


class TestInferLabelAgentPrefixes(_CypherCaptureMixin, unittest.TestCase):
    def test_ses_prefix_maps_to_agent_session(self):
        self.assertEqual(self.lf._infer_label_from_id("ENC-SES-029"), "AgentSession")

    def test_agt_prefix_maps_to_agent_identity(self):
        self.assertEqual(self.lf._infer_label_from_id("ENC-AGT-005"), "AgentIdentity")

    def test_cred_prefix_maps_to_agent_credential(self):
        self.assertEqual(self.lf._infer_label_from_id("CRED-abcdef0123"), "AgentCredential")

    def test_task_prefix_unchanged(self):
        self.assertEqual(self.lf._infer_label_from_id("ENC-TSK-J04"), "Task")


class TestNormalizeSynthesizesRecordType(_CypherCaptureMixin, unittest.TestCase):
    def test_agent_session_synthesized(self):
        out = self.lf._normalize_record_for_graph({"session_id": "ENC-SES-030", "status": "claimed"})
        self.assertEqual(out["record_type"], "agent_session")
        self.assertEqual(out["record_id"], "ENC-SES-030")

    def test_agent_identity_synthesized(self):
        out = self.lf._normalize_record_for_graph({"agent_type_id": "ENC-AGT-007", "surface": "cli"})
        self.assertEqual(out["record_type"], "agent_identity")
        self.assertEqual(out["record_id"], "ENC-AGT-007")

    def test_agent_credential_synthesized(self):
        out = self.lf._normalize_record_for_graph(
            {"credential_id": "CRED-deadbeef", "agent_identity_id": "ENC-AGT-007"}
        )
        self.assertEqual(out["record_type"], "agent_credential")
        self.assertEqual(out["record_id"], "CRED-deadbeef")

    def test_credential_takes_precedence_over_agent_type_id(self):
        # A credential row has agent_identity_id but no session_id; a session row has both
        # session_id and agent_type_id. Ensure ordering resolves each unambiguously.
        sess = self.lf._normalize_record_for_graph(
            {"session_id": "ENC-SES-1", "agent_type_id": "ENC-AGT-1"}
        )
        self.assertEqual(sess["record_type"], "agent_session")


class TestEdgeLabelRegistration(_CypherCaptureMixin, unittest.TestCase):
    NEW = {
        "authenticated-as": "AUTHENTICATED_AS",
        "owned-by": "OWNED_BY",
        "derived-from": "DERIVED_FROM",
        "triggered-by": "TRIGGERED_BY",
        "mutated": "MUTATED",
    }

    def test_graph_sync_mapping_has_all_five(self):
        for k, v in self.NEW.items():
            self.assertEqual(self.lf.RELATIONSHIP_TYPE_TO_EDGE_LABEL[k], v)

    def test_byte_identical_with_graph_query_api(self):
        """ENC-ISS-178 drift guard: the 5 labels must also be in graph_query_api
        _ALLOWED_EDGE_TYPES. Read the sibling lambda's source (no import — avoids its heavy
        neo4j deps) and assert each label token is present in the frozenset literal."""
        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "graph_query_api", "lambda_function.py",
        )
        with open(path) as fh:
            src = fh.read()
        m = re.search(r"_ALLOWED_EDGE_TYPES\s*=\s*frozenset\(\{(.*?)\}\)", src, re.DOTALL)
        self.assertIsNotNone(m, "could not locate _ALLOWED_EDGE_TYPES frozenset literal")
        body = m.group(1)
        for label in self.NEW.values():
            self.assertIn(f'"{label}"', body, f"{label} missing from _ALLOWED_EDGE_TYPES")


class TestUpsertAgentNode(_CypherCaptureMixin, unittest.TestCase):
    def _upsert(self, record):
        tx = MagicMock()
        self.lf._upsert_agent_node(tx, record)
        return tx

    def test_identity_node_label(self):
        tx = self._upsert({
            "record_type": "agent_identity", "record_id": "ENC-AGT-005",
            "agent_type_id": "ENC-AGT-005", "surface": "cli", "model": "opus", "status": "active",
        })
        calls = self._calls(tx)
        self.assertTrue(any(":AgentIdentity" in c for c in calls), calls)

    def test_session_node_label_and_props(self):
        tx = self._upsert({
            "record_type": "agent_session", "record_id": "ENC-SES-030",
            "session_id": "ENC-SES-030", "agent_type_id": "ENC-AGT-005",
            "status": "claimed", "credential_id": "CRED-abc",
        })
        calls = self._calls(tx)
        self.assertTrue(any(":AgentSession" in c for c in calls), calls)
        # credential_id must be carried into the projected props
        props = tx.run.call_args_list[0].kwargs.get("props", {})
        self.assertEqual(props.get("credential_id"), "CRED-abc")
        self.assertEqual(props.get("record_id"), "ENC-SES-030")

    def test_credential_node_label(self):
        tx = self._upsert({
            "record_type": "agent_credential", "record_id": "CRED-abc",
            "credential_id": "CRED-abc", "agent_identity_id": "ENC-AGT-005", "status": "active",
        })
        calls = self._calls(tx)
        self.assertTrue(any(":AgentCredential" in c for c in calls), calls)

    def test_counter_sentinel_skipped(self):
        tx = self._upsert({
            "record_type": "agent_session", "record_id": "counter#ENC-SES",
            "session_id": "counter#ENC-SES",
        })
        tx.run.assert_not_called()


class TestReconcileAgentEdges(_CypherCaptureMixin, unittest.TestCase):
    def _reconcile(self, record):
        tx = MagicMock()
        self.lf._reconcile_agent_edges(tx, record)
        return self._calls(tx)

    def test_authenticated_as(self):
        calls = self._reconcile({
            "record_type": "agent_session", "record_id": "ENC-SES-030",
            "agent_type_id": "ENC-AGT-005", "parent_session_id": "root",
        })
        self.assertTrue(any("AUTHENTICATED_AS" in c for c in calls), calls)
        self.assertTrue(any(":AgentIdentity" in c for c in calls), calls)

    def test_triggered_by_parent_session(self):
        calls = self._reconcile({
            "record_type": "agent_session", "record_id": "ENC-SES-031",
            "agent_type_id": "ENC-AGT-005", "parent_session_id": "ENC-SES-030",
        })
        self.assertTrue(any("TRIGGERED_BY" in c for c in calls), calls)

    def test_triggered_by_root_skipped(self):
        calls = self._reconcile({
            "record_type": "agent_session", "record_id": "ENC-SES-030",
            "agent_type_id": "ENC-AGT-005", "parent_session_id": "root",
        })
        self.assertFalse(any("TRIGGERED_BY" in c for c in calls), calls)

    def test_owned_by(self):
        calls = self._reconcile({
            "record_type": "agent_credential", "record_id": "CRED-abc",
            "agent_identity_id": "ENC-AGT-005",
        })
        self.assertTrue(any("OWNED_BY" in c for c in calls), calls)

    def test_derived_from_when_rotated(self):
        calls = self._reconcile({
            "record_type": "agent_credential", "record_id": "CRED-child",
            "agent_identity_id": "ENC-AGT-005", "rotated_from": "CRED-parent",
        })
        self.assertTrue(any("DERIVED_FROM" in c for c in calls), calls)

    def test_derived_from_absent_without_rotation(self):
        calls = self._reconcile({
            "record_type": "agent_credential", "record_id": "CRED-root",
            "agent_identity_id": "ENC-AGT-005", "rotated_from": "",
        })
        self.assertFalse(any("DERIVED_FROM" in c for c in calls), calls)


class TestMutatedEdgeHook(_CypherCaptureMixin, unittest.TestCase):
    def test_mutated_edge_from_provider(self):
        record = {
            "record_type": "task", "record_id": "ENC-TSK-J04",
            "write_source": {"provider": "ENC-SES-029"},
        }
        driven = self._run_session_capture(self.lf._project_mutated_edge, record)
        self.assertEqual(len(driven), 1)
        calls = self._calls(driven[0])
        self.assertTrue(any("MUTATED" in c for c in calls), calls)
        self.assertTrue(any(":AgentSession" in c for c in calls), calls)
        self.assertTrue(any(":Task" in c for c in calls), calls)

    def test_no_edge_when_provider_not_session(self):
        record = {
            "record_type": "task", "record_id": "ENC-TSK-J04",
            "write_source": {"provider": "github"},
        }
        session = MagicMock()
        self.lf._project_mutated_edge(session, record)
        session.execute_write.assert_not_called()

    def test_no_self_edge(self):
        record = {
            "record_type": "agent_session", "record_id": "ENC-SES-029",
            "write_source": {"provider": "ENC-SES-029"},
        }
        session = MagicMock()
        self.lf._project_mutated_edge(session, record)
        session.execute_write.assert_not_called()

    def test_no_edge_without_write_source(self):
        record = {"record_type": "task", "record_id": "ENC-TSK-J04"}
        session = MagicMock()
        self.lf._project_mutated_edge(session, record)
        session.execute_write.assert_not_called()


if __name__ == "__main__":
    unittest.main()
