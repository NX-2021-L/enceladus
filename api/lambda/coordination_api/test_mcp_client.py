import importlib.util
import pathlib
import unittest


MODULE_PATH = pathlib.Path(__file__).with_name("mcp_client.py")
SPEC = importlib.util.spec_from_file_location("coordination_mcp_client", MODULE_PATH)
mcp_client = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(mcp_client)


class CoordinationMcpClientTests(unittest.TestCase):
    def test_write_capability_includes_governance_hash(self):
        client = mcp_client.CoordinationMcpClient()
        result = client.coordination_request_dispatch(
            request_id="CRQ-123",
            execution_mode="codex_app_server",
            provider_session={},
        )
        self.assertIn("governance_hash", result)
        self.assertEqual(len(result["governance_hash"]), 64)
        self.assertEqual(result["normalized_state"], "running")

    def test_codex_session_start_is_deterministic_for_request_thread(self):
        client = mcp_client.CoordinationMcpClient()
        session_a = client.codex_session_start(
            request_id="CRQ-ABC",
            thread_id="thread-fixed",
            fork_from_thread_id="",
            model="gpt-5-codex",
        )
        session_b = client.codex_session_start(
            request_id="CRQ-ABC",
            thread_id="thread-fixed",
            fork_from_thread_id="",
            model="gpt-5-codex",
        )
        self.assertEqual(session_a["provider_session_id"], session_b["provider_session_id"])
        self.assertEqual(session_a["turn_id"], session_b["turn_id"])

    def test_codex_turn_complete_preserves_existing_session_identity(self):
        client = mcp_client.CoordinationMcpClient()
        result = client.codex_turn_complete(
            request_id="CRQ-XYZ",
            command_id="cmd-001",
            provider_result={"turn_status": "completed"},
            existing_provider_session={
                "provider_session_id": "psn-existing",
                "thread_id": "thread-existing",
                "turn_id": "turn-existing",
                "model": "gpt-5-codex",
            },
        )
        self.assertEqual(result["provider_session_id"], "psn-existing")
        self.assertEqual(result["thread_id"], "thread-existing")
        self.assertEqual(result["turn_id"], "turn-existing")
        self.assertEqual(result["execution_id"], "cmd-001")


if __name__ == "__main__":
    unittest.main()
