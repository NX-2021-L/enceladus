"""ENC-ISS-133 / ENC-TSK-F09 regression tests for the TASK legacy-segment alias.

40 records created before the TSK convention (JAP-TASK-*, HFY-TASK-*, ISG-TASK-*)
must parse correctly via _parse_record_id and _tracker_key without rewriting their
DynamoDB keys. Canonical minting paths (_TRACKER_TYPE_SUFFIX equivalents) are not
tested here because the MCP server server.py only holds the read-side _ID_SEGMENT_TO_TYPE.
"""

import importlib.util
import pathlib
import sys
import unittest
from unittest.mock import patch


MODULE_PATH = pathlib.Path(__file__).with_name("server.py")
SPEC = importlib.util.spec_from_file_location("enceladus_server_legacy_alias", MODULE_PATH)
server = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = server
SPEC.loader.exec_module(server)


_FAKE_PREFIX_MAP = {
    "JAP": "jobapps",
    "HFY": "harrisonfamily",
    "ISG": "intelligent-scraper-generator",
    "ENC": "enceladus",
}


class LegacyTaskSegmentAliasTests(unittest.TestCase):
    def test_task_segment_is_task_type(self):
        self.assertEqual(server._ID_SEGMENT_TO_TYPE["TASK"], "task")

    def test_canonical_tsk_still_present(self):
        self.assertEqual(server._ID_SEGMENT_TO_TYPE["TSK"], "task")

    def test_parse_record_id_accepts_jap_task(self):
        with patch.object(server, "_get_prefix_map", return_value=_FAKE_PREFIX_MAP):
            project_id, record_type, normalized = server._parse_record_id("JAP-TASK-421")
        self.assertEqual(project_id, "jobapps")
        self.assertEqual(record_type, "task")
        self.assertEqual(normalized, "JAP-TASK-421")

    def test_parse_record_id_accepts_hfy_task(self):
        with patch.object(server, "_get_prefix_map", return_value=_FAKE_PREFIX_MAP):
            _, record_type, normalized = server._parse_record_id("HFY-TASK-024")
        self.assertEqual(record_type, "task")
        self.assertEqual(normalized, "HFY-TASK-024")

    def test_parse_record_id_accepts_isg_task(self):
        with patch.object(server, "_get_prefix_map", return_value=_FAKE_PREFIX_MAP):
            _, record_type, normalized = server._parse_record_id("ISG-TASK-205")
        self.assertEqual(record_type, "task")
        self.assertEqual(normalized, "ISG-TASK-205")

    def test_tracker_key_for_legacy_jap_task(self):
        with patch.object(server, "_get_prefix_map", return_value=_FAKE_PREFIX_MAP):
            key = server._tracker_key("JAP-TASK-421")
        self.assertEqual(key["project_id"], {"S": "jobapps"})
        self.assertEqual(key["record_id"], {"S": "task#JAP-TASK-421"})

    def test_canonical_tsk_still_parses_correctly(self):
        with patch.object(server, "_get_prefix_map", return_value=_FAKE_PREFIX_MAP):
            project_id, record_type, normalized = server._parse_record_id("ENC-TSK-001")
        self.assertEqual(project_id, "enceladus")
        self.assertEqual(record_type, "task")
        self.assertEqual(normalized, "ENC-TSK-001")


if __name__ == "__main__":
    unittest.main()
