import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from gateway_mcp_probe import parse_body, tools_ok  # noqa: E402

GOOD = '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"search"},{"name":"get_compact_context"}]}}'


class GatewayProbe(unittest.TestCase):
    def test_json_ok(self):
        self.assertTrue(tools_ok(parse_body(GOOD))[0])

    def test_sse_ok(self):
        self.assertTrue(tools_ok(parse_body("event: message\ndata: " + GOOD + "\n\n"))[0])

    def test_error_fails(self):
        msg = parse_body('{"jsonrpc":"2.0","id":2,"error":{"code":-32603,"message":"Internal error"}}')
        self.assertFalse(tools_ok(msg)[0])

    def test_missing_tool_fails(self):
        self.assertFalse(tools_ok({"result": {"tools": [{"name": "search"}]}})[0])

    def test_no_payload_raises(self):
        with self.assertRaises(ValueError):
            parse_body("event: ping\n")


if __name__ == "__main__":
    unittest.main()
