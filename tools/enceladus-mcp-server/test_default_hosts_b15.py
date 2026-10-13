#!/usr/bin/env python3
"""DVP-TSK-B15 (isolation W5a): server.py self-call defaults must not point at the shared jreese.net host.

The prod MCP server calls the Enceladus API on https://enceladus.jreese.net. A default that starts with
https://jreese.net/ would silently route prod self-calls through the shared host being retired.
Static (AST) scan, so it needs no server import side effects.
"""

import ast
import os
import re
import unittest

_SERVER = os.path.join(os.path.dirname(__file__), "server.py")
_OLD_HOST_PREFIX = "https://jreese.net/"
_NEW_HOST_PREFIX = "https://enceladus.jreese.net/"


def _api_base_defaults():
    """Return {NAME: [string constants]} for module-level *_API_BASE / *_API_URL assignments."""
    with open(_SERVER, encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), filename=_SERVER)
    found = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and re.search(r"_API_(BASE|URL)$", target.id):
                found[target.id] = [
                    n.value for n in ast.walk(node.value) if isinstance(n, ast.Constant) and isinstance(n.value, str)
                ]
    return found


class TestServerDefaultHosts(unittest.TestCase):
    def test_api_base_defaults_found(self):
        self.assertIn("COORDINATION_API_BASE", _api_base_defaults())

    def test_no_api_base_default_uses_shared_jreese_host(self):
        for name, constants in _api_base_defaults().items():
            for value in constants:
                with self.subTest(name=name, value=value):
                    self.assertFalse(value.startswith(_OLD_HOST_PREFIX), f"{name} default still on jreese.net: {value}")

    def test_http_defaults_use_enceladus_host_or_direct_gateway(self):
        for name, constants in _api_base_defaults().items():
            for value in constants:
                if not value.startswith("https://") or ".execute-api." in value:
                    continue
                with self.subTest(name=name, value=value):
                    self.assertTrue(value.startswith(_NEW_HOST_PREFIX), f"{name} default off enceladus.jreese.net: {value}")


if __name__ == "__main__":
    unittest.main()
