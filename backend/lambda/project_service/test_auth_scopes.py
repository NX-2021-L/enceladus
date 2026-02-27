from __future__ import annotations

import importlib.util
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

_SPEC = importlib.util.spec_from_file_location(
    "project_service",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
project_service = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(project_service)


class ProjectServiceScopeTests(unittest.TestCase):
    def setUp(self):
        self._orig_scopes = project_service.INTERNAL_API_KEY_SCOPES

    def tearDown(self):
        project_service.INTERNAL_API_KEY_SCOPES = self._orig_scopes

    def test_internal_key_scope_denied_for_write(self):
        project_service.INTERNAL_API_KEY_SCOPES = {"scope-key": {"projects:read"}}
        self.assertFalse(
            project_service._internal_key_has_scopes(
                "scope-key",
                ["projects:write"],
            )
        )

    def test_internal_key_scope_prefix_allows_write(self):
        project_service.INTERNAL_API_KEY_SCOPES = {"scope-key": {"projects:*"}}
        self.assertTrue(
            project_service._internal_key_has_scopes(
                "scope-key",
                ["projects:write"],
            )
        )


if __name__ == "__main__":
    unittest.main()
