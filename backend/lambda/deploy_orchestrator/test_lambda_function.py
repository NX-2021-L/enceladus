"""deploy_orchestrator integration analysis regression tests.

Ensures overlap analysis warns instead of hard-failing so pending deploy
requests are not left unprocessed.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest

_SPEC = importlib.util.spec_from_file_location(
    "deploy_orchestrator",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
deploy_orchestrator = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
sys.modules[_SPEC.name] = deploy_orchestrator
_SPEC.loader.exec_module(deploy_orchestrator)


class DeployOrchestratorIntegrationAnalysisTests(unittest.TestCase):
    def test_analyze_integration_passes_without_overlaps(self) -> None:
        requests = [
            {"request_id": "REQ-1", "files_changed": ["frontend/ui/src/app.tsx"], "related_record_ids": []},
            {"request_id": "REQ-2", "files_changed": ["frontend/ui/src/hooks/useFeed.ts"], "related_record_ids": []},
        ]
        result = deploy_orchestrator._analyze_integration(requests)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["file_overlaps"], [])
        self.assertEqual(result["warnings"], [])

    def test_analyze_integration_warns_on_regular_file_overlap(self) -> None:
        requests = [
            {"request_id": "REQ-1", "files_changed": ["frontend/ui/src/app.tsx"], "related_record_ids": []},
            {"request_id": "REQ-2", "files_changed": ["frontend/ui/src/app.tsx"], "related_record_ids": []},
        ]
        result = deploy_orchestrator._analyze_integration(requests)
        self.assertEqual(result["status"], "warning")
        self.assertTrue(any("frontend/ui/src/app.tsx" in msg for msg in result["warnings"]))

    def test_analyze_integration_warns_not_fails_for_version_overlap(self) -> None:
        requests = [
            {"request_id": "REQ-1", "files_changed": ["frontend/ui/src/lib/version.ts"], "related_record_ids": []},
            {"request_id": "REQ-2", "files_changed": ["frontend/ui/src/lib/version.ts"], "related_record_ids": []},
        ]
        result = deploy_orchestrator._analyze_integration(requests)
        self.assertEqual(result["status"], "warning")
        self.assertTrue(any("version.ts" in msg for msg in result["warnings"]))


if __name__ == "__main__":
    unittest.main()
