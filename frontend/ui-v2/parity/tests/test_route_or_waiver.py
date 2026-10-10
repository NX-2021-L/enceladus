"""DVP-TSK-862 AC3: a PR that adds a registry action without a route or a waiver fails the
blocking ratchet; a waiver (or a route/map entry) in the same PR passes. Uses the real
io-kit CLI against a fixture copy of caps.json; skipped when the CLI is not on PATH."""
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

PARITY = Path(__file__).resolve().parents[1]
CAPS = PARITY.parents[2] / "tools" / "enceladus-mcp-server" / "parity" / "caps.json"
CLI = shutil.which("io-kit")


@unittest.skipUnless(CLI, "io-kit CLI not installed")
class RouteOrWaiver(unittest.TestCase):
    def run_check(self, waivers: str | None):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            caps = json.loads(CAPS.read_text())
            caps["actions"].append({**caps["actions"][0], "name": "fixture.new_action"})  # unflagged, unmapped
            (td / "caps.json").write_text(json.dumps(caps))
            (td / "waivers.yaml").write_text(waivers if waivers is not None else "waivers: []\n")
            cmd = [CLI, "parity", "baseline", "check", "--baseline", str(PARITY / "baseline.json"),
                   "--caps", str(td / "caps.json"), "--routes", str(PARITY / "routes.yaml"),
                   "--stack", "enceladus.jreese.net", "--mapping", str(PARITY / "map.yaml"),
                   "--waivers", str(td / "waivers.yaml"), "--mode", "blocking", "--today", "2026-10-10"]
            return subprocess.run(cmd, capture_output=True, text=True)

    def test_new_action_without_route_or_waiver_fails(self):
        r = self.run_check(None)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("PARITY-FAIL", r.stdout)

    def test_new_action_with_waiver_passes(self):
        w = ('waivers:\n  - {action: fixture.new_action, surface: enceladus, owner: DVP-TSK-862, '
             'reason: fixture, expires: "2026-11-01"}\n')
        r = self.run_check(w)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
