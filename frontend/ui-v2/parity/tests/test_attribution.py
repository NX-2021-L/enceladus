"""DVP-TSK-862 AC2: handler attribution is action-level precise on a committed fixture."""
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import generate_parity as g  # noqa: E402


class Attribution(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.real = g.SRC
        g.configure(HERE.parent / "fixtures" / "attribution" / "src")
        cls.routes = {r["path"]: r["handlers"] for r in g.build_routes()}

    @classmethod
    def tearDownClass(cls):
        g.configure(cls.real)

    def test_route_gets_only_the_symbols_it_imports(self):
        self.assertNotIn("POST /api/v1/beta", self.routes["/a"])  # shared module, not imported

    def test_method_pairs_with_its_own_url(self):
        self.assertEqual(self.routes["/a"], ["DELETE /api/v1/m2/{id}", "GET /api/v1/alpha", "GET /api/v1/m1"])

    def test_local_name_is_not_an_api_symbol(self):
        self.assertEqual(self.routes["/b"], [])


class Committed(unittest.TestCase):
    def test_committed_manifests_are_current(self):
        g.configure(HERE.parent.parent / "src")
        self.assertEqual(g.main(["--check"]), 0)


if __name__ == "__main__":
    unittest.main()
