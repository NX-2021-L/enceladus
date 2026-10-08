import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from check_requirements_pins import check_text  # noqa: E402


class CheckRequirementsPins(unittest.TestCase):
    def test_bare_line_fails(self):
        self.assertEqual(len(check_text("PyJWT==2.10.1\ncertifi\n")), 1)

    def test_unpinned_mcp_fails(self):
        errs = check_text("mcp\n")
        self.assertEqual(len(errs), 1)
        self.assertIn("bare", errs[0])

    def test_mcp_range_fails(self):
        self.assertEqual(len(check_text("mcp>=1.0,<2\n")), 1)
        self.assertEqual(len(check_text("mcp>=1.26.0\n")), 1)

    def test_mcp_exact_ok(self):
        self.assertEqual(check_text("mcp==1.26.0\n"), [])

    def test_range_ok(self):
        self.assertEqual(check_text("certifi>=2024.2.2\nPyJWT>=2.8.0,<3.0\n"), [])

    def test_ignored_lines(self):
        text = "# comment\n\n-r base.txt\n--index-url https://x\n-c c.txt\nboto3==1.35.99  # pin\n"
        self.assertEqual(check_text(text), [])

    def test_extras_and_markers(self):
        self.assertEqual(check_text("requests[socks]>=2\n"), [])
        self.assertEqual(len(check_text("requests[socks]\n")), 1)
        self.assertEqual(len(check_text("foo ; python_version<'3.9'\n")), 1)


if __name__ == "__main__":
    unittest.main()
