"""DVP-TSK-A78: every vendored content_store.py must equal the canonical shared-layer copy."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import sync_content_store as s  # noqa: E402


class TestVendoredCopies(unittest.TestCase):
    def test_canonical_exists(self):
        self.assertTrue(os.path.isfile(s.CANONICAL))

    def test_no_vendored_copy_has_drifted(self):
        self.assertEqual(s.check(), 0)


if __name__ == "__main__":
    unittest.main()
