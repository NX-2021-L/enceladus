"""ENC-TSK-I82 AC-3: canonicalization unit tests.

'Implementation', ' implementation ', 'IMPLEMENTATION' all map to 'implementation'.
"""

import unittest

from canonicalize import CANON_VERSION, canonical_values, canonicalize


class TestCanonicalize(unittest.TestCase):
    def test_ac3_case_and_whitespace_collapse(self):
        for raw in ("Implementation", " implementation ", "IMPLEMENTATION"):
            self.assertEqual(canonicalize(raw), "implementation", msg=raw)

    def test_ac3_all_three_collapse_to_one_key(self):
        keys = {canonicalize(r) for r in ("Implementation", " implementation ", "IMPLEMENTATION")}
        self.assertEqual(keys, {"implementation"})

    def test_underscore_and_whitespace_to_hyphen(self):
        self.assertEqual(canonicalize("In Progress"), "in-progress")
        self.assertEqual(canonicalize("in_progress"), "in-progress")
        self.assertEqual(canonicalize("in   progress"), "in-progress")
        self.assertEqual(canonicalize("in__progress"), "in-progress")

    def test_strip_non_alphanumerics(self):
        self.assertEqual(canonicalize("P0!!"), "p0")
        self.assertEqual(canonicalize("bug/risk"), "bugrisk")
        self.assertEqual(canonicalize("--lead--"), "lead")

    def test_unicode_nfc_normalization(self):
        # Composed vs decomposed forms of 'é' must canonicalize identically.
        composed = "Caf\u00e9"          # café (single codepoint é)
        decomposed = "Cafe\u0301"        # café (e + combining acute)
        self.assertEqual(canonicalize(composed), canonicalize(decomposed))

    def test_empty_and_none(self):
        self.assertEqual(canonicalize(None), "")
        self.assertEqual(canonicalize("   "), "")
        self.assertEqual(canonicalize("!!!"), "")

    def test_canonical_values_list_fanout_and_dedup(self):
        out = canonical_values(["Backend", "backend ", "Infra"])
        self.assertEqual(out, ["backend", "infra"])

    def test_canonical_values_scalar(self):
        self.assertEqual(canonical_values("Implementation"), ["implementation"])

    def test_canon_version_is_int(self):
        self.assertIsInstance(CANON_VERSION, int)


if __name__ == "__main__":
    unittest.main()
