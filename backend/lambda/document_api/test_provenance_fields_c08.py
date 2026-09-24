"""Tests for ENC-TSK-C08 / ENC-FTR-065: document_api provenance field handling.

The HCE writes consolidated_from / proposed_by / fsrs_initial_stability at
candidate creation and PATCHes informed_by for GDMP Stage 2. _extract_provenance_fields
is the shared validator/serializer used by both PUT and PATCH.
"""
import unittest

import lambda_function as da


class TestExtractProvenanceFields(unittest.TestCase):
    def test_empty_body_no_fields(self):
        self.assertEqual(da._extract_provenance_fields({})["item_fields"], {})

    def test_consolidated_from_serialized(self):
        out = da._extract_provenance_fields({"consolidated_from": ["DOC-1", " DOC-2 ", ""]})
        self.assertEqual(
            out["item_fields"]["consolidated_from"],
            {"L": [{"S": "DOC-1"}, {"S": "DOC-2"}]},
        )

    def test_informed_by_serialized(self):
        out = da._extract_provenance_fields({"informed_by": ["DOC-A"]})
        self.assertEqual(out["item_fields"]["informed_by"], {"L": [{"S": "DOC-A"}]})

    def test_proposed_by_serialized(self):
        out = da._extract_provenance_fields({"proposed_by": "ENC-FTR-064"})
        self.assertEqual(out["item_fields"]["proposed_by"], {"S": "ENC-FTR-064"})

    def test_fsrs_initial_stability_serialized(self):
        out = da._extract_provenance_fields({"fsrs_initial_stability": 4.25})
        self.assertEqual(out["item_fields"]["fsrs_initial_stability"], {"N": "4.25"})

    def test_non_list_consolidated_from_errors(self):
        out = da._extract_provenance_fields({"consolidated_from": "DOC-1"})
        self.assertIn("error", out)

    def test_non_numeric_stability_errors(self):
        out = da._extract_provenance_fields({"fsrs_initial_stability": "high"})
        self.assertIn("error", out)

    def test_negative_stability_errors(self):
        out = da._extract_provenance_fields({"fsrs_initial_stability": -1})
        self.assertIn("error", out)


if __name__ == "__main__":
    unittest.main()
