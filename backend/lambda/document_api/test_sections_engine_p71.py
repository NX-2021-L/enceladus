"""test_sections_engine_p71.py — Unit tests for the pure section-patch engine
(ENC-TSK-P71 / FR-B1-13..25), sections.py.

No mocking needed here — sections.py is pure (no boto3), so these exercise
resolve_anchor / apply_patch / rebase_body_headings / generate_ulid directly
against outline.compute_outline_with_spans() output.

Covers:
  AC-2: anchor resolution order (block_id, block_id+heading_path agree/
        disagree, heading_path+ordinal, ambiguous, not-found).
  AC-3: section extent + replace/append/prepend/delete, include_heading,
        exactly-one-blank-line normalization, trailing-whitespace stripping.
  AC-4: heading rebasing (ATX shift, setext->ATX first, fenced code untouched,
        rebase_headings=false leaves body verbatim).
  AC-5: block-id stamping on first patch of an anchor lacking one; no
        duplicate block_id after a sequence of operations.

Run: python3 -m pytest test_sections_engine_p71.py -v
"""

from __future__ import annotations

import re
import unittest

import outline
import sections


BLOCK_ID_RE = re.compile(r"<!-- enc:block:([0-9A-Za-z]{26}) -->")


def _outline(doc: str):
    return outline.compute_outline_with_spans(doc)


class TestAnchorResolution(unittest.TestCase):
    DOC = (
        "# Title\n\n"
        "## Alpha\n<!-- enc:block:01ARZ3NDEKTSV4RRFFQ69G5FAV -->\nAlpha body.\n\n"
        "## Beta\n\nBeta body.\n\n"
        "## Alpha\n\nSecond alpha body.\n"
    )

    def test_resolve_by_block_id(self):
        entries = _outline(self.DOC)
        entry = sections.resolve_anchor(entries, {"block_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV"})
        self.assertEqual(entry["heading_path"], ["Alpha"])
        self.assertEqual(entry["ordinal"], 1)

    def test_block_id_and_agreeing_heading_path_ok(self):
        entries = _outline(self.DOC)
        entry = sections.resolve_anchor(
            entries, {"block_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV", "heading_path": ["Alpha"]},
        )
        self.assertEqual(entry["ordinal"], 1)

    def test_block_id_and_disagreeing_heading_path_ambiguous(self):
        entries = _outline(self.DOC)
        with self.assertRaises(sections.AnchorError) as ctx:
            sections.resolve_anchor(
                entries, {"block_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV", "heading_path": ["Beta"]},
            )
        exc = ctx.exception
        self.assertEqual(exc.status, 409)
        self.assertEqual(exc.code, "ANCHOR_AMBIGUOUS")
        self.assertIn("candidates", exc.details)
        self.assertGreaterEqual(len(exc.details["candidates"]), 2)

    def test_heading_path_without_ordinal_ambiguous(self):
        entries = _outline(self.DOC)
        with self.assertRaises(sections.AnchorError) as ctx:
            sections.resolve_anchor(entries, {"heading_path": ["Alpha"]})
        self.assertEqual(ctx.exception.status, 409)
        self.assertEqual(ctx.exception.code, "ANCHOR_AMBIGUOUS")
        self.assertEqual(len(ctx.exception.details["candidates"]), 2)

    def test_heading_path_with_ordinal_resolves(self):
        entries = _outline(self.DOC)
        entry = sections.resolve_anchor(entries, {"heading_path": ["Alpha"], "ordinal": 2})
        self.assertEqual(entry["ordinal"], 2)
        self.assertEqual(entry["line_start"], entries[3]["line_start"])

    def test_heading_path_whitespace_normalized_case_sensitive(self):
        entries = _outline(self.DOC)
        entry = sections.resolve_anchor(entries, {"heading_path": ["  Beta  "]})
        self.assertEqual(entry["heading_path"], ["Beta"])
        with self.assertRaises(sections.AnchorError):
            sections.resolve_anchor(entries, {"heading_path": ["beta"]})  # case-sensitive

    def test_not_found_includes_full_outline(self):
        entries = _outline(self.DOC)
        with self.assertRaises(sections.AnchorError) as ctx:
            sections.resolve_anchor(entries, {"heading_path": ["Nonexistent"]})
        self.assertEqual(ctx.exception.status, 404)
        self.assertEqual(ctx.exception.code, "ANCHOR_NOT_FOUND")
        self.assertEqual(len(ctx.exception.details["outline"]), len(entries))

    def test_no_block_id_or_heading_path_invalid(self):
        entries = _outline(self.DOC)
        with self.assertRaises(sections.AnchorError) as ctx:
            sections.resolve_anchor(entries, {"ordinal": 1})
        self.assertEqual(ctx.exception.status, 400)


class TestSectionOps(unittest.TestCase):
    def _doc(self):
        return (
            "# Title\n\n"
            "## Alpha\n<!-- enc:block:01ARZ3NDEKTSV4RRFFQ69G5FAV -->\n"
            "Existing alpha body.\n\n"
            "## Beta\n\nBeta body.\n"
        )

    def _alpha(self, doc):
        entries = _outline(doc)
        return sections.resolve_anchor(entries, {"block_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV"})

    def test_replace(self):
        doc = self._doc()
        entry = self._alpha(doc)
        r = sections.apply_patch(doc, entry, "replace", "New content.", rebase_headings=False)
        self.assertIn("New content.", r["content"])
        self.assertNotIn("Existing alpha body.", r["content"])
        # exactly one blank line above/below
        self.assertIn(
            "<!-- enc:block:01ARZ3NDEKTSV4RRFFQ69G5FAV -->\n\nNew content.\n\n## Beta",
            r["content"],
        )

    def test_append_inserts_after_last_nonblank_line(self):
        doc = self._doc()
        entry = self._alpha(doc)
        r = sections.apply_patch(doc, entry, "append", "Appended.", rebase_headings=False)
        self.assertIn("Existing alpha body.\n\nAppended.", r["content"])

    def test_prepend_inserts_before_first_nonblank_line(self):
        doc = self._doc()
        entry = self._alpha(doc)
        r = sections.apply_patch(doc, entry, "prepend", "Prepended.", rebase_headings=False)
        self.assertIn("Prepended.\n\nExisting alpha body.", r["content"])

    def test_delete_without_include_heading_keeps_heading(self):
        doc = self._doc()
        entry = self._alpha(doc)
        r = sections.apply_patch(doc, entry, "delete", None)
        self.assertIn("## Alpha", r["content"])
        self.assertIn("<!-- enc:block:01ARZ3NDEKTSV4RRFFQ69G5FAV -->", r["content"])
        self.assertNotIn("Existing alpha body.", r["content"])
        self.assertEqual(r["block_id"], "01ARZ3NDEKTSV4RRFFQ69G5FAV")

    def test_delete_with_include_heading_removes_heading_and_comment(self):
        doc = self._doc()
        entry = self._alpha(doc)
        r = sections.apply_patch(doc, entry, "delete", None, include_heading=True)
        self.assertNotIn("## Alpha", r["content"])
        self.assertNotIn("enc:block:01ARZ3NDEKTSV4RRFFQ69G5FAV", r["content"])
        self.assertIn("## Beta", r["content"])
        self.assertIsNone(r["block_id"])

    def test_replace_include_heading_renames_heading(self):
        doc = self._doc()
        entry = self._alpha(doc)
        r = sections.apply_patch(
            doc, entry, "replace", "### Renamed\n\nNew body.",
            include_heading=True, rebase_headings=False,
        )
        self.assertIn("### Renamed", r["content"])
        self.assertNotIn("## Alpha", r["content"])
        self.assertIn("New body.", r["content"])

    def test_trailing_whitespace_stripped_on_inserted_lines(self):
        doc = self._doc()
        entry = self._alpha(doc)
        r = sections.apply_patch(doc, entry, "replace", "Line with trailing spaces.   \n", rebase_headings=False)
        self.assertIn("Line with trailing spaces.\n", r["content"])
        self.assertNotIn("spaces.   \n", r["content"])

    def test_bytes_changed_reported(self):
        doc = self._doc()
        entry = self._alpha(doc)
        r = sections.apply_patch(doc, entry, "append", "x", rebase_headings=False)
        self.assertEqual(r["bytes_changed"], abs(r["after_bytes"] - r["before_bytes"]))
        self.assertGreater(r["bytes_changed"], 0)


class TestBlockIdStamping(unittest.TestCase):
    def test_stamps_on_first_patch_when_absent(self):
        doc = "# Title\n\n## Alpha\n\nbody.\n"
        entry = sections.resolve_anchor(_outline(doc), {"heading_path": ["Alpha"]})
        self.assertIsNone(entry["block_id"])
        r = sections.apply_patch(doc, entry, "append", "more.", rebase_headings=False)
        self.assertTrue(r["stamped"])
        self.assertIsNotNone(r["block_id"])
        m = BLOCK_ID_RE.search(r["content"])
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), r["block_id"])

    def test_no_duplicate_block_id_after_sequence_of_ops(self):
        doc = "# Title\n\n## Alpha\n\nbody a.\n\n## Beta\n\nbody b.\n"
        entries = _outline(doc)
        alpha = sections.resolve_anchor(entries, {"heading_path": ["Alpha"]})
        r1 = sections.apply_patch(doc, alpha, "append", "x1", rebase_headings=False)
        doc2 = r1["content"]

        entries2 = _outline(doc2)
        beta = sections.resolve_anchor(entries2, {"heading_path": ["Beta"]})
        r2 = sections.apply_patch(doc2, beta, "append", "x2", rebase_headings=False)
        doc3 = r2["content"]

        # Re-patch Alpha again (now has a block_id) — must NOT re-stamp.
        entries3 = _outline(doc3)
        alpha_again = sections.resolve_anchor(entries3, {"block_id": r1["block_id"]})
        r3 = sections.apply_patch(doc3, alpha_again, "append", "x3", rebase_headings=False)
        self.assertFalse(r3["stamped"])
        self.assertEqual(r3["block_id"], r1["block_id"])

        all_ids = BLOCK_ID_RE.findall(r3["content"])
        self.assertEqual(len(all_ids), len(set(all_ids)), "block_id must never appear twice")
        self.assertEqual(len(all_ids), 2)

    def test_stamp_not_applied_on_delete_include_heading(self):
        doc = "# Title\n\n## Alpha\n\nbody.\n"
        entry = sections.resolve_anchor(_outline(doc), {"heading_path": ["Alpha"]})
        r = sections.apply_patch(doc, entry, "delete", None, include_heading=True)
        self.assertFalse(r["stamped"])
        self.assertIsNone(r["block_id"])
        self.assertNotIn("enc:block:", r["content"])


class TestRebaseHeadings(unittest.TestCase):
    def test_shallowest_becomes_anchor_level_plus_one(self):
        doc = "# Title\n\n## Section\n\nbody.\n"
        entry = sections.resolve_anchor(_outline(doc), {"heading_path": ["Section"]})
        body = "# Sub One\n\ntext\n\n## Sub Two\n\nmore text\n"
        r = sections.apply_patch(doc, entry, "replace", body, rebase_headings=True)
        self.assertIn("### Sub One", r["content"])
        self.assertIn("#### Sub Two", r["content"])

    def test_clamped_at_6(self):
        doc = "# Title\n\n###### Deep\n\nbody.\n"
        entry = sections.resolve_anchor(_outline(doc), {"heading_path": ["Deep"]})
        r = sections.apply_patch(doc, entry, "replace", "# One\n\ntext\n", rebase_headings=True)
        # target_level = min(6, 6+1) = 6; shallowest(1) -> shift +5 -> level 6 clamped
        self.assertIn("###### One", r["content"])

    def test_setext_converted_to_atx_before_rebase(self):
        doc = "# Title\n\n## Section\n\nbody.\n"
        entry = sections.resolve_anchor(_outline(doc), {"heading_path": ["Section"]})
        body = "Setext One\n==========\n\ntext\n"
        r = sections.apply_patch(doc, entry, "replace", body, rebase_headings=True)
        self.assertIn("### Setext One", r["content"])
        self.assertNotIn("==========", r["content"])

    def test_fenced_code_headings_untouched(self):
        doc = "# Title\n\n## Section\n\nbody.\n"
        entry = sections.resolve_anchor(_outline(doc), {"heading_path": ["Section"]})
        body = "# Real Heading\n\n```\n# not a heading\n```\n"
        r = sections.apply_patch(doc, entry, "replace", body, rebase_headings=True)
        self.assertIn("### Real Heading", r["content"])
        self.assertIn("# not a heading", r["content"])
        self.assertNotIn("### not a heading", r["content"])
        self.assertNotIn("#### not a heading", r["content"])

    def test_rebase_false_leaves_body_verbatim(self):
        doc = "# Title\n\n## Section\n\nbody.\n"
        entry = sections.resolve_anchor(_outline(doc), {"heading_path": ["Section"]})
        body = "# Untouched Heading\n\ntext\n"
        r = sections.apply_patch(doc, entry, "replace", body, rebase_headings=False)
        self.assertIn("# Untouched Heading", r["content"])
        self.assertNotIn("### Untouched Heading", r["content"])


class TestValidateOpAndBody(unittest.TestCase):
    def test_delete_with_body_forbidden(self):
        err = sections.validate_op_and_body("delete", "oops")
        self.assertEqual(err[0], "OP_BODY_FORBIDDEN")

    def test_delete_without_body_ok(self):
        self.assertIsNone(sections.validate_op_and_body("delete", None))

    def test_replace_without_body_required(self):
        err = sections.validate_op_and_body("replace", None)
        self.assertEqual(err[0], "OP_BODY_REQUIRED")
        err = sections.validate_op_and_body("append", "")
        self.assertEqual(err[0], "OP_BODY_REQUIRED")

    def test_replace_with_body_ok(self):
        self.assertIsNone(sections.validate_op_and_body("replace", "x"))


class TestUlid(unittest.TestCase):
    def test_format(self):
        u = sections.generate_ulid()
        self.assertEqual(len(u), 26)
        self.assertRegex(u, r"^[0-9A-HJKMNP-TV-Z]{26}$")

    def test_accepted_by_outline_block_id_regex(self):
        doc = f"# Title\n\n## Alpha\n<!-- enc:block:{sections.generate_ulid()} -->\nbody.\n"
        entries = outline.compute_outline(doc)
        self.assertIsNotNone(entries[1]["block_id"])

    def test_uniqueness(self):
        ids = {sections.generate_ulid() for _ in range(200)}
        self.assertEqual(len(ids), 200)


if __name__ == "__main__":
    unittest.main()
