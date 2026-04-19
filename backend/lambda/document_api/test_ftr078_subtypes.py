"""test_ftr078_subtypes.py - ENC-FTR-078 AC #22 matrix coverage.

Exhaustive unit and integration tests for the `idea`, `context-node`, `skill`
document subtype extensions plus Scope B `doc` subtypepattern / enum-hardening
mechanism. Derives from the authoritative spec:

    DOC-EDEFF7CD0BD5 - ENC-FTR Proposal: documents.put idea + context-node +
    skill subtype extensions + doc subtypepattern self-learning mechanism
    (v3 prod)

Each test in this module maps to one of the 17 lettered AC #22 items
(a)-(q) plus three integration-style scenarios that exercise end-to-end
round-trips through the (mocked) DynamoDB + S3 surfaces.

AC #22 coverage:

    (a) Happy-path PUT for each of doc, idea, context-node, skill,
        doc+subtypepattern                                       -> HappyPathPutTests
    (b) Context-node cap rejection (body 2049 chars)             -> ContextNodeCapTests
    (c) Context-node edge-density rejection (4 related_items)    -> ContextNodeEdgeDensityTests
    (d) Skill full_description rejection (4097 chars)            -> SkillFullDescriptionCapTests
    (e) Skill claude_description rejection (1025 chars)          -> SkillClaudeDescriptionCapTests
    (f) Skill missing-required-field rejection (x4)              -> SkillMissingFieldTests
    (g) agentskills_manifest non-conformant (missing name)       -> SkillManifestConformanceTests
    (h) runtime_variants with unknown keys accepted              -> SkillRuntimeVariantsTests
    (i) Title colon-prefix rejection (3 variants)                -> DocTitleColonPrefixTests
    (j) Subtypepattern canonicalization                          -> SubtypepatternCanonicalizationTests
    (k) Subtypepattern invalid formats (4 variants)              -> SubtypepatternInvalidFormatTests
    (l) Subtypepattern on non-doc subtype                        -> SubtypepatternWrongSubtypeTests
    (m) Search subtypepattern filter                             -> SearchSubtypepatternFilterTests
    (n) Non-enum document_subtype with redirect text             -> NonEnumSubtypeRedirectTests
    (o) Legacy-shape record readable                             -> LegacyRecordReadTests
    (p) Patch to legacy record not touching title/subtype        -> LegacyRecordPatchTests
    (q) Invalid subtype regression                               -> InvalidSubtypeRegressionTests

Integration tests:
    - Skill end-to-end round-trip with valid manifest            -> IntegrationSkillRoundTripTests
    - Context-node at exactly cap + N_MIN                        -> IntegrationContextNodeBoundaryTests
    - PATCH general subtype record to idea                       -> IntegrationLegacyToIdeaPatchTests

Mocking style mirrors `test_lambda_function.py`:
    - _authenticate is patched to return ({"sub": "user1"}, None)
    - _validate_project_exists is patched to return None (project exists)
    - _upload_content is patched to return a canned (s3_key, hash, size)
    - _get_ddb is patched to return a MagicMock whose put_item / get_item /
      scan / update_item methods are configured per-test

All tests are locally runnable with no AWS credentials. Run:

    python3 -m pytest test_ftr078_subtypes.py -v
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(__file__))

_spec = importlib.util.spec_from_file_location(
    "document_api",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
document_api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(document_api)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_event(
    method="PUT",
    path="/api/v1/documents",
    body=None,
    cookie="enceladus_id_token=valid-jwt",
    query_params=None,
):
    """Build a mock API Gateway v2 event (mirrors test_lambda_function.py)."""
    event = {
        "requestContext": {"http": {"method": method, "path": path}},
        "headers": {"cookie": cookie} if cookie else {"host": "example.com"},
        "rawPath": path,
        "queryStringParameters": query_params or {},
    }
    if body is not None:
        event["body"] = json.dumps(body) if isinstance(body, dict) else body
    return event


def _base_put_body(**overrides):
    """Minimal viable PUT body - callers override document_subtype / fields."""
    body = {
        "project_id": "devops",
        "title": "Test Document",
        "content": "# Hello\n\nSome content.",
        "document_subtype": "doc",
        "confirm_subtype": True,  # bypass the handoff-detection guard for 'doc'
    }
    body.update(overrides)
    return body


def _valid_agentskills_manifest(**overrides):
    manifest = {
        "name": "example-skill",
        "description": "An example skill for test purposes.",
        "version": "1.0.0",
    }
    manifest.update(overrides)
    return manifest


def _valid_skill_body(**overrides):
    """Minimal viable skill PUT body with all required fields populated."""
    body = {
        "project_id": "devops",
        "title": "Example Skill",
        "content": "# Example Skill\n\nSkill body stub.",
        "document_subtype": "skill",
        "full_description": "This is the full description of the skill.",
        "claude_description": "This is the Claude-spec SKILL.md description (<= 1024 chars).",
        "agentskills_manifest": _valid_agentskills_manifest(),
        "agentskills_spec_version": document_api.AGENTSKILLS_SPEC_VERSION_DEFAULT,
        "related_items": ["DOC-AAAAAAAAAAAA", "DOC-BBBBBBBBBBBB"],
    }
    body.update(overrides)
    return body


def _valid_context_node_body(**overrides):
    """Minimal viable context-node PUT body at exactly 5 edges, well under cap."""
    body = {
        "project_id": "devops",
        "title": "Example Context Node",
        "content": "# Example Context Node\n\nA compressed graph anchor.",
        "document_subtype": "context-node",
        "related_items": [
            "DOC-AAAAAAAAAAAA",
            "DOC-BBBBBBBBBBBB",
            "DOC-CCCCCCCCCCCC",
            "DOC-DDDDDDDDDDDD",
            "DOC-EEEEEEEEEEEE",
        ],
    }
    body.update(overrides)
    return body


def _configure_ddb_for_put(mock_ddb):
    """Wire a MagicMock DDB so a put_item call succeeds without raising."""
    fake_ddb = MagicMock()
    fake_ddb.put_item.return_value = {}
    mock_ddb.return_value = fake_ddb
    return fake_ddb


def _error_envelope(resp):
    """Pull the error_envelope dict out of a lambda response for assertions."""
    return json.loads(resp["body"]).get("error_envelope") or {}


def _resp_body(resp):
    return json.loads(resp["body"])


# ---------------------------------------------------------------------------
# (a) Happy-path PUT for each of doc, idea, context-node, skill, doc+subtypepattern
# ---------------------------------------------------------------------------


class HappyPathPutTests(unittest.TestCase):
    """AC #22 (a): Five happy-path PUT variants, one per allow-list subtype."""

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_validate_project_exists", return_value=None)
    @patch.object(document_api, "_upload_content",
                  return_value=("agent-documents/devops/DOC-X.md", "abc123", 50))
    @patch.object(document_api, "_get_ddb")
    def test_happy_path_put_doc(self, mock_ddb, *_):
        _configure_ddb_for_put(mock_ddb)
        event = _make_event(body=_base_put_body(
            title="Plain Doc Title",  # no colon prefix
            document_subtype="doc",
        ))
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 201, _resp_body(resp))
        self.assertTrue(_resp_body(resp)["success"])

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_validate_project_exists", return_value=None)
    @patch.object(document_api, "_upload_content",
                  return_value=("agent-documents/devops/DOC-X.md", "abc123", 50))
    @patch.object(document_api, "_get_ddb")
    def test_happy_path_put_idea(self, mock_ddb, *_):
        _configure_ddb_for_put(mock_ddb)
        event = _make_event(body=_base_put_body(
            title="Idea: Compression-as-Learning",
            document_subtype="idea",
        ))
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 201, _resp_body(resp))
        self.assertTrue(_resp_body(resp)["success"])

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_validate_project_exists", return_value=None)
    @patch.object(document_api, "_upload_content",
                  return_value=("agent-documents/devops/DOC-X.md", "abc123", 50))
    @patch.object(document_api, "_get_ddb")
    def test_happy_path_put_context_node(self, mock_ddb, *_):
        _configure_ddb_for_put(mock_ddb)
        event = _make_event(body=_valid_context_node_body())
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 201, _resp_body(resp))
        self.assertTrue(_resp_body(resp)["success"])

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_validate_project_exists", return_value=None)
    @patch.object(document_api, "_upload_content",
                  return_value=("agent-documents/devops/DOC-X.md", "abc123", 50))
    @patch.object(document_api, "_get_ddb")
    def test_happy_path_put_skill(self, mock_ddb, *_):
        _configure_ddb_for_put(mock_ddb)
        event = _make_event(body=_valid_skill_body())
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 201, _resp_body(resp))
        self.assertTrue(_resp_body(resp)["success"])

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_validate_project_exists", return_value=None)
    @patch.object(document_api, "_upload_content",
                  return_value=("agent-documents/devops/DOC-X.md", "abc123", 50))
    @patch.object(document_api, "_get_ddb")
    def test_happy_path_put_doc_with_subtypepattern(self, mock_ddb, *_):
        fake_ddb = _configure_ddb_for_put(mock_ddb)
        event = _make_event(body=_base_put_body(
            title="Enceladus v3 Migration Blueprint",  # no colon prefix
            document_subtype="doc",
            subtypepattern="blueprint",
        ))
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 201, _resp_body(resp))
        self.assertTrue(_resp_body(resp)["success"])
        # Assert subtypepattern was persisted on the DDB item.
        call_args = fake_ddb.put_item.call_args
        item = call_args[1]["Item"]
        self.assertIn("subtypepattern", item)
        self.assertEqual(item["subtypepattern"], {"S": "blueprint"})


# ---------------------------------------------------------------------------
# (b) Context-node cap rejection
# ---------------------------------------------------------------------------


class ContextNodeCapTests(unittest.TestCase):
    """AC #22 (b): body 2049 chars rejects with code context_node_cap_exceeded."""

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_validate_project_exists", return_value=None)
    @patch.object(document_api, "_get_ddb")
    def test_context_node_body_2049_rejects(self, mock_ddb, *_):
        # Body is pure text with no H1 or metadata lines -> readable_body_length == 2049
        big_body = "x" * (document_api.CAP_CONTEXT_NODE + 1)
        event = _make_event(body=_valid_context_node_body(content=big_body))
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 400)
        envelope = _error_envelope(resp)
        self.assertEqual(envelope["code"], "CONTEXT_NODE_CAP_EXCEEDED")
        self.assertEqual(envelope["details"]["measured"], 2049)
        self.assertEqual(envelope["details"]["cap"], document_api.CAP_CONTEXT_NODE)


# ---------------------------------------------------------------------------
# (c) Context-node edge-density rejection
# ---------------------------------------------------------------------------


class ContextNodeEdgeDensityTests(unittest.TestCase):
    """AC #22 (c): 4 related_items rejects with context_node_edge_density_insufficient."""

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_validate_project_exists", return_value=None)
    @patch.object(document_api, "_get_ddb")
    def test_context_node_four_edges_rejects(self, mock_ddb, *_):
        body = _valid_context_node_body(related_items=[
            "DOC-AAAAAAAAAAAA",
            "DOC-BBBBBBBBBBBB",
            "DOC-CCCCCCCCCCCC",
            "DOC-DDDDDDDDDDDD",
        ])
        event = _make_event(body=body)
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 400)
        envelope = _error_envelope(resp)
        self.assertEqual(envelope["code"], "CONTEXT_NODE_EDGE_DENSITY_INSUFFICIENT")
        self.assertEqual(envelope["details"]["measured"], 4)
        self.assertEqual(envelope["details"]["min"], document_api.N_MIN_CONTEXT_NODE)


# ---------------------------------------------------------------------------
# (d) Skill full_description cap rejection
# ---------------------------------------------------------------------------


class SkillFullDescriptionCapTests(unittest.TestCase):
    """AC #22 (d): 4097 chars rejects with code skill_full_description_invalid."""

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_validate_project_exists", return_value=None)
    @patch.object(document_api, "_get_ddb")
    def test_skill_full_description_4097_rejects(self, mock_ddb, *_):
        body = _valid_skill_body(
            full_description="x" * (document_api.CAP_SKILL_FULL_DESC + 1),
        )
        event = _make_event(body=body)
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 400)
        envelope = _error_envelope(resp)
        self.assertEqual(envelope["code"], "SKILL_FULL_DESCRIPTION_INVALID")
        self.assertEqual(envelope["details"]["measured"], 4097)
        self.assertEqual(envelope["details"]["cap"], document_api.CAP_SKILL_FULL_DESC)


# ---------------------------------------------------------------------------
# (e) Skill claude_description too-long rejection
# ---------------------------------------------------------------------------


class SkillClaudeDescriptionCapTests(unittest.TestCase):
    """AC #22 (e): 1025 chars rejects with code skill_claude_description_too_long."""

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_validate_project_exists", return_value=None)
    @patch.object(document_api, "_get_ddb")
    def test_skill_claude_description_1025_rejects(self, mock_ddb, *_):
        body = _valid_skill_body(
            claude_description="y" * (document_api.CAP_SKILL_CLAUDE_DESC + 1),
        )
        event = _make_event(body=body)
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 400)
        envelope = _error_envelope(resp)
        self.assertEqual(envelope["code"], "SKILL_CLAUDE_DESCRIPTION_TOO_LONG")
        self.assertEqual(envelope["details"]["measured"], 1025)
        self.assertEqual(envelope["details"]["cap"], document_api.CAP_SKILL_CLAUDE_DESC)


# ---------------------------------------------------------------------------
# (f) Skill missing-required-field rejection (x4)
# ---------------------------------------------------------------------------


class SkillMissingFieldTests(unittest.TestCase):
    """AC #22 (f): each of the four required skill fields, missing, gets its own code."""

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_validate_project_exists", return_value=None)
    @patch.object(document_api, "_get_ddb")
    def test_missing_full_description(self, mock_ddb, *_):
        body = _valid_skill_body()
        body.pop("full_description")
        resp = document_api.lambda_handler(_make_event(body=body), None)
        self.assertEqual(resp["statusCode"], 400)
        self.assertEqual(_error_envelope(resp)["code"], "SKILL_FULL_DESCRIPTION_MISSING")

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_validate_project_exists", return_value=None)
    @patch.object(document_api, "_get_ddb")
    def test_missing_claude_description(self, mock_ddb, *_):
        body = _valid_skill_body()
        body.pop("claude_description")
        resp = document_api.lambda_handler(_make_event(body=body), None)
        self.assertEqual(resp["statusCode"], 400)
        self.assertEqual(
            _error_envelope(resp)["code"], "SKILL_CLAUDE_DESCRIPTION_MISSING"
        )

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_validate_project_exists", return_value=None)
    @patch.object(document_api, "_get_ddb")
    def test_missing_agentskills_manifest(self, mock_ddb, *_):
        body = _valid_skill_body()
        body.pop("agentskills_manifest")
        resp = document_api.lambda_handler(_make_event(body=body), None)
        self.assertEqual(resp["statusCode"], 400)
        self.assertEqual(
            _error_envelope(resp)["code"], "SKILL_AGENTSKILLS_MANIFEST_MISSING"
        )

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_validate_project_exists", return_value=None)
    @patch.object(document_api, "_get_ddb")
    def test_missing_agentskills_spec_version(self, mock_ddb, *_):
        body = _valid_skill_body()
        body.pop("agentskills_spec_version")
        resp = document_api.lambda_handler(_make_event(body=body), None)
        self.assertEqual(resp["statusCode"], 400)
        self.assertEqual(
            _error_envelope(resp)["code"], "SKILL_AGENTSKILLS_SPEC_VERSION_MISSING"
        )


# ---------------------------------------------------------------------------
# (g) agentskills_manifest non-conformant payload (missing name)
# ---------------------------------------------------------------------------


class SkillManifestConformanceTests(unittest.TestCase):
    """AC #22 (g): non-conformant manifest (missing 'name' key) rejects."""

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_validate_project_exists", return_value=None)
    @patch.object(document_api, "_get_ddb")
    def test_manifest_missing_name_rejects(self, mock_ddb, *_):
        bad_manifest = {
            # name missing on purpose
            "description": "An example skill for test purposes.",
            "version": "1.0.0",
        }
        body = _valid_skill_body(agentskills_manifest=bad_manifest)
        resp = document_api.lambda_handler(_make_event(body=body), None)
        self.assertEqual(resp["statusCode"], 400)
        envelope = _error_envelope(resp)
        self.assertEqual(envelope["code"], "SKILL_AGENTSKILLS_MANIFEST_INVALID")
        self.assertIn("name", envelope["details"]["validator_output"]["missing_keys"])

    def test_validate_agentskills_manifest_unit_missing_name(self):
        """Direct unit test against the helper for name-missing branch.

        The helper returns the raw lowercase sentinel code; _error() uppercases
        when routed through the HTTP surface. Tests that invoke the helper
        directly therefore compare against the lowercase form.
        """
        err = document_api._validate_agentskills_manifest(
            {"description": "desc", "version": "1.0.0"},
            document_api.AGENTSKILLS_SPEC_VERSION_DEFAULT,
        )
        self.assertIsNotNone(err)
        self.assertEqual(err["code"], "skill_agentskills_manifest_invalid")
        self.assertIn("name", err["details"]["missing_keys"])

    def test_validate_agentskills_manifest_unit_non_dict(self):
        """Direct unit test: non-dict manifest rejects."""
        err = document_api._validate_agentskills_manifest(
            "not a dict",
            document_api.AGENTSKILLS_SPEC_VERSION_DEFAULT,
        )
        self.assertIsNotNone(err)
        self.assertEqual(err["code"], "skill_agentskills_manifest_invalid")

    def test_validate_agentskills_manifest_unit_wrong_version(self):
        """Direct unit test: unsupported spec version rejects."""
        err = document_api._validate_agentskills_manifest(
            _valid_agentskills_manifest(),
            "9.9.9",
        )
        self.assertIsNotNone(err)
        self.assertEqual(err["code"], "skill_agentskills_manifest_invalid")

    def test_validate_agentskills_manifest_unit_happy(self):
        """Direct unit test: valid manifest returns None."""
        err = document_api._validate_agentskills_manifest(
            _valid_agentskills_manifest(),
            document_api.AGENTSKILLS_SPEC_VERSION_DEFAULT,
        )
        self.assertIsNone(err)


# ---------------------------------------------------------------------------
# (h) runtime_variants with unknown keys accepted
# ---------------------------------------------------------------------------


class SkillRuntimeVariantsTests(unittest.TestCase):
    """AC #22 (h): runtime_variants accepts unknown keys for forward-compat."""

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_validate_project_exists", return_value=None)
    @patch.object(document_api, "_upload_content",
                  return_value=("agent-documents/devops/DOC-X.md", "abc123", 50))
    @patch.object(document_api, "_get_ddb")
    def test_runtime_variants_unknown_keys_accepted(self, mock_ddb, *_):
        fake_ddb = _configure_ddb_for_put(mock_ddb)
        body = _valid_skill_body(runtime_variants={
            "openai-gpts": {"instructions": "x"},
            "experimental-runtime-foo": {"some_key": [1, 2, 3]},
            "future-unknown": True,
        })
        resp = document_api.lambda_handler(_make_event(body=body), None)
        self.assertEqual(resp["statusCode"], 201, _resp_body(resp))
        # Verify the stored runtime_variants JSON contains the unknown keys verbatim.
        item = fake_ddb.put_item.call_args[1]["Item"]
        stored = json.loads(item["runtime_variants"]["S"])
        self.assertIn("openai-gpts", stored)
        self.assertIn("experimental-runtime-foo", stored)
        self.assertIn("future-unknown", stored)

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_validate_project_exists", return_value=None)
    @patch.object(document_api, "_upload_content",
                  return_value=("agent-documents/devops/DOC-X.md", "abc123", 50))
    @patch.object(document_api, "_get_ddb")
    def test_runtime_variants_empty_object_accepted(self, mock_ddb, *_):
        _configure_ddb_for_put(mock_ddb)
        body = _valid_skill_body(runtime_variants={})
        resp = document_api.lambda_handler(_make_event(body=body), None)
        self.assertEqual(resp["statusCode"], 201, _resp_body(resp))

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_validate_project_exists", return_value=None)
    @patch.object(document_api, "_get_ddb")
    def test_runtime_variants_non_dict_rejected(self, mock_ddb, *_):
        body = _valid_skill_body(runtime_variants=["should", "not", "be", "a", "list"])
        resp = document_api.lambda_handler(_make_event(body=body), None)
        self.assertEqual(resp["statusCode"], 400)
        self.assertEqual(
            _error_envelope(resp)["code"], "SKILL_RUNTIME_VARIANTS_INVALID"
        )


# ---------------------------------------------------------------------------
# (i) Title colon-prefix rejection (3 variants)
# ---------------------------------------------------------------------------


class DocTitleColonPrefixTests(unittest.TestCase):
    """AC #22 (i): 'Blueprint: X', 'Post-Mortem: X', 'runbook: X' all rejected."""

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_validate_project_exists", return_value=None)
    @patch.object(document_api, "_get_ddb")
    def _assert_rejected(self, title, mock_ddb, *_):
        body = _base_put_body(title=title, document_subtype="doc")
        resp = document_api.lambda_handler(_make_event(body=body), None)
        self.assertEqual(resp["statusCode"], 400, f"title={title!r} body={_resp_body(resp)}")
        envelope = _error_envelope(resp)
        self.assertEqual(envelope["code"], "DOC_TITLE_COLON_PREFIX_DISALLOWED",
                         f"title={title!r}")

    def test_blueprint_colon_prefix_rejected(self):
        self._assert_rejected("Blueprint: Enceladus Migration")

    def test_post_mortem_colon_prefix_rejected(self):
        self._assert_rejected("Post-Mortem: Incident 1234")

    def test_runbook_lowercase_colon_prefix_rejected(self):
        self._assert_rejected("runbook: deploy checkout")


# ---------------------------------------------------------------------------
# (j) Subtypepattern canonicalization
# ---------------------------------------------------------------------------


class SubtypepatternCanonicalizationTests(unittest.TestCase):
    """AC #22 (j): input 'Blueprint' stores as 'blueprint'."""

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_validate_project_exists", return_value=None)
    @patch.object(document_api, "_upload_content",
                  return_value=("agent-documents/devops/DOC-X.md", "abc123", 50))
    @patch.object(document_api, "_get_ddb")
    def test_uppercase_blueprint_canonicalizes_to_lowercase(self, mock_ddb, *_):
        fake_ddb = _configure_ddb_for_put(mock_ddb)
        body = _base_put_body(
            title="Enceladus v3 Migration Plan",
            document_subtype="doc",
            subtypepattern="Blueprint",  # mixed-case input
        )
        resp = document_api.lambda_handler(_make_event(body=body), None)
        self.assertEqual(resp["statusCode"], 201, _resp_body(resp))
        item = fake_ddb.put_item.call_args[1]["Item"]
        self.assertEqual(item["subtypepattern"], {"S": "blueprint"})

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_validate_project_exists", return_value=None)
    @patch.object(document_api, "_upload_content",
                  return_value=("agent-documents/devops/DOC-X.md", "abc123", 50))
    @patch.object(document_api, "_get_ddb")
    def test_whitespace_is_trimmed(self, mock_ddb, *_):
        fake_ddb = _configure_ddb_for_put(mock_ddb)
        body = _base_put_body(
            title="Plan doc",
            document_subtype="doc",
            subtypepattern="  Post-Mortem  ",
        )
        resp = document_api.lambda_handler(_make_event(body=body), None)
        self.assertEqual(resp["statusCode"], 201, _resp_body(resp))
        item = fake_ddb.put_item.call_args[1]["Item"]
        self.assertEqual(item["subtypepattern"], {"S": "post-mortem"})

    def test_canonicalize_helper_non_string_returns_none(self):
        """_canonicalize_subtypepattern returns None on non-string input."""
        self.assertIsNone(document_api._canonicalize_subtypepattern(42))
        self.assertIsNone(document_api._canonicalize_subtypepattern(None))
        self.assertIsNone(document_api._canonicalize_subtypepattern(["blueprint"]))

    def test_canonicalize_helper_trim_and_lowercase(self):
        self.assertEqual(document_api._canonicalize_subtypepattern("  Blueprint  "),
                         "blueprint")
        self.assertEqual(document_api._canonicalize_subtypepattern("POST-MORTEM"),
                         "post-mortem")


# ---------------------------------------------------------------------------
# (k) Subtypepattern invalid formats (4 variants)
# ---------------------------------------------------------------------------


class SubtypepatternInvalidFormatTests(unittest.TestCase):
    """AC #22 (k): four invalid-format variants each reject with subtypepattern_invalid_format."""

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_validate_project_exists", return_value=None)
    @patch.object(document_api, "_get_ddb")
    def _assert_invalid_format(self, pattern, mock_ddb, *_):
        body = _base_put_body(
            title="Some Doc",
            document_subtype="doc",
            subtypepattern=pattern,
        )
        resp = document_api.lambda_handler(_make_event(body=body), None)
        self.assertEqual(resp["statusCode"], 400, f"pattern={pattern!r}")
        self.assertEqual(_error_envelope(resp)["code"],
                         "SUBTYPEPATTERN_INVALID_FORMAT",
                         f"pattern={pattern!r}")

    def test_underscore_and_digit_rejected(self):
        self._assert_invalid_format("blueprint_2")

    def test_space_between_words_rejected(self):
        # After canonicalization ('blue print'), regex ^[a-z-]+$ must fail.
        self._assert_invalid_format("BLUE PRINT")

    def test_trailing_punctuation_rejected(self):
        self._assert_invalid_format("blueprint?")

    def test_leading_digit_rejected(self):
        self._assert_invalid_format("2024-blueprint")


# ---------------------------------------------------------------------------
# (l) Subtypepattern on non-doc subtype rejected
# ---------------------------------------------------------------------------


class SubtypepatternWrongSubtypeTests(unittest.TestCase):
    """AC #22 (l): subtypepattern on a non-doc subtype (skill) rejects."""

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_validate_project_exists", return_value=None)
    @patch.object(document_api, "_get_ddb")
    def test_subtypepattern_on_skill_rejects(self, mock_ddb, *_):
        body = _valid_skill_body(subtypepattern="portable")
        resp = document_api.lambda_handler(_make_event(body=body), None)
        self.assertEqual(resp["statusCode"], 400)
        envelope = _error_envelope(resp)
        self.assertEqual(envelope["code"], "SUBTYPEPATTERN_WRONG_SUBTYPE")
        self.assertEqual(envelope["details"]["document_subtype"], "skill")

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_validate_project_exists", return_value=None)
    @patch.object(document_api, "_get_ddb")
    def test_subtypepattern_on_idea_rejects(self, mock_ddb, *_):
        body = _base_put_body(
            title="Idea sketch",
            document_subtype="idea",
            subtypepattern="prototype",
        )
        # idea doesn't need confirm_subtype, but _base_put_body supplies it harmlessly.
        resp = document_api.lambda_handler(_make_event(body=body), None)
        self.assertEqual(resp["statusCode"], 400)
        self.assertEqual(_error_envelope(resp)["code"], "SUBTYPEPATTERN_WRONG_SUBTYPE")


# ---------------------------------------------------------------------------
# (m) Search subtypepattern filter
# ---------------------------------------------------------------------------


class SearchSubtypepatternFilterTests(unittest.TestCase):
    """AC #22 (m): search with subtypepattern filter returns only matching records."""

    def _scan_seed(self):
        """Three seed records with varying (document_subtype, subtypepattern)."""
        return [
            {
                "document_id": {"S": "DOC-PLAN-BLUE1"},
                "project_id": {"S": "devops"},
                "title": {"S": "Blueprint one"},
                "status": {"S": "active"},
                "document_subtype": {"S": "doc"},
                "subtypepattern": {"S": "blueprint"},
                "created_at": {"S": "2026-01-01T00:00:00Z"},
                "updated_at": {"S": "2026-01-01T00:00:00Z"},
                "keywords": {"L": []},
                "related_items": {"L": []},
            },
            {
                "document_id": {"S": "DOC-PLAN-BLUE2"},
                "project_id": {"S": "devops"},
                "title": {"S": "Another blueprint"},
                "status": {"S": "active"},
                "document_subtype": {"S": "doc"},
                "subtypepattern": {"S": "blueprint"},
                "created_at": {"S": "2026-02-01T00:00:00Z"},
                "updated_at": {"S": "2026-02-01T00:00:00Z"},
                "keywords": {"L": []},
                "related_items": {"L": []},
            },
            {
                "document_id": {"S": "DOC-PLAN-RUNBOOK"},
                "project_id": {"S": "devops"},
                "title": {"S": "Deploy runbook"},
                "status": {"S": "active"},
                "document_subtype": {"S": "doc"},
                "subtypepattern": {"S": "runbook"},
                "created_at": {"S": "2026-03-01T00:00:00Z"},
                "updated_at": {"S": "2026-03-01T00:00:00Z"},
                "keywords": {"L": []},
                "related_items": {"L": []},
            },
            {
                "document_id": {"S": "DOC-IDEA-BLUE"},
                "project_id": {"S": "devops"},
                "title": {"S": "Blueprint-adjacent idea"},
                "status": {"S": "active"},
                # Idea subtype even though the stale field shape includes
                # a subtypepattern (should NEVER happen in new writes, but we
                # defensively assert the search filter scopes to doc-only).
                "document_subtype": {"S": "idea"},
                "subtypepattern": {"S": "blueprint"},
                "created_at": {"S": "2026-04-01T00:00:00Z"},
                "updated_at": {"S": "2026-04-01T00:00:00Z"},
                "keywords": {"L": []},
                "related_items": {"L": []},
            },
        ]

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_get_ddb")
    def test_subtypepattern_filter_returns_only_matching_doc_records(
        self, mock_ddb, *_
    ):
        fake_ddb = MagicMock()
        fake_ddb.scan.return_value = {"Items": self._scan_seed()}
        mock_ddb.return_value = fake_ddb

        event = _make_event(
            method="GET",
            path="/api/v1/documents/search",
            query_params={"project": "devops", "subtypepattern": "blueprint"},
        )
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 200, _resp_body(resp))
        body = _resp_body(resp)
        ids = {d["document_id"] for d in body["documents"]}
        # Only the two doc+blueprint records match.
        self.assertEqual(ids, {"DOC-PLAN-BLUE1", "DOC-PLAN-BLUE2"})

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_get_ddb")
    def test_subtypepattern_filter_canonicalizes_input(self, mock_ddb, *_):
        """Filter input is trimmed + lowercased before comparison."""
        fake_ddb = MagicMock()
        fake_ddb.scan.return_value = {"Items": self._scan_seed()}
        mock_ddb.return_value = fake_ddb

        event = _make_event(
            method="GET",
            path="/api/v1/documents/search",
            query_params={"project": "devops", "subtypepattern": "  BLUEPRINT  "},
        )
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 200)
        ids = {d["document_id"] for d in _resp_body(resp)["documents"]}
        self.assertEqual(ids, {"DOC-PLAN-BLUE1", "DOC-PLAN-BLUE2"})

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_get_ddb")
    def test_subtypepattern_filter_empty_value_is_noop(self, mock_ddb, *_):
        """Empty/absent subtypepattern filter returns all docs (no filter applied)."""
        fake_ddb = MagicMock()
        fake_ddb.scan.return_value = {"Items": self._scan_seed()}
        mock_ddb.return_value = fake_ddb

        event = _make_event(
            method="GET",
            path="/api/v1/documents/search",
            query_params={"project": "devops"},
        )
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 200)
        body = _resp_body(resp)
        # All four seed records returned (no subtypepattern filter).
        self.assertEqual(len(body["documents"]), 4)


# ---------------------------------------------------------------------------
# (n) Non-enum document_subtype rejection with redirect text
# ---------------------------------------------------------------------------


class NonEnumSubtypeRedirectTests(unittest.TestCase):
    """AC #22 (n): 'foobar' subtype rejects with code document_subtype_not_in_enum
    and the error message / envelope mentions subtypepattern redirect."""

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_validate_project_exists", return_value=None)
    @patch.object(document_api, "_get_ddb")
    def test_foobar_subtype_rejects_with_redirect(self, mock_ddb, *_):
        body = _base_put_body(document_subtype="foobar")
        resp = document_api.lambda_handler(_make_event(body=body), None)
        self.assertEqual(resp["statusCode"], 400)
        envelope = _error_envelope(resp)
        self.assertEqual(envelope["code"], "DOCUMENT_SUBTYPE_NOT_IN_ENUM")
        # Redirect text must mention subtypepattern.
        combined_text = (
            envelope["message"]
            + " "
            + json.dumps(envelope["details"])
        )
        self.assertIn("subtypepattern", combined_text)

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_validate_project_exists", return_value=None)
    @patch.object(document_api, "_get_ddb")
    def test_legacy_value_rejects_with_redirect(self, mock_ddb, *_):
        """Legacy 'blueprint' (in legacy_readable_only set) rejects on writes."""
        body = _base_put_body(document_subtype="blueprint")
        resp = document_api.lambda_handler(_make_event(body=body), None)
        self.assertEqual(resp["statusCode"], 400)
        envelope = _error_envelope(resp)
        self.assertEqual(envelope["code"], "DOCUMENT_SUBTYPE_NOT_IN_ENUM")
        self.assertIn("subtypepattern", json.dumps(envelope["details"]))


# ---------------------------------------------------------------------------
# (o) Legacy-shape record readable via GET
# ---------------------------------------------------------------------------


class LegacyRecordReadTests(unittest.TestCase):
    """AC #22 (o) + AC-19: legacy 'general' / 'blueprint' records remain readable."""

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_get_ddb")
    @patch.object(document_api, "_get_content", return_value="# Legacy\n\nbody")
    def test_legacy_general_subtype_readable(self, _mock_content, mock_ddb, *_):
        fake_ddb = MagicMock()
        fake_ddb.get_item.return_value = {
            "Item": {
                "document_id": {"S": "DOC-LEGACYGEN001"},
                "project_id": {"S": "devops"},
                "title": {"S": "A general doc from 2025"},
                "status": {"S": "active"},
                "document_subtype": {"S": "general"},  # legacy
                "created_at": {"S": "2025-10-01T00:00:00Z"},
                "updated_at": {"S": "2025-10-01T00:00:00Z"},
            }
        }
        mock_ddb.return_value = fake_ddb

        event = _make_event(method="GET", path="/api/v1/documents/DOC-LEGACYGEN001")
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 200)
        body = _resp_body(resp)
        self.assertEqual(body["document_id"], "DOC-LEGACYGEN001")
        self.assertEqual(body["document_subtype"], "general")

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_get_ddb")
    @patch.object(document_api, "_get_content", return_value="# Old Blueprint\n\nbody")
    def test_legacy_blueprint_shape_record_readable(
        self, _mock_content, mock_ddb, *_
    ):
        """DOC-14DAB0B7059C-shape: emergent subtype='blueprint' must still read."""
        fake_ddb = MagicMock()
        fake_ddb.get_item.return_value = {
            "Item": {
                "document_id": {"S": "DOC-14DAB0B7059C"},
                "project_id": {"S": "enceladus"},
                "title": {"S": "Blueprint: some old pre-patch doc"},
                "status": {"S": "active"},
                # Emergent subtype string (NOT in the allow-list, NOT in legacy
                # set either, but pre-patch these were silently accepted).
                "document_subtype": {"S": "blueprint"},
                "created_at": {"S": "2025-11-01T00:00:00Z"},
                "updated_at": {"S": "2025-11-01T00:00:00Z"},
            }
        }
        mock_ddb.return_value = fake_ddb

        event = _make_event(method="GET", path="/api/v1/documents/DOC-14DAB0B7059C")
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 200)
        body = _resp_body(resp)
        self.assertEqual(body["document_subtype"], "blueprint")


# ---------------------------------------------------------------------------
# (p) Patch to legacy record not touching title/subtype/subtypepattern
# ---------------------------------------------------------------------------


class LegacyRecordPatchTests(unittest.TestCase):
    """AC #22 (p) + AC-19: patches that don't touch validated fields pass through."""

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_upload_content",
                  return_value=("agent-documents/devops/DOC-LEG.md", "h", 20))
    @patch.object(document_api, "_get_ddb")
    def test_content_only_patch_on_general_subtype_passes(
        self, mock_ddb, *_
    ):
        """Patching content on a legacy 'general' doc should not trigger
        title-hygiene or enum validation."""
        fake_ddb = MagicMock()
        fake_ddb.get_item.return_value = {
            "Item": {
                "document_id": {"S": "DOC-LEGACYGEN001"},
                "project_id": {"S": "devops"},
                "title": {"S": "Blueprint: legacy title"},  # has colon prefix
                "status": {"S": "active"},
                "document_subtype": {"S": "general"},  # legacy
                "created_at": {"S": "2025-10-01T00:00:00Z"},
                "updated_at": {"S": "2025-10-01T00:00:00Z"},
                "version": {"N": "3"},
            }
        }
        fake_ddb.update_item.return_value = {}
        mock_ddb.return_value = fake_ddb

        event = _make_event(
            method="PATCH",
            path="/api/v1/documents/DOC-LEGACYGEN001",
            body={"content": "# Updated\n\nfresh body"},
        )
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 200, _resp_body(resp))
        self.assertTrue(_resp_body(resp)["success"])

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_get_ddb")
    def test_keywords_only_patch_on_blueprint_legacy_passes(self, mock_ddb, *_):
        """Patching keywords on a legacy 'blueprint' emergent-subtype doc passes."""
        fake_ddb = MagicMock()
        fake_ddb.get_item.return_value = {
            "Item": {
                "document_id": {"S": "DOC-14DAB0B7059C"},
                "project_id": {"S": "enceladus"},
                "title": {"S": "Blueprint: old migration plan"},
                "status": {"S": "active"},
                "document_subtype": {"S": "blueprint"},  # legacy emergent string
                "created_at": {"S": "2025-11-01T00:00:00Z"},
                "updated_at": {"S": "2025-11-01T00:00:00Z"},
                "version": {"N": "1"},
            }
        }
        fake_ddb.update_item.return_value = {}
        mock_ddb.return_value = fake_ddb

        event = _make_event(
            method="PATCH",
            path="/api/v1/documents/DOC-14DAB0B7059C",
            body={"keywords": ["migration", "legacy"]},
        )
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 200, _resp_body(resp))


# ---------------------------------------------------------------------------
# (q) Invalid subtype regression (general protection for AC-2 / AC-3)
# ---------------------------------------------------------------------------


class InvalidSubtypeRegressionTests(unittest.TestCase):
    """AC #22 (q): broad regression that any unknown subtype is rejected
    through both PUT and PATCH surfaces."""

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_validate_project_exists", return_value=None)
    @patch.object(document_api, "_get_ddb")
    def test_arbitrary_unknown_subtype_rejects_on_put(self, mock_ddb, *_):
        for bogus in ("proposal", "memo", "diagram", "zz-anything"):
            body = _base_put_body(document_subtype=bogus)
            resp = document_api.lambda_handler(_make_event(body=body), None)
            self.assertEqual(resp["statusCode"], 400, f"bogus={bogus}")
            self.assertEqual(
                _error_envelope(resp)["code"],
                "DOCUMENT_SUBTYPE_NOT_IN_ENUM",
                f"bogus={bogus}",
            )

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_get_ddb")
    def test_arbitrary_unknown_subtype_rejects_on_patch(self, mock_ddb, *_):
        fake_ddb = MagicMock()
        fake_ddb.get_item.return_value = {
            "Item": {
                "document_id": {"S": "DOC-ABCDEFGHIJKL"},
                "project_id": {"S": "devops"},
                "title": {"S": "Plain doc"},
                "status": {"S": "active"},
                "document_subtype": {"S": "doc"},
                "created_at": {"S": "2026-01-01T00:00:00Z"},
                "updated_at": {"S": "2026-01-01T00:00:00Z"},
                "version": {"N": "1"},
            }
        }
        mock_ddb.return_value = fake_ddb

        event = _make_event(
            method="PATCH",
            path="/api/v1/documents/DOC-ABCDEFGHIJKL",
            body={"document_subtype": "proposal"},
        )
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 400)
        self.assertEqual(
            _error_envelope(resp)["code"], "DOCUMENT_SUBTYPE_NOT_IN_ENUM"
        )


# ---------------------------------------------------------------------------
# Helper-level tests: _measure_context_node_readable_body
# ---------------------------------------------------------------------------


class MeasureContextNodeReadableBodyTests(unittest.TestCase):
    """Direct tests for the readable-body measurement helper."""

    def test_strips_h1_line(self):
        # splitlines() -> ["# DOC-EXAMPLE Header", "", "hello world"]
        # H1 skipped, blank + body appended -> "\nhello world" (12 chars).
        content = "# DOC-EXAMPLE Header\n\nhello world"
        measured = document_api._measure_context_node_readable_body(content)
        self.assertEqual(measured, len("\nhello world"))

    def test_strips_metadata_keys(self):
        content = (
            "# DOC-EXAMPLE Title\n"
            "**Project**: enceladus\n"
            "**Related**: DOC-AAA\n"
            "**Created**: 2026-04-18\n"
            "**Author**: someone\n"
            "\n"
            "readable body"
        )
        # H1 + 4 metadata lines skipped; surviving lines are [""] and
        # ["readable body"], joined by "\n" -> "\nreadable body" (14 chars).
        measured = document_api._measure_context_node_readable_body(content)
        self.assertEqual(measured, len("\nreadable body"))

    def test_non_string_returns_zero(self):
        self.assertEqual(document_api._measure_context_node_readable_body(None), 0)
        self.assertEqual(document_api._measure_context_node_readable_body(12345), 0)

    def test_exact_cap_body_measures_cap(self):
        """A raw body of exactly CAP chars (no H1, no metadata) measures CAP."""
        body = "x" * document_api.CAP_CONTEXT_NODE
        self.assertEqual(
            document_api._measure_context_node_readable_body(body),
            document_api.CAP_CONTEXT_NODE,
        )


# ---------------------------------------------------------------------------
# Integration tests: end-to-end round-trips
# ---------------------------------------------------------------------------


class IntegrationSkillRoundTripTests(unittest.TestCase):
    """Integration: write a skill via _handle_put, verify what lands in DDB /
    S3 reflects the payload and the spec 0.1.0 validator passed."""

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1", "email": "dev@example.com"}, None))
    @patch.object(document_api, "_validate_project_exists", return_value=None)
    @patch.object(document_api, "_upload_content",
                  return_value=("agent-documents/devops/DOC-SKILL.md", "hash-abc", 120))
    @patch.object(document_api, "_get_ddb")
    def test_skill_end_to_end_put(self, mock_ddb, mock_upload, *_):
        fake_ddb = _configure_ddb_for_put(mock_ddb)

        manifest = _valid_agentskills_manifest(
            name="enc-skill-one",
            description="Enceladus-native portable skill.",
            version="1.2.3",
        )
        body = _valid_skill_body(
            title="Portable Skill Sample",
            content="# Portable Skill Sample\n\nStub body — canonical spec is full_description.",
            full_description="Full description paragraph with phronesis.",
            claude_description="Short Claude SKILL.md description.",
            agentskills_manifest=manifest,
            agentskills_spec_version=document_api.AGENTSKILLS_SPEC_VERSION_DEFAULT,
            runtime_variants={"claude-code": {}, "openai-gpts": {}},
            related_items=["DOC-AAAAAAAAAAAA", "DOC-BBBBBBBBBBBB"],
        )
        resp = document_api.lambda_handler(_make_event(body=body), None)

        # HTTP 201 + success envelope
        self.assertEqual(resp["statusCode"], 201, _resp_body(resp))
        resp_body = _resp_body(resp)
        self.assertTrue(resp_body["success"])
        self.assertTrue(resp_body["document_id"].startswith("DOC-"))

        # S3 was called once
        mock_upload.assert_called_once()

        # DDB item carries every skill field verbatim
        item = fake_ddb.put_item.call_args[1]["Item"]
        self.assertEqual(item["document_subtype"], {"S": "skill"})
        self.assertEqual(item["full_description"],
                         {"S": "Full description paragraph with phronesis."})
        self.assertEqual(item["claude_description"],
                         {"S": "Short Claude SKILL.md description."})
        self.assertEqual(item["agentskills_spec_version"],
                         {"S": document_api.AGENTSKILLS_SPEC_VERSION_DEFAULT})
        stored_manifest = json.loads(item["agentskills_manifest"]["S"])
        self.assertEqual(stored_manifest["name"], "enc-skill-one")
        self.assertEqual(stored_manifest["version"], "1.2.3")
        stored_variants = json.loads(item["runtime_variants"]["S"])
        self.assertIn("claude-code", stored_variants)
        self.assertIn("openai-gpts", stored_variants)


class IntegrationContextNodeBoundaryTests(unittest.TestCase):
    """Integration: exactly 5 related_items and body at exactly 2048 readable chars."""

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_validate_project_exists", return_value=None)
    @patch.object(document_api, "_upload_content",
                  return_value=("agent-documents/devops/DOC-CN.md", "hash-cn", 2048))
    @patch.object(document_api, "_get_ddb")
    def test_context_node_at_boundary_accepted(self, mock_ddb, *_):
        fake_ddb = _configure_ddb_for_put(mock_ddb)
        # Pure body: no H1, no metadata lines -> readable_body == len(content).
        body_text = "x" * document_api.CAP_CONTEXT_NODE
        body = _valid_context_node_body(content=body_text)
        # Sanity: we're at exactly 5 edges (the default in the helper) and 2048 chars.
        self.assertEqual(len(body["related_items"]), document_api.N_MIN_CONTEXT_NODE)
        self.assertEqual(
            document_api._measure_context_node_readable_body(body_text),
            document_api.CAP_CONTEXT_NODE,
        )

        resp = document_api.lambda_handler(_make_event(body=body), None)
        self.assertEqual(resp["statusCode"], 201, _resp_body(resp))
        item = fake_ddb.put_item.call_args[1]["Item"]
        self.assertEqual(item["document_subtype"], {"S": "context-node"})
        self.assertEqual(item["readable_body_length"],
                         {"N": str(document_api.CAP_CONTEXT_NODE)})


class IntegrationLegacyToIdeaPatchTests(unittest.TestCase):
    """Integration: PATCH a legacy 'general' record to 'idea' in one step."""

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_get_ddb")
    def test_patch_general_to_idea_succeeds(self, mock_ddb, *_):
        fake_ddb = MagicMock()
        fake_ddb.get_item.return_value = {
            "Item": {
                "document_id": {"S": "DOC-GENIDEAMIG1"},
                "project_id": {"S": "enceladus"},
                "title": {"S": "Idea: Emergent concept sketch"},
                "status": {"S": "active"},
                "document_subtype": {"S": "general"},  # legacy, readable
                "created_at": {"S": "2025-12-01T00:00:00Z"},
                "updated_at": {"S": "2025-12-01T00:00:00Z"},
                "version": {"N": "1"},
            }
        }
        fake_ddb.update_item.return_value = {}
        mock_ddb.return_value = fake_ddb

        # Only change the subtype — do NOT touch title / content / subtypepattern.
        event = _make_event(
            method="PATCH",
            path="/api/v1/documents/DOC-GENIDEAMIG1",
            body={"document_subtype": "idea"},
        )
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 200, _resp_body(resp))
        self.assertTrue(_resp_body(resp)["success"])

        # Assert update_item captured the subtype transition.
        update_call = fake_ddb.update_item.call_args
        attr_values = update_call[1]["ExpressionAttributeValues"]
        self.assertEqual(attr_values[":ds_new"], {"S": "idea"})


if __name__ == "__main__":
    unittest.main()
