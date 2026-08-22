"""Offline tests for elr_validate -- the three-layer pre-flight gate
(DOC-F2CF625B7556 section 4a). No network access: the dictionary pull is
either mocked at the urlopen layer (for fetch_dictionary/auth-path tests)
or bypassed entirely by calling validate_entity_payload() directly with
an in-memory fixture dictionary slice (tests/fixtures/dictionary_slice.json).
"""

import json
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

import elr_validate as ev
from elr_lib import config as elr_config

_FIXTURES = Path(__file__).resolve().parent / "fixtures"
_DICTIONARY = json.loads((_FIXTURES / "dictionary_slice.json").read_text(encoding="utf-8"))


def _overlay():
    return ev.load_overlay()


class _FakeHttpResponse:
    def __init__(self, status, body):
        self._status = status
        self._body = body

    def getcode(self):
        return self._status

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


def _governance_dictionary_response(dictionary):
    envelope = {
        "success": True,
        "uri": "governance://governance_data_dictionary.json",
        "file_name": "governance_data_dictionary.json",
        "content": json.dumps(dictionary),
    }
    return _FakeHttpResponse(200, json.dumps(envelope).encode("utf-8"))


# ---------------------------------------------------------------------------
# Layer 1 + Layer 2 payload validation (pure functions, fully offline)
# ---------------------------------------------------------------------------


class MissingRequiredFieldTests(unittest.TestCase):
    """Overlay entry 10: tracker.create feature without user_story --
    Layer 1 has no required-ness signal for user_story (only min_length,
    per the real Appendix B finding), so Layer 2 must be the one that
    refuses, and it must name the exact field.
    """

    def test_missing_user_story_refused_by_layer2(self):
        entries, anomaly = _overlay()
        payload = {"category": "capability", "priority": "P1"}
        digest = ev.validate_entity_payload("tracker.feature", payload, "tracker.create", _DICTIONARY, entries, anomaly)

        self.assertFalse(digest["ok"])
        self.assertEqual(digest["refusal"]["reason"], "validation_failed")
        self.assertEqual(digest["refusal"]["missing_fields"], ["user_story"])
        violation = digest["refusal"]["violations"][0]
        self.assertEqual(violation["source"], "layer2")
        self.assertEqual(violation["entry_id"], 10)
        self.assertIn("user_story", violation["reason"])

    def test_present_user_story_is_not_flagged(self):
        entries, anomaly = _overlay()
        payload = {"category": "capability", "priority": "P1", "user_story": "As a user I need X so that Y happens"}
        digest = ev.validate_entity_payload("tracker.feature", payload, "tracker.create", _DICTIONARY, entries, anomaly)
        self.assertTrue(digest["ok"])

    def test_entry_10_is_not_logged_redundant_it_still_does_real_work(self):
        """dictionary_derivable for entry 10 is 'partial' (enums yes,
        required-ness no) -- it must never be folded into the redundant
        list, which is reserved for entries dictionary_derivable=='true'.
        """
        entries, anomaly = _overlay()
        payload = {"category": "capability", "priority": "P1"}
        digest = ev.validate_entity_payload("tracker.feature", payload, "tracker.create", _DICTIONARY, entries, anomaly)
        redundant_anomalies = [a for a in digest["anomalies"] if a.startswith("redundant_overlay_entries")]
        self.assertEqual(redundant_anomalies, [])


class EnumViolationTests(unittest.TestCase):
    def test_bad_category_enum_refused_with_allowed_values(self):
        entries, anomaly = _overlay()
        payload = {"category": "not-a-real-category", "priority": "P1", "user_story": "As a user I need X so that Y"}
        digest = ev.validate_entity_payload("tracker.feature", payload, "tracker.create", _DICTIONARY, entries, anomaly)

        self.assertFalse(digest["ok"])
        violations = digest["refusal"]["violations"]
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0]["path"], "category")
        self.assertEqual(violations[0]["kind"], "enum_violation")
        self.assertIn("infrastructure", violations[0]["allowed_values"])

    def test_valid_enum_passes(self):
        entries, anomaly = _overlay()
        payload = {"category": "epic", "priority": "P0", "user_story": "As a user I need X so that Y happens"}
        digest = ev.validate_entity_payload("tracker.feature", payload, "tracker.create", _DICTIONARY, entries, anomaly)
        self.assertTrue(digest["ok"])


class NestedTransitionEvidenceTests(unittest.TestCase):
    """tracker.task.transition_evidence.properties.deploy_evidence
    .required_fields IS dictionary-encoded (confirms A.3 entry four /
    overlay entry 4 from the Layer 1 side).
    """

    def test_missing_nested_required_field_refused(self):
        entries, anomaly = _overlay()
        payload = {
            "transition_evidence": {
                "deploy_evidence": {"id": 1, "name": "job", "head_sha": "a" * 40}
                # "status" omitted -- required_fields entry, must be caught
            }
        }
        digest = ev.validate_entity_payload("tracker.task", payload, "checkout.advance", _DICTIONARY, entries, anomaly)
        self.assertFalse(digest["ok"])
        self.assertIn("transition_evidence.deploy_evidence.status", digest["refusal"]["missing_fields"])

    def test_server_stamped_nested_field_never_flagged_missing(self):
        """code_on_main_evidence.github_verified is explicitly
        service-stamped ('Do not set manually') -- a caller payload that
        omits it must NOT be refused for that reason.
        """
        entries, anomaly = _overlay()
        payload = {"transition_evidence": {"code_on_main_evidence": {"commit_sha": "a" * 40}}}
        digest = ev.validate_entity_payload("tracker.task", payload, "checkout.advance", _DICTIONARY, entries, anomaly)
        self.assertTrue(digest["ok"], digest)

    def test_bad_commit_sha_pattern_refused(self):
        entries, anomaly = _overlay()
        payload = {"transition_evidence": {"code_on_main_evidence": {"commit_sha": "not-40-hex-chars"}}}
        digest = ev.validate_entity_payload("tracker.task", payload, "checkout.advance", _DICTIONARY, entries, anomaly)
        self.assertFalse(digest["ok"])
        kinds = {v["kind"] for v in digest["refusal"]["violations"]}
        self.assertIn("constraint_violation", kinds)

    def test_entry_4_fully_derivable_logged_redundant(self):
        """entry 4 (checkout.advance to deploy-success, evidence shape)
        is dictionary_derivable == 'true' -- once Layer 1 catches the
        same nested shape it should be logged redundant.
        """
        entries, anomaly = _overlay()
        payload = {"transition_evidence": {"deploy_evidence": {"id": 1, "name": "job", "head_sha": "a" * 40}}}
        digest = ev.validate_entity_payload("tracker.task", payload, "checkout.advance", _DICTIONARY, entries, anomaly)
        redundant_anomalies = [a for a in digest["anomalies"] if a.startswith("redundant_overlay_entries")]
        self.assertEqual(len(redundant_anomalies), 1)
        self.assertIn("4", redundant_anomalies[0])
        # entry 13 (code_only chain) is 'partial' -- never counted redundant.
        self.assertNotIn("13", redundant_anomalies[0])


class Layer1PrecedenceTests(unittest.TestCase):
    """tracker.lesson encodes required-ness directly (constraints.required
    == true, B.1 scheme 1) -- Layer 1 must catch a missing required field
    on its own, with no overlay entry needed at all.
    """

    def test_layer1_alone_catches_missing_required_field(self):
        digest = ev.validate_entity_payload("tracker.lesson", {"title": "x"}, None, _DICTIONARY, [], None)
        self.assertFalse(digest["ok"])
        missing = set(digest["refusal"]["missing_fields"])
        self.assertIn("observation", missing)
        self.assertIn("pillar_scores", missing)
        # every violation must be attributable to layer 1 -- no "source":
        # "layer2" tag should appear since no overlay entries were passed.
        for v in digest["refusal"]["violations"]:
            self.assertNotEqual(v.get("source"), "layer2")

    def test_layer1_required_fields_checked_reported_on_success(self):
        payload = {"title": "a lesson title", "observation": "what happened", "pillar_scores": {"a": 1}}
        digest = ev.validate_entity_payload("tracker.lesson", payload, None, _DICTIONARY, [], None)
        self.assertTrue(digest["ok"])
        self.assertEqual(
            set(digest["layer1_required_fields_checked"]), {"title", "observation", "pillar_scores"}
        )

    def test_array_required_keys_per_item(self):
        entries, anomaly = _overlay()
        payload = {"category": "bug", "evidence": [{"description": "it broke"}]}  # steps_to_duplicate missing
        digest = ev.validate_entity_payload("tracker.issue", payload, None, _DICTIONARY, entries, anomaly)
        self.assertFalse(digest["ok"])
        self.assertTrue(any("steps_to_duplicate" in v["path"] for v in digest["refusal"]["violations"]))


class UnknownEntityTests(unittest.TestCase):
    def test_unknown_entity_refused(self):
        digest = ev.validate_entity_payload("tracker.not_a_real_entity", {}, None, _DICTIONARY, [], None)
        self.assertFalse(digest["ok"])
        self.assertEqual(digest["refusal"]["reason"], "unknown_entity")


# ---------------------------------------------------------------------------
# Overlay loading -- "overlay gaps never block"
# ---------------------------------------------------------------------------


class OverlayLoadingTests(unittest.TestCase):
    def test_real_overlay_file_loads_all_fourteen_entries(self):
        entries, anomaly = ev.load_overlay()
        self.assertIsNone(anomaly)
        self.assertEqual(len(entries), 14)
        ids = sorted(e["id"] for e in entries)
        self.assertEqual(ids, list(range(1, 15)))

    def test_missing_overlay_file_proceeds_with_anomaly_not_refusal(self):
        entries, anomaly = ev.load_overlay(Path("/nonexistent/path/elr_contracts.json"))
        self.assertEqual(entries, [])
        self.assertEqual(anomaly, "overlay-unavailable")

        # And validate_entity_payload must NOT refuse just because the
        # overlay is gone -- it proceeds Layer-1-only.
        payload = {"category": "epic", "priority": "P0", "user_story": "As a user I need X so that Y happens"}
        digest = ev.validate_entity_payload("tracker.feature", payload, "tracker.create", _DICTIONARY, entries, anomaly)
        self.assertTrue(digest["ok"])
        self.assertIn("overlay-unavailable", digest["anomalies"])

    def test_corrupt_overlay_file_proceeds_with_anomaly(self, tmp_path=None):
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            fh.write("{not valid json")
            corrupt_path = Path(fh.name)
        try:
            entries, anomaly = ev.load_overlay(corrupt_path)
            self.assertEqual(entries, [])
            self.assertEqual(anomaly, "overlay-unavailable")
        finally:
            corrupt_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Layer 1 dictionary fetch: auth-path resolution + fail-closed refusal
# ---------------------------------------------------------------------------


class DictionaryAuthPathTests(unittest.TestCase):
    def test_dedicated_key_file_wins_when_present(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            key_file = Path(tmp) / "dict-key.json"
            key_file.write_text(json.dumps({"token": "dedicated-token-value", "token_id": "x", "scope": "dictionary:read"}))
            with patch.object(ev, "DICT_KEY_FILE", key_file):
                token, auth_path, error = ev.resolve_dictionary_auth()
        self.assertEqual(token, "dedicated-token-value")
        self.assertEqual(auth_path, "dedicated-key")
        self.assertIsNone(error)

    def test_falls_back_to_internal_key_chain_when_key_file_absent(self):
        with patch.object(ev, "DICT_KEY_FILE", Path("/nonexistent/dict-key.json")):
            with patch.dict("os.environ", {"ENCELADUS_COORDINATION_INTERNAL_API_KEY": "fallback-value"}, clear=False):
                token, auth_path, error = ev.resolve_dictionary_auth()
        self.assertEqual(token, "fallback-value")
        self.assertEqual(auth_path, "fallback-internal-key")
        self.assertIsNone(error)

    def test_corrupt_key_file_falls_back_with_anomaly(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            key_file = Path(tmp) / "dict-key.json"
            key_file.write_text("{not valid json")
            with patch.object(ev, "DICT_KEY_FILE", key_file):
                with patch.dict("os.environ", {"ENCELADUS_COORDINATION_INTERNAL_API_KEY": "fallback-value"}, clear=False):
                    token, auth_path, error = ev.resolve_dictionary_auth()
        self.assertEqual(token, "fallback-value")
        self.assertEqual(auth_path, "fallback-internal-key")
        self.assertIsNotNone(error)

    def test_no_auth_available_when_nothing_resolves(self):
        env_keys = list(elr_config.COMMON_INTERNAL_KEY_ENV_CHAIN) + ["ENCELADUS_GOVERNANCE_API_INTERNAL_API_KEY"]
        import os

        with patch.object(ev, "DICT_KEY_FILE", Path("/nonexistent/dict-key.json")):
            saved = {k: os.environ.pop(k, None) for k in env_keys}
            try:
                token, auth_path, error = ev.resolve_dictionary_auth()
            finally:
                for k, v in saved.items():
                    if v is not None:
                        os.environ[k] = v
        self.assertEqual(token, "")
        self.assertEqual(auth_path, "no-auth-available")


class FetchDictionaryTests(unittest.TestCase):
    """fetch_dictionary() itself, with urlopen mocked -- no network."""

    def test_successful_pull_returns_parsed_dictionary(self):
        fake_resp = _governance_dictionary_response(_DICTIONARY)
        with patch.object(ev, "DICT_KEY_FILE", Path("/nonexistent/dict-key.json")):
            with patch.dict("os.environ", {"ENCELADUS_COORDINATION_INTERNAL_API_KEY": "some-key"}, clear=False):
                with patch("elr_lib.transport.urllib.request.urlopen", return_value=fake_resp):
                    with patch.object(ev, "_write_session_cache"):
                        result = ev.fetch_dictionary(timeout=5)
        self.assertTrue(result["ok"])
        self.assertEqual(result["auth_path"], "fallback-internal-key")
        self.assertEqual(result["version"], _DICTIONARY["version"])
        self.assertEqual(result["entity_count"], len(_DICTIONARY["entities"]))
        self.assertTrue(result["content_hash"].startswith("sha256:"))
        self.assertIn("governance_data_dictionary.json", result["source_route"])

    def test_unreachable_dictionary_is_not_ok(self):
        with patch.object(ev, "DICT_KEY_FILE", Path("/nonexistent/dict-key.json")):
            with patch("elr_lib.transport.urllib.request.urlopen", side_effect=urllib.error.URLError("no route")):
                result = ev.fetch_dictionary(timeout=5)
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], 0)
        self.assertIn("error", result)
        self.assertIsNotNone(result["error"])

    def test_http_error_dictionary_is_not_ok(self):
        import io

        http_err = urllib.error.HTTPError(
            url="https://jreese.net/api/v1/governance/governance_data_dictionary.json",
            code=403,
            msg="forbidden",
            hdrs=None,
            fp=io.BytesIO(b'{"error":"forbidden"}'),
        )
        with patch.object(ev, "DICT_KEY_FILE", Path("/nonexistent/dict-key.json")):
            with patch("elr_lib.transport.urllib.request.urlopen", side_effect=http_err):
                result = ev.fetch_dictionary(timeout=5)
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], 403)


class CmdValidateFailClosedTests(unittest.TestCase):
    """The end-to-end `validate` command path: dictionary-unreachable
    MUST produce a refusal digest, never a fallback/degraded validation.
    """

    def _args(self, **overrides):
        import argparse

        base = dict(entity="tracker.feature", payload="-", op="tracker.create", overlay=None, timeout=5)
        base.update(overrides)
        return argparse.Namespace(**base)

    def test_dictionary_unreachable_is_a_refusal_not_a_fallback(self):
        unreachable_result = {
            "ok": False,
            "auth_path": "fallback-internal-key",
            "status": 0,
            "source_route": "https://bogus.invalid.example/governance/governance_data_dictionary.json",
            "dictionary": None,
            "version": None,
            "entity_count": None,
            "size_bytes": None,
            "content_hash": None,
            "error": "unreachable: no route",
            "anomalies": [],
        }
        with patch.object(ev, "fetch_dictionary", return_value=unreachable_result):
            digest = ev.cmd_validate(self._args())

        self.assertFalse(digest["ok"])
        self.assertEqual(digest["refusal"]["reason"], "dictionary_unreachable")
        # It must be a REFUSAL -- never quietly proceed with a partial or
        # cached validation result.
        self.assertNotIn("layer1_required_fields_checked", digest)

    def test_invalid_payload_json_is_a_refusal(self):
        ok_result = {
            "ok": True,
            "auth_path": "fallback-internal-key",
            "status": 200,
            "source_route": "https://jreese.net/api/v1/governance/governance_data_dictionary.json",
            "dictionary": _DICTIONARY,
            "version": _DICTIONARY["version"],
            "entity_count": len(_DICTIONARY["entities"]),
            "size_bytes": 100,
            "content_hash": "sha256:deadbeef",
            "error": None,
            "anomalies": [],
        }
        with patch.object(ev, "fetch_dictionary", return_value=ok_result):
            with patch.object(ev, "_read_source", return_value="{not valid json"):
                digest = ev.cmd_validate(self._args())
        self.assertFalse(digest["ok"])
        self.assertEqual(digest["refusal"]["reason"], "invalid_payload_input")


# ---------------------------------------------------------------------------
# Layer 3 -- structured error-envelope learning
# ---------------------------------------------------------------------------


class Layer3EnvelopeLearningTests(unittest.TestCase):
    """Real shape observed live in backend/lambda/tracker_mutation/
    lambda_function.py's _tracker_create_validation_error /
    _error helpers: error_envelope.{code,message,retryable,details},
    with details flattened onto the top level too (body.update(details)).
    """

    def _real_shape_envelope(self):
        return {
            "success": False,
            "error": "Feature creation requires user_story.",
            "error_envelope": {
                "code": 400,
                "message": "Feature creation requires user_story.",
                "retryable": False,
                "details": {
                    "record_type": "feature",
                    "missing_required_fields": ["user_story"],
                    "governed_rules": [],
                    "allowed_values": {"priority": ["P0", "P1", "P2", "P3"], "category": ["capability", "enhancement", "epic", "infrastructure"]},
                    "example_fix": {
                        "tool": "tracker_create",
                        "arguments": {"project_id": "<project_id>", "record_type": "feature", "title": "<title>", "governance_hash": "<governance_hash>"},
                    },
                },
            },
            # body.update(details) flattens these onto the top level too:
            "record_type": "feature",
            "missing_required_fields": ["user_story"],
            "governed_rules": [],
            "allowed_values": {"priority": ["P0", "P1", "P2", "P3"], "category": ["capability", "enhancement", "epic", "infrastructure"]},
            "example_fix": {
                "tool": "tracker_create",
                "arguments": {"project_id": "<project_id>", "record_type": "feature", "title": "<title>", "governance_hash": "<governance_hash>"},
            },
        }

    def test_fields_surfaced_verbatim(self):
        digest = ev.learn_from_envelope(self._real_shape_envelope())
        self.assertTrue(digest["ok"])
        parsed = digest["parsed"]
        self.assertEqual(parsed["code"], 400)
        self.assertEqual(parsed["message"], "Feature creation requires user_story.")
        self.assertEqual(parsed["retryable"], False)
        self.assertEqual(parsed["missing_required_fields"], ["user_story"])
        self.assertEqual(parsed["allowed_values"]["category"], ["capability", "enhancement", "epic", "infrastructure"])
        self.assertEqual(parsed["example_fix"]["tool"], "tracker_create")
        self.assertEqual(parsed["record_type"], "feature")

    def test_proposed_overlay_entry_emitted_but_never_written(self):
        digest = ev.learn_from_envelope(self._real_shape_envelope())
        proposed = digest["proposed_overlay_entry"]
        self.assertIn("user_story", proposed["requirement"])
        self.assertEqual(proposed["required_fields"], ["user_story"])
        self.assertIn("PROPOSED", proposed["verified"]["status"])
        # elr_contracts.json on disk must be untouched by a learn() call.
        on_disk = json.loads(ev.DEFAULT_OVERLAY_PATH.read_text(encoding="utf-8"))
        self.assertEqual(len(on_disk["entries"]), 14)

    def test_document_api_shape_required_fields_key(self):
        """document_api's error envelope uses 'required_fields' (not
        'missing_required_fields') under error_envelope.details -- both
        naming variants must be tolerated.
        """
        envelope = {
            "error": "handoff document missing source_record_id",
            "error_envelope": {
                "code": "INVALID_INPUT",
                "message": "handoff document missing source_record_id",
                "details": {
                    "required_fields": ["source_record_id"],
                    "dictionary_entity": "document.handoff",
                    "document_subtype": "handoff",
                },
            },
        }
        digest = ev.learn_from_envelope(envelope)
        self.assertEqual(digest["parsed"]["required_fields"], ["source_record_id"])
        self.assertEqual(digest["parsed"]["dictionary_entity"], "document.handoff")

    def test_learn_command_reads_from_file(self):
        import argparse
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(self._real_shape_envelope(), fh)
            envelope_path = fh.name
        try:
            args = argparse.Namespace(envelope=envelope_path)
            digest = ev.cmd_learn(args)
        finally:
            Path(envelope_path).unlink(missing_ok=True)
        self.assertTrue(digest["ok"])
        self.assertEqual(digest["parsed"]["missing_required_fields"], ["user_story"])

    def test_learn_command_invalid_json_is_refusal(self):
        import argparse

        args = argparse.Namespace(envelope="-")
        with patch.object(ev, "_read_source", return_value="{not valid json"):
            digest = ev.cmd_learn(args)
        self.assertFalse(digest["ok"])
        self.assertEqual(digest["refusal"]["reason"], "invalid_envelope_input")


# ---------------------------------------------------------------------------
# CLI shape: allow_abbrev=False (A.8's argparse prefix trap)
# ---------------------------------------------------------------------------


class CliTests(unittest.TestCase):
    def test_top_level_flag_abbreviation_rejected(self):
        parser = ev.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["--time", "5", "validate", "--entity", "tracker.feature", "--payload", "-"])

    def test_subcommand_flag_abbreviation_rejected(self):
        parser = ev.build_parser()
        with self.assertRaises(SystemExit):
            # "--ent" must NOT silently bind to "--entity"
            parser.parse_args(["validate", "--ent", "tracker.feature", "--payload", "-"])

    def test_full_flags_parse_cleanly(self):
        parser = ev.build_parser()
        args = parser.parse_args(["validate", "--entity", "tracker.feature", "--payload", "-", "--op", "tracker.create"])
        self.assertEqual(args.command, "validate")
        self.assertEqual(args.entity, "tracker.feature")
        self.assertEqual(args.op, "tracker.create")

    def test_learn_subcommand_parses(self):
        parser = ev.build_parser()
        args = parser.parse_args(["learn", "--envelope", "-"])
        self.assertEqual(args.command, "learn")
        self.assertEqual(args.envelope, "-")

    def test_missing_command_is_an_error(self):
        parser = ev.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args([])

    def test_main_exits_nonzero_on_refusal(self):
        unreachable_result = {
            "ok": False,
            "auth_path": "no-auth-available",
            "status": 0,
            "source_route": "https://jreese.net/api/v1/governance/governance_data_dictionary.json",
            "dictionary": None,
            "version": None,
            "entity_count": None,
            "size_bytes": None,
            "content_hash": None,
            "error": "unreachable",
            "anomalies": [],
        }
        with patch.object(ev, "fetch_dictionary", return_value=unreachable_result):
            rc = ev.main(["validate", "--entity", "tracker.feature", "--payload", "-"])
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
