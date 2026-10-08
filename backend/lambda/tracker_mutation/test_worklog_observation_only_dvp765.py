"""test_worklog_observation_only_dvp765.py — `observation_only` on POST .../log (DVP-TSK-765).

The observer-clock defect class (DVP-TSK-736 defect 1): a periodic observer
that re-confirms a record through `_handle_log()` appends a worklog entry,
which bumps updated_at / sync_version and allocates a version_seq -- so an
unchanged record reads as freshly modified. `observation_only: true` records
the observation on its own clock instead: SET last_observed_at, ADD
observation_count, and nothing else.

Covers:
  * The DEFAULT path (flag absent, or explicitly false) is pinned: the exact
    update_item kwargs and the exact response body are asserted against
    literals, so any change to the default path fails here. So is its
    validation: false or null with no description is the same literal 400,
    with no write.
  * The default path still bumps updated_at / sync_version / history /
    version_seq on the persisted record.
  * Two observation_only calls leave updated_at unchanged while
    observation_count goes 1 -> 2, and change nothing on the item except the
    two observation attributes -- so content_hash is unchanged too.
  * The gates in front of the write (existence, task checkout ownership)
    still apply; a non-boolean flag is refused; a null description is read as
    absent and a non-string one refused; GET exposes both fields.
  * Both fields are server-side only: tracker.set and tracker.create refuse
    them with 400 RESERVED_FIELD, as for the ENC-TSK-F41 counters.

Run: python3 -m pytest test_worklog_observation_only_dvp765.py -q
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import unittest
from unittest import mock

import boto3
from moto import mock_aws

os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
_spec = importlib.util.spec_from_file_location(
    "tracker_mutation_observation_only_dvp765",
    os.path.join(_HERE, "lambda_function.py"),
)
tm = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
sys.modules[_spec.name] = tm
_spec.loader.exec_module(tm)

# The read-side content_hash (DOC-59D2295AA7FD section 7.1.6) is computed by the
# MCP server's pure projection module; load it by path to assert against the
# real function rather than a re-statement of its field list.
_REPO = os.path.dirname(os.path.dirname(os.path.dirname(_HERE)))
_mp_spec = importlib.util.spec_from_file_location(
    "manifest_projection_dvp765",
    os.path.join(_REPO, "tools", "enceladus-mcp-server", "manifest_projection.py"),
)
manifest_projection = importlib.util.module_from_spec(_mp_spec)
assert _mp_spec and _mp_spec.loader
_mp_spec.loader.exec_module(manifest_projection)

PROVIDER = "github"
ISSUE = "ENC-ISS-765"
ISSUE_KEY = {"project_id": {"S": "enceladus"}, "record_id": {"S": f"issue#{ISSUE}"}}
PRIOR_UPDATED_AT = "2026-09-01T00:00:00Z"
NOW = "2026-10-07T12:00:00Z"


def _body(provider=PROVIDER, **extra):
    body = {"write_source": {"provider": provider, "channel": "mcp_server"}}
    body.update(extra)
    return body


def _payload(resp):
    return json.loads(resp["body"])


class ObservationBase(unittest.TestCase):
    """moto-backed tracker table (mirrors test_worklog_versionseq_m79.py fixtures)."""

    def setUp(self):
        self._moto = mock_aws()
        self._moto.start()
        self.addCleanup(self._moto.stop)
        self.ddb = boto3.client("dynamodb", region_name="us-west-2")
        self.ddb.create_table(
            TableName=tm.DYNAMODB_TABLE,
            AttributeDefinitions=[
                {"AttributeName": "project_id", "AttributeType": "S"},
                {"AttributeName": "record_id", "AttributeType": "S"},
            ],
            KeySchema=[
                {"AttributeName": "project_id", "KeyType": "HASH"},
                {"AttributeName": "record_id", "KeyType": "RANGE"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        for table, key in (
            (tm.CHECKOUT_TOKENS_TABLE, "pk"),
            (tm.AGENT_SESSIONS_TABLE, "session_id"),
            (tm.PROJECTS_TABLE, "project_id"),
        ):
            self.ddb.create_table(
                TableName=table,
                AttributeDefinitions=[{"AttributeName": key, "AttributeType": "S"}],
                KeySchema=[{"AttributeName": key, "KeyType": "HASH"}],
                BillingMode="PAY_PER_REQUEST",
            )
        patcher = mock.patch.object(tm, "_ddb", self.ddb)
        patcher.start()
        self.addCleanup(patcher.stop)

    def put_issue(self, **extra):
        item = {
            **ISSUE_KEY,
            "item_id": {"S": ISSUE},
            "record_type": {"S": "issue"},
            "status": {"S": "open"},
            "title": {"S": "DVP-TSK-765 observation subject"},
            "updated_at": {"S": PRIOR_UPDATED_AT},
            "last_update_note": {"S": "the last real change"},
            "sync_version": {"N": "5"},
            "version_seq": {"N": "17"},
            "feed_scope": {"S": "global"},
            "history": {"L": [{"M": {
                "timestamp": {"S": PRIOR_UPDATED_AT},
                "status": {"S": "worklog"},
                "description": {"S": "the last real change"},
            }}]},
        }
        item.update(extra)
        self.ddb.put_item(TableName=tm.DYNAMODB_TABLE, Item=item)

    def get_item(self, key=ISSUE_KEY):
        return self.ddb.get_item(TableName=tm.DYNAMODB_TABLE, Key=key).get("Item") or {}

    def capture_record_update(self, key=ISSUE_KEY):
        """Proxy the moto client, capturing only update_item calls on `key`
        (the version_seq allocator's own counter-row writes pass through)."""
        real_ddb = self.ddb
        captured = []

        class _SpyDdb:
            def update_item(self, **kwargs):
                if kwargs.get("Key") == key:
                    captured.append(kwargs)
                return real_ddb.update_item(**kwargs)

            def __getattr__(self, name):
                return getattr(real_ddb, name)

        patcher = mock.patch.object(tm, "_ddb", _SpyDdb())
        patcher.start()
        self.addCleanup(patcher.stop)
        return captured


# ---------------------------------------------------------------------------
# The default path, pinned
# ---------------------------------------------------------------------------


class DefaultPathPinTests(ObservationBase):
    #: The literal update_item call the default /log path made BEFORE
    #: DVP-TSK-765, with the clock fixed at NOW and the allocator at 41. If
    #: this needs editing, the default path changed -- which DVP-TSK-765 forbids.
    EXPECTED_UPDATE = {
        "TableName": tm.DYNAMODB_TABLE,
        "Key": ISSUE_KEY,
        "UpdateExpression": (
            "SET updated_at = :now, last_update_note = :note, "
            "write_source = :wsrc, "
            "sync_version = if_not_exists(sync_version, :zero) + :one, "
            "history = list_append(if_not_exists(history, :empty), :hentry)"
            ", version_seq = :vseq, feed_scope = :fscope"
        ),
        "ExpressionAttributeValues": {
            ":now": {"S": NOW},
            ":note": {"S": "pinned default entry"},
            ":wsrc": {"M": {
                "channel": {"S": "mcp_server"},
                "provider": {"S": PROVIDER},
                "dispatch_id": {"S": ""},
                "coordination_request_id": {"S": ""},
                "timestamp": {"S": NOW},
            }},
            ":zero": {"N": "0"},
            ":one": {"N": "1"},
            ":hentry": {"L": [{"M": {
                "timestamp": {"S": NOW},
                "status": {"S": "worklog"},
                "description": {"S": "pinned default entry"},
            }}]},
            ":empty": {"L": []},
            ":vseq": {"N": "41"},
            ":fscope": {"S": "global"},
        },
    }
    EXPECTED_RESPONSE = {"success": True, "record_id": ISSUE, "updated_at": NOW}

    def _log(self, **flag):
        self.put_issue()
        captured = self.capture_record_update()
        with mock.patch.object(tm, "_now_z", return_value=NOW), \
                mock.patch.object(tm, "allocate_version_seq", return_value=41):
            resp = tm._handle_log(
                "enceladus", "issue", ISSUE, _body(description="pinned default entry", **flag),
            )
        return resp, captured

    def test_flag_absent_makes_the_pinned_update_item_call(self):
        resp, captured = self._log()
        self.assertEqual(resp["statusCode"], 200)
        self.assertEqual(captured, [self.EXPECTED_UPDATE])
        self.assertEqual(_payload(resp), self.EXPECTED_RESPONSE)

    def test_flag_false_is_byte_identical_to_flag_absent(self):
        resp, captured = self._log(observation_only=False)
        self.assertEqual(resp["statusCode"], 200)
        self.assertEqual(captured, [self.EXPECTED_UPDATE])
        self.assertEqual(_payload(resp), self.EXPECTED_RESPONSE)

    def test_flag_null_is_treated_as_absent(self):
        resp, captured = self._log(observation_only=None)
        self.assertEqual(captured, [self.EXPECTED_UPDATE])
        self.assertEqual(_payload(resp), self.EXPECTED_RESPONSE)

    def test_default_log_still_bumps_updated_at_exactly_as_before(self):
        self.put_issue()
        with mock.patch.object(tm, "_now_z", return_value=NOW):
            resp = tm._handle_log("enceladus", "issue", ISSUE, _body(description="a real change"))
        self.assertEqual(resp["statusCode"], 200)

        item = self.get_item()
        self.assertEqual(item["updated_at"]["S"], NOW)
        self.assertNotEqual(item["updated_at"]["S"], PRIOR_UPDATED_AT)
        self.assertEqual(item["sync_version"]["N"], "6")
        self.assertEqual(len(item["history"]["L"]), 2)
        self.assertEqual(item["last_update_note"]["S"], "a real change")
        self.assertNotIn("last_observed_at", item)
        self.assertNotIn("observation_count", item)

    def test_default_log_still_requires_a_description(self):
        self.put_issue()
        resp = tm._handle_log("enceladus", "issue", ISSUE, _body())
        self.assertEqual(resp["statusCode"], 400)
        self.assertIn("description", _payload(resp)["error"])

    #: The literal 400 the default path returned BEFORE DVP-TSK-765 for a
    #: missing or blank description.
    EXPECTED_DESCRIPTION_REQUIRED = {
        "success": False,
        "error": "Field 'description' is required.",
        "error_envelope": {
            "code": "INVALID_INPUT",
            "message": "Field 'description' is required.",
            "retryable": False,
            "details": {},
        },
    }

    def test_false_and_null_keep_the_description_guard_and_write_nothing(self):
        """The validation half of the pin. false and null are the default path,
        so a missing or blank description is the same 400 as with the flag
        absent, and nothing is written -- no history entry, no observation."""
        self.put_issue()
        before = self.get_item()
        captured = self.capture_record_update()
        for flag in ({}, {"observation_only": False}, {"observation_only": None}):
            for description in ({}, {"description": ""}, {"description": "   "}):
                with self.subTest(flag=flag, description=description):
                    resp = tm._handle_log(
                        "enceladus", "issue", ISSUE, _body(**flag, **description),
                    )
                    self.assertEqual(resp["statusCode"], 400)
                    self.assertEqual(_payload(resp), self.EXPECTED_DESCRIPTION_REQUIRED)
        self.assertEqual(captured, [])
        self.assertEqual(self.get_item(), before)


# ---------------------------------------------------------------------------
# observation_only: true
# ---------------------------------------------------------------------------


class ObservationOnlyTests(ObservationBase):
    def _observe(self, now, **extra):
        with mock.patch.object(tm, "_now_z", return_value=now):
            return tm._handle_log(
                "enceladus", "issue", ISSUE, _body(observation_only=True, **extra),
            )

    def test_two_observations_hold_updated_at_while_the_count_goes_1_then_2(self):
        self.put_issue()

        first = self._observe("2026-10-07T12:00:00Z")
        self.assertEqual(first["statusCode"], 200)
        self.assertEqual(_payload(first), {
            "success": True, "record_id": ISSUE, "observation_only": True,
            "last_observed_at": "2026-10-07T12:00:00Z", "observation_count": 1,
        })
        self.assertEqual(self.get_item()["updated_at"]["S"], PRIOR_UPDATED_AT)

        second = self._observe("2026-10-07T13:00:00Z")
        self.assertEqual(_payload(second)["observation_count"], 2)
        self.assertEqual(_payload(second)["last_observed_at"], "2026-10-07T13:00:00Z")

        item = self.get_item()
        self.assertEqual(item["updated_at"]["S"], PRIOR_UPDATED_AT)
        self.assertEqual(item["observation_count"]["N"], "2")
        self.assertEqual(item["last_observed_at"]["S"], "2026-10-07T13:00:00Z")

    def test_an_observation_changes_nothing_but_the_two_observation_fields(self):
        self.put_issue()
        before = self.get_item()
        for _ in range(2):
            self.assertEqual(self._observe(NOW)["statusCode"], 200)
        after = self.get_item()

        # Not vacuous: the observation landed ...
        self.assertEqual(after["observation_count"], {"N": "2"})
        self.assertEqual(after["last_observed_at"], {"S": NOW})
        # ... and it is the ONLY thing that did.
        unchanged = {k: v for k, v in after.items()
                     if k not in ("last_observed_at", "observation_count")}
        self.assertEqual(unchanged, before)
        # Spelled out for the fields DVP-TSK-765 names.
        for field in ("updated_at", "sync_version", "version_seq", "history",
                      "last_update_note", "feed_scope"):
            self.assertEqual(after[field], before[field], field)
        self.assertNotIn("write_source", after)

    def test_an_observation_leaves_content_hash_unchanged(self):
        self.put_issue()
        before = manifest_projection.compute_content_hash(tm._deser_item(self.get_item()))
        self.assertEqual(self._observe(NOW)["statusCode"], 200)
        observed = self.get_item()
        self.assertEqual(observed["observation_count"], {"N": "1"})
        after = manifest_projection.compute_content_hash(tm._deser_item(observed))
        self.assertEqual(after, before)

        # Contrast: a worklog append DOES move it (updated_at is a hashed field).
        tm._handle_log("enceladus", "issue", ISSUE, _body(description="real change"))
        moved = manifest_projection.compute_content_hash(tm._deser_item(self.get_item()))
        self.assertNotEqual(moved, before)

    def test_an_observation_is_one_two_attribute_update(self):
        self.put_issue()
        captured = self.capture_record_update()
        self._observe(NOW)
        self.assertEqual(len(captured), 1)
        call = captured[0]
        self.assertEqual(
            call["UpdateExpression"], "SET last_observed_at = :obs ADD observation_count :one"
        )
        self.assertEqual(call["ExpressionAttributeValues"],
                         {":obs": {"S": NOW}, ":one": {"N": "1"}})
        self.assertEqual(call["ConditionExpression"], "attribute_exists(record_id)")

    def test_an_observation_allocates_no_version_seq_and_mirrors_no_worklog(self):
        self.put_issue()
        with mock.patch.object(tm, "allocate_version_seq") as allocate, \
                mock.patch.object(tm, "_mirror_worklog_to_session") as mirror:
            resp = self._observe(NOW)
        self.assertEqual(resp["statusCode"], 200)
        allocate.assert_not_called()
        mirror.assert_not_called()

    def test_description_is_optional_and_never_appended(self):
        self.put_issue()
        resp = self._observe(NOW, description="seen; still current")
        self.assertEqual(resp["statusCode"], 200)
        item = self.get_item()
        self.assertEqual(len(item["history"]["L"]), 1)
        self.assertEqual(item["last_update_note"]["S"], "the last real change")

    def test_a_null_description_reads_as_absent(self):
        """{observation_only: true, description: null} must not reach .strip()."""
        self.put_issue()
        resp = self._observe(NOW, description=None)
        self.assertEqual(resp["statusCode"], 200)
        self.assertEqual(_payload(resp)["observation_count"], 1)
        item = self.get_item()
        self.assertEqual(len(item["history"]["L"]), 1)
        self.assertEqual(item["updated_at"]["S"], PRIOR_UPDATED_AT)

    def test_a_null_description_through_lambda_handler_is_a_recorded_observation(self):
        """End to end: the request body is parsed and dispatched, and the null
        description is an observation, not an unhandled Lambda error."""
        self.put_issue()
        path = f"/api/v1/tracker/enceladus/issue/{ISSUE}/log"
        event = {
            "requestContext": {"http": {"method": "POST", "path": path}},
            "headers": {"host": "example.com"},
            "rawPath": path,
            "body": json.dumps(_body(observation_only=True, description=None)),
        }
        with mock.patch.object(tm, "_authenticate", return_value=({"internal_service": True}, None)), \
                mock.patch.object(tm, "_validate_project_exists", return_value=None), \
                mock.patch.object(tm, "_now_z", return_value=NOW):
            resp = tm.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 200)
        self.assertEqual(_payload(resp)["last_observed_at"], NOW)
        self.assertEqual(self.get_item()["observation_count"], {"N": "1"})

    def test_a_non_string_description_is_refused_without_a_write(self):
        self.put_issue()
        before = self.get_item()
        for value in (7, {}, ["seen"], True):
            resp = self._observe(NOW, description=value)
            self.assertEqual(resp["statusCode"], 400, value)
            self.assertIn("description", _payload(resp)["error"])
        self.assertEqual(self.get_item(), before)

    def test_a_non_boolean_flag_is_refused_without_a_write(self):
        self.put_issue()
        before = self.get_item()
        for value in ("true", "false", 1, 0, {}):
            resp = tm._handle_log(
                "enceladus", "issue", ISSUE,
                _body(description="ambiguous flag", observation_only=value),
            )
            self.assertEqual(resp["statusCode"], 400, value)
            self.assertIn("observation_only", _payload(resp)["error"])
        self.assertEqual(self.get_item(), before)

    def test_a_missing_record_is_404_and_nothing_is_created(self):
        resp = self._observe(NOW)
        self.assertEqual(resp["statusCode"], 404)
        self.assertEqual(self.get_item(), {})

    def test_a_record_deleted_after_the_read_is_404_not_a_phantom_item(self):
        # The existence read in _handle_log has passed; the record is gone by
        # the time the write lands. Without the condition, UpdateItem would
        # create an item holding only the two observation attributes.
        resp = tm._record_observation(self.ddb, ISSUE_KEY, ISSUE)
        self.assertEqual(resp["statusCode"], 404)
        self.assertEqual(self.get_item(), {})

    def test_a_task_observation_still_requires_the_checkout(self):
        task_key = {"project_id": {"S": "enceladus"}, "record_id": {"S": "task#ENC-TSK-765"}}
        self.ddb.put_item(TableName=tm.DYNAMODB_TABLE, Item={
            **task_key, "item_id": {"S": "ENC-TSK-765"}, "record_type": {"S": "task"},
            "status": {"S": "open"}, "updated_at": {"S": PRIOR_UPDATED_AT},
        })
        resp = tm._handle_log(
            "enceladus", "task", "ENC-TSK-765", _body(observation_only=True),
        )
        self.assertEqual(resp["statusCode"], 409)
        self.assertNotIn("observation_count", self.get_item(task_key))

    def test_get_exposes_both_observation_fields(self):
        self.put_issue()
        self._observe(NOW)
        resp = tm._handle_get_record("enceladus", "issue", ISSUE)
        self.assertEqual(resp["statusCode"], 200)
        record = _payload(resp)["record"]
        self.assertEqual(record["last_observed_at"], NOW)
        self.assertEqual(record["observation_count"], 1)
        self.assertEqual(record["updated_at"], PRIOR_UPDATED_AT)


# ---------------------------------------------------------------------------
# The observation fields are server-side only (the ENC-TSK-F41 precedent)
# ---------------------------------------------------------------------------


class ReservedObservationFieldTests(ObservationBase):
    OBSERVATION_FIELDS = ("last_observed_at", "observation_count")

    def _assert_reserved(self, resp, field):
        self.assertEqual(resp["statusCode"], 400, field)
        envelope = _payload(resp)["error_envelope"]
        self.assertEqual(envelope["code"], "RESERVED_FIELD")
        self.assertEqual(envelope["details"]["field"], field)
        self.assertEqual(envelope["details"]["reason"], "server_side_only")
        self.assertEqual(envelope["details"]["rule_citation"], "DVP-TSK-765")

    def test_patch_cannot_write_either_field(self):
        """A forged last_observed_at, or a non-numeric observation_count that
        would make every later observation's ADD a retryable 500, is refused
        before any read or write."""
        self.put_issue()
        before = self.get_item()
        for field, value in (("last_observed_at", "2099-01-01T00:00:00Z"),
                             ("observation_count", "not-a-number")):
            resp = tm._handle_update_field(
                "enceladus", "issue", ISSUE, _body(field=field, value=value),
            )
            self._assert_reserved(resp, field)
        self.assertEqual(self.get_item(), before)

        # The observation path is unharmed: the ADD still lands on a number.
        with mock.patch.object(tm, "_now_z", return_value=NOW):
            observed = tm._handle_log(
                "enceladus", "issue", ISSUE, _body(observation_only=True),
            )
        self.assertEqual(observed["statusCode"], 200)
        self.assertEqual(_payload(observed)["observation_count"], 1)

    def test_the_patch_guard_precedes_any_ddb_call(self):
        fake = mock.MagicMock()
        with mock.patch.object(tm, "_get_ddb", return_value=fake):
            for field in self.OBSERVATION_FIELDS:
                resp = tm._handle_update_field(
                    "enceladus", "issue", ISSUE, _body(field=field, value="x"),
                )
                self._assert_reserved(resp, field)
        fake.update_item.assert_not_called()
        fake.get_item.assert_not_called()

    def test_create_cannot_seed_either_field(self):
        for field, value in (("last_observed_at", NOW), ("observation_count", 3)):
            resp = tm._handle_create_record(
                "enceladus", "issue", {"title": "seeded observation", field: value},
            )
            self._assert_reserved(resp, field)


if __name__ == "__main__":
    unittest.main()
