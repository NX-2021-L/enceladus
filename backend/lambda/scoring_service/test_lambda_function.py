"""Unit tests for the Enceladus Scoring Service (ENC-TSK-H47 / B63 Phase 2B).

Pure-function tests + an idempotent write-back test that fakes the DynamoDB client. No real AWS.
Runs under pytest (test_* discovery) and standalone (`python test_lambda_function.py`).
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lambda_function as sf  # noqa: E402

try:
    from botocore.exceptions import ClientError
except ImportError:  # botocore always present in the Lambda runtime; guard local bare envs
    class ClientError(Exception):  # type: ignore
        def __init__(self, response, op):
            super().__init__("ClientError")
            self.response = response


GOOD_PILLARS = {"efficiency": 0.8, "human_protection": 0.7, "intention": 0.6, "alignment": 0.75}


def _sns_event(message_dict):
    return {"Records": [{"EventSource": "aws:sns", "Sns": {"Message": json.dumps(message_dict)}}]}


def _scoring_message(**over):
    msg = {
        "event_type": "lesson.scoring.requested",
        "schema_version": 1,
        "project_id": "enceladus",
        "record_id": "lesson#ENC-LSN-001",
        "item_id": "ENC-LSN-001",
        "pillar_scores": dict(GOOD_PILLARS),
    }
    msg.update(over)
    return msg


# --- scoring parity with tracker_mutation (ENC-FTR-054) ----------------------
def test_pillar_composite_weighting():
    # 0.25*0.8 + 0.30*0.7 + 0.20*0.6 + 0.25*0.75 = 0.2 + 0.21 + 0.12 + 0.1875 = 0.7175
    assert sf._compute_lesson_pillar_composite(GOOD_PILLARS) == 0.7175


def test_pillar_composite_clamps_out_of_range():
    # Values outside [0,1] are clamped before weighting.
    clamped = sf._compute_lesson_pillar_composite(
        {"efficiency": 5.0, "human_protection": -1.0, "intention": 0.0, "alignment": 0.0}
    )
    assert clamped == round(0.25 * 1.0, 4)


def test_resonance_in_unit_interval():
    r = sf._compute_resonance_score(GOOD_PILLARS)
    assert 0.0 <= r <= 1.0


def test_resonance_force_surrender_penalty():
    # High efficiency (drives force) + low human_protection (drives surrender) trips the penalty,
    # so resonance is strictly lower than a balanced profile.
    spiky = sf._compute_resonance_score({"efficiency": 1.0, "human_protection": 0.0,
                                         "intention": 0.0, "alignment": 0.0})
    balanced = sf._compute_resonance_score({"efficiency": 0.5, "human_protection": 0.5,
                                            "intention": 0.5, "alignment": 0.5})
    assert spiky < balanced


def test_coerce_pillar_scores_rejects_missing_pillar():
    assert sf._coerce_pillar_scores({"efficiency": 0.5}) is None
    assert sf._coerce_pillar_scores("not-a-dict") is None
    assert sf._coerce_pillar_scores({**GOOD_PILLARS, "intention": "x"}) is None
    assert sf._coerce_pillar_scores(GOOD_PILLARS) == GOOD_PILLARS


# --- idempotent write-back (SNS at-least-once) -------------------------------
class _FakeDDB:
    def __init__(self, *, raise_conditional=False, raise_other=False):
        self.calls = []
        self._raise_conditional = raise_conditional
        self._raise_other = raise_other

    def update_item(self, **kwargs):
        self.calls.append(kwargs)
        if self._raise_conditional:
            raise ClientError({"Error": {"Code": "ConditionalCheckFailedException"}}, "UpdateItem")
        if self._raise_other:
            raise ClientError({"Error": {"Code": "ProvisionedThroughputExceededException"}}, "UpdateItem")
        return {}


def _patch_ddb(fake):
    sf._ddb_client = fake
    sf._ddb = lambda: fake  # type: ignore


def test_apply_scores_writes_scored_with_pending_guard():
    fake = _FakeDDB()
    _patch_ddb(fake)
    out = sf._apply_scores("enceladus", "lesson#ENC-LSN-001", 0.7175, 0.5)
    assert out == "scored"
    call = fake.calls[0]
    # Idempotency guard: conditional on scoring_status=pending.
    assert "scoring_status = :pending" in call["ConditionExpression"]
    assert call["ExpressionAttributeValues"][":scored"] == {"S": "scored"}
    assert call["ExpressionAttributeValues"][":pc"] == {"N": "0.7175"}


def test_apply_scores_conditional_failure_is_noop():
    _patch_ddb(_FakeDDB(raise_conditional=True))
    assert sf._apply_scores("enceladus", "lesson#ENC-LSN-001", 0.7, 0.5) == "noop"


def test_apply_scores_other_error_returns_error():
    _patch_ddb(_FakeDDB(raise_other=True))
    assert sf._apply_scores("enceladus", "lesson#ENC-LSN-001", 0.7, 0.5) == "error"


# --- end-to-end through the SNS handler -------------------------------------
def test_handler_scores_sns_record():
    fake = _FakeDDB()
    _patch_ddb(fake)
    out = sf.lambda_handler(_sns_event(_scoring_message()), None)
    assert out["processed"] == 1 and out["errors"] == 0
    assert out["results"][0]["outcome"] == "scored"
    assert out["results"][0]["pillar_composite"] == 0.7175
    assert len(fake.calls) == 1


def test_handler_duplicate_delivery_is_idempotent():
    # First delivery scores; replayed delivery hits the pending-guard and is a no-op success.
    _patch_ddb(_FakeDDB(raise_conditional=True))
    out = sf.lambda_handler(_sns_event(_scoring_message()), None)
    assert out["errors"] == 0 and out["results"][0]["outcome"] == "noop"


def test_handler_skips_bad_pillar_scores_without_write():
    fake = _FakeDDB()
    _patch_ddb(fake)
    out = sf.lambda_handler(_sns_event(_scoring_message(pillar_scores={"efficiency": 0.5})), None)
    assert out["errors"] == 0
    assert out["results"][0]["outcome"] == "skipped"
    assert fake.calls == []  # no DynamoDB write for an unscorable message


def test_handler_raises_on_write_error_for_dlq_redrive():
    _patch_ddb(_FakeDDB(raise_other=True))
    raised = False
    try:
        sf.lambda_handler(_sns_event(_scoring_message()), None)
    except RuntimeError:
        raised = True
    assert raised, "a real write failure must raise so Lambda async retry/DLQ re-drives"


def test_handler_direct_invoke_bare_message():
    fake = _FakeDDB()
    _patch_ddb(fake)
    out = sf.lambda_handler(_scoring_message(), None)
    assert out["processed"] == 1 and out["results"][0]["outcome"] == "scored"


def test_handler_health_probe():
    out = sf.lambda_handler({"action": "health"}, None)
    assert out["ok"] is True and out["service"] == "scoring_service"


def test_handler_undecodable_record_skipped():
    fake = _FakeDDB()
    _patch_ddb(fake)
    out = sf.lambda_handler({"Records": [{"Sns": {"Message": "{not-json"}}]}, None)
    assert out["errors"] == 0 and out["results"][0]["outcome"] == "skipped"


if __name__ == "__main__":
    fns = [g for n, g in sorted(globals().items()) if n.startswith("test_") and callable(g)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"ERROR {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
