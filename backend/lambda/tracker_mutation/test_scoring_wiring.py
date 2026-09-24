"""Tests for the ENC-TSK-H47 Scoring Service wiring in tracker_mutation.

Focus: the BEST-EFFORT publish invariant (a failed/unconfigured SNS publish never raises — the
lesson DynamoDB write is the source of truth and is never blocked), the message envelope shape, and
the independently-toggleable feature flag. Runs standalone or under pytest.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lambda_function as lf  # noqa: E402

GOOD_PILLARS = {"efficiency": 0.8, "human_protection": 0.7, "intention": 0.6, "alignment": 0.75}


class _FakeSns:
    def __init__(self, *, raise_exc=None):
        self._raise_exc = raise_exc
        self.calls = []

    def publish(self, **kwargs):
        self.calls.append(kwargs)
        if self._raise_exc:
            raise self._raise_exc
        return {"MessageId": "m-1"}


def _patch_sns(fake):
    lf._sns_client = fake
    lf._get_sns = lambda: fake  # type: ignore


def test_unconfigured_topic_is_best_effort_false():
    lf.LESSON_SCORING_TOPIC_ARN = ""
    assert lf._publish_lesson_scoring_request("enceladus", "lesson#ENC-LSN-1", "ENC-LSN-1", GOOD_PILLARS) is False


def test_publish_exception_is_swallowed():
    lf.LESSON_SCORING_TOPIC_ARN = "arn:aws:sns:us-west-2:1:enceladus-lesson-scoring"
    _patch_sns(_FakeSns(raise_exc=RuntimeError("sns down")))
    # Must NOT raise — a notification side-channel failure can never block the lesson write.
    assert lf._publish_lesson_scoring_request("enceladus", "lesson#ENC-LSN-1", "ENC-LSN-1", GOOD_PILLARS) is False


def test_publish_envelope_shape():
    lf.LESSON_SCORING_TOPIC_ARN = "arn:aws:sns:us-west-2:1:enceladus-lesson-scoring"
    fake = _FakeSns()
    _patch_sns(fake)
    ok = lf._publish_lesson_scoring_request("enceladus", "lesson#ENC-LSN-9", "ENC-LSN-9", GOOD_PILLARS)
    assert ok is True and fake.calls
    call = fake.calls[0]
    assert call["TopicArn"] == lf.LESSON_SCORING_TOPIC_ARN
    msg = json.loads(call["Message"])
    assert msg["event_type"] == "lesson.scoring.requested"
    assert msg["project_id"] == "enceladus"
    assert msg["record_id"] == "lesson#ENC-LSN-9"
    assert msg["item_id"] == "ENC-LSN-9"
    assert msg["pillar_scores"] == GOOD_PILLARS
    assert "schema_version" in msg


def test_flag_independently_toggleable():
    # No AppConfig + no env var -> resolves without error (default posture).
    os.environ.pop("ENABLE_SCORING_SERVICE", None)
    assert lf._scoring_service_enabled() in (False, True)
    os.environ["ENABLE_SCORING_SERVICE"] = "true"
    assert lf._scoring_service_enabled() is True
    os.environ["ENABLE_SCORING_SERVICE"] = "false"
    assert lf._scoring_service_enabled() is False
    os.environ.pop("ENABLE_SCORING_SERVICE", None)


def test_scoring_flag_independent_of_lifecycle_flag():
    # H47 must be toggleable without affecting the H46 lifecycle flag (and vice versa) — independent
    # env fallbacks prove the AppConfig keys are distinct.
    os.environ["ENABLE_SCORING_SERVICE"] = "true"
    os.environ["ENABLE_LIFECYCLE_SERVICE"] = "false"
    assert lf._scoring_service_enabled() is True
    assert lf._lifecycle_service_enabled() is False
    os.environ.pop("ENABLE_SCORING_SERVICE", None)
    os.environ.pop("ENABLE_LIFECYCLE_SERVICE", None)


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
