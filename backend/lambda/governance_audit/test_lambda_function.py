import json

import lambda_function as mod


def _stream_record(event_name: str, image: dict) -> dict:
    return {
        "eventName": event_name,
        "eventSource": "aws:dynamodb",
        "dynamodb": {
            "NewImage": image,
        },
    }


def _attr_map(values: dict) -> dict:
    out = {}
    for key, value in values.items():
        if isinstance(value, dict):
            out[key] = {"M": _attr_map(value)}
        elif isinstance(value, bool):
            out[key] = {"BOOL": value}
        elif value is None:
            out[key] = {"NULL": True}
        else:
            out[key] = {"S": str(value)}
    return out


def test_missing_write_source_detected(monkeypatch):
    seen = []
    monkeypatch.setattr(mod, "_publish_alert", lambda anomaly, image, event_name: seen.append((anomaly, image, event_name)))

    event = {
        "Records": [
            _stream_record(
                "INSERT",
                _attr_map(
                    {
                        "project_id": "enceladus",
                        "record_id": "task#ENC-TSK-454-TEST-A",
                        "item_id": "ENC-TSK-454-TEST-A",
                        "record_type": "task",
                        "status": "open",
                    }
                ),
            )
        ]
    }

    result = mod.handler(event, None)

    assert result == {"processed": 1, "clean": 0, "anomalies": 1}
    assert len(seen) == 1
    assert seen[0][0]["type"] == "MISSING_WRITE_SOURCE"


def test_known_channel_is_clean(monkeypatch):
    monkeypatch.setattr(mod, "_publish_alert", lambda anomaly, image, event_name: None)

    event = {
        "Records": [
            _stream_record(
                "MODIFY",
                _attr_map(
                    {
                        "project_id": "enceladus",
                        "record_id": "task#ENC-TSK-454-TEST-B",
                        "item_id": "ENC-TSK-454-TEST-B",
                        "record_type": "task",
                        "status": "open",
                        "write_source": {"channel": "tracker_cli"},
                    }
                ),
            )
        ]
    }

    result = mod.handler(event, None)

    assert result == {"processed": 1, "clean": 1, "anomalies": 0}


def test_sqs_wrapped_unknown_channel_detected(monkeypatch):
    seen = []
    monkeypatch.setattr(mod, "_publish_alert", lambda anomaly, image, event_name: seen.append((anomaly, image, event_name)))

    payload = {
        "eventName": "MODIFY",
        "eventSource": "aws:dynamodb",
        "dynamodb": {
            "NewImage": _attr_map(
                {
                    "project_id": "enceladus",
                    "record_id": "task#ENC-TSK-454-TEST-C",
                    "item_id": "ENC-TSK-454-TEST-C",
                    "record_type": "task",
                    "status": "open",
                    "write_source": {"channel": "unknown_cli"},
                }
            )
        },
    }

    event = {
        "Records": [
            {
                "eventSource": "aws:sqs",
                "body": json.dumps(payload),
            }
        ]
    }

    result = mod.handler(event, None)

    assert result == {"processed": 1, "clean": 0, "anomalies": 1}
    assert len(seen) == 1
    assert seen[0][0]["type"] == "UNKNOWN_CHANNEL"
