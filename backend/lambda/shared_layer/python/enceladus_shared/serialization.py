"""enceladus_shared.serialization — DynamoDB serialization/deserialization.

Provides TypeSerializer/TypeDeserializer wrappers and timestamp helpers
used across multiple Enceladus Lambdas.

Part of ENC-TSK-525: Extract shared Lambda layer.
"""

from __future__ import annotations

import datetime as dt
import time
from decimal import Decimal
from typing import Any, Dict

from boto3.dynamodb.types import TypeDeserializer, TypeSerializer

_SER = TypeSerializer()
_DESER = TypeDeserializer()


def _serialize(value: Any) -> Any:
    """Serialize a Python value for DynamoDB."""
    if isinstance(value, float):
        value = Decimal(str(value))
    return _SER.serialize(value)


def _deserialize(item: Dict[str, Any]) -> Dict[str, Any]:
    """Deserialize a DynamoDB item to a plain Python dict."""
    out: Dict[str, Any] = {}
    for k, v in item.items():
        val = _DESER.deserialize(v)
        if isinstance(val, Decimal):
            val = int(val) if val == int(val) else float(val)
        out[k] = val
    return out


def _now_z() -> str:
    """Current UTC timestamp in ISO 8601 format with Z suffix."""
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _unix_now() -> int:
    """Current Unix epoch as integer."""
    return int(time.time())
