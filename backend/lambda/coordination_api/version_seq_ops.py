"""version_seq_ops.py -- coordination_api's access to the sequencing rule.

ENC-TSK-S94 / ENC-ISS-908. coordination_api set tracker status with a plain
UpdateItem that allocated no version_seq, so every status it wrote -- closes
included -- was invisible to the Query on version-seq-index behind
``GET /api/v1/feed/delta``. A client that missed the push event therefore could
not heal that record until its next sequenced write. This module is the lambda's
single access point to the one sequencing rule.

The import is layered on purpose. ``SharedLayerArn`` is a PINNED default
(``enceladus-shared:15`` in infrastructure/cloudformation/02-compute.yaml) and
that pin does not carry ``sequenced_governed_write_parts`` yet. Unguarded imports
of a symbol a pinned layer lacks are exactly what produced the ``:7`` and ``:10``
``Runtime.ImportModuleError`` incidents recorded on that parameter, so:

  1. prefer the shared rule when the layer carries it;
  2. otherwise compose it from ``allocate_version_seq`` +
     ``version_seq_update_clause``, which layer ``:15`` does carry (verified
     byte-identical to the repository source);
  3. otherwise degrade to stamping ``write_kind`` alone -- today's behaviour --
     rather than bricking the Lambda at module load.

``version_seq`` is a MONOTONE CURSOR, never a counter: allocation is its own
UpdateItem and runs before this writer's conditional write, so a
ConditionalCheckFailed burns a number and leaves a gap. Gaps are harmless to a
``version_seq > :cursor`` Query; no consumer may derive a count or a rate from it.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Tuple

# No local-module dependency on purpose: both _set_tracker_status copies
# (lambda_function.py and tracker_ops.py) import this module, and the monolith
# does not import config/serialization at all.
logger = logging.getLogger(__name__)

SEQUENCING_SOURCE = "unavailable"

try:  # 1. the one rule, once the pinned layer carries it
    from enceladus_shared.version_seq import (
        sequenced_governed_write_parts as _rule,
    )

    SEQUENCING_SOURCE = "shared_layer_rule"
except ImportError:
    try:  # 2. compose from the primitives layer :15 does carry
        from enceladus_shared.version_seq import (
            allocate_version_seq,
            version_seq_update_clause,
        )

        def _rule(ddb: Any, table_name: str):
            seq = allocate_version_seq(ddb, table_name)
            expr, values = version_seq_update_clause(seq)
            values = dict(values)
            values[":vsq_wkind"] = {"S": "governed"}
            return expr + ", write_kind = :vsq_wkind", values, seq

        SEQUENCING_SOURCE = "shared_layer_primitives"
    except ImportError:  # 3. degrade, never brick
        _rule = None


def sequenced_write_parts(
    ddb: Any, table_name: str
) -> Tuple[str, Dict[str, Dict[str, str]]]:
    """Return an appendable SET fragment + values that sequence a governed write.

    The fragment always begins with ``", "`` and always assigns ``write_kind``,
    so a caller must NOT assign ``write_kind`` itself. Append it inside the
    ``SET`` clause and BEFORE any ``ADD`` clause -- a ``SET`` assignment placed
    after ``" ADD ..."`` is invalid UpdateExpression syntax (ENC-TSK-P49).

    When no sequencing rule is reachable the fragment still marks the write
    governed, so the DynamoDB-stream filters keep it, and the write is simply
    unsequenced as it is today.
    """
    if _rule is None:
        logger.warning(
            "coordination_api: no version_seq rule reachable (%s); "
            "status write will be governed but UNSEQUENCED (ENC-ISS-908)",
            SEQUENCING_SOURCE,
        )
        return ", write_kind = :vsq_wkind", {":vsq_wkind": {"S": "governed"}}
    try:
        expr, values, _seq = _rule(ddb, table_name)
    except Exception:  # noqa: BLE001
        # Fail OPEN on telemetry, never on governance: allocating a sequence
        # number is a separate UpdateItem on the version_seq counter, and its
        # failure must not take down the governed status write that follows.
        logger.exception(
            "coordination_api: version_seq allocation failed (%s); status write "
            "will be governed but UNSEQUENCED (ENC-ISS-908)",
            SEQUENCING_SOURCE,
        )
        return ", write_kind = :vsq_wkind", {":vsq_wkind": {"S": "governed"}}
    return expr, values


def closed_count_add_parts(
    record_type: str, new_status: str
) -> Tuple[str, Dict[str, Dict[str, str]]]:
    """Return the ``ADD`` fragment that counts a task close, or ``("", {})``.

    ENC-TSK-F41 / ENC-FTR-076: ``closed_count`` is the gate evidence for
    ``component.advance`` approved -> designed, and this writer never added it.
    Only tasks carry the attribute, so other record types get nothing.
    """
    if str(record_type or "").strip().lower() != "task":
        return "", {}
    if str(new_status or "").strip().lower() != "closed":
        return "", {}
    return " ADD closed_count :vsq_cc_one", {":vsq_cc_one": {"N": "1"}}
