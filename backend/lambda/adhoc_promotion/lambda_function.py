"""Ad-hoc promotion transform -- the one gate out of ``hive.adhoc``.

BRD B5-R2 (DVP-TSK-661). Invoked by **io**, from Superset (DVP-TSK-688) or the
io-graph PWA (DVP-TSK-689). Never by a schedule, never by an agent.

Two actions:

``plan``
    Read the quarantined table and return the pre-populated type map
    (DVP-TSK-685). Read-only. This is what the promotion screen loads.

``promote``
    Apply the type map io reviewed, all-or-nothing (DVP-TSK-686), and write the
    result through the B2-R2 shared registration library (DVP-TSK-687).

Event shape::

    {
      "action": "plan" | "promote",
      "source_table":   "quarterly_spend",       # in hive.adhoc
      "target_project": "devops",
      "target_table":   "quarterly_spend",       # optional, defaults to source
      "type_map":       {"amount": "decimal(12,2)", ...},   # promote only
      "actor":          {"kind": "human", "id": "io", "surface": "superset"}
    }

The ``actor`` block is not decoration. DOC-FF843F9F0E2C reserves promotion for a
human against a fixed contract -- "no agent session initiates or completes a
promotion autonomously" -- and this handler enforces that rather than trusting
callers to honour it. An invocation that presents an agent session id, or that
declares any actor kind other than ``human``, is refused before the source table
is read. That refusal is the D-4 no-agent constraint made executable: an agent
that tried to promote a table would get a 403 out of this function, not a
governed table.

A failed promotion returns HTTP 422 with the offending rows. It is a normal,
expected outcome -- the gate doing its job -- so it is returned rather than
raised. A promotion that partially succeeded is not representable in this
handler's return type, which is the intended shape of the contract.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, Mapping, Optional

from promotion_coerce import PromotionCoercionError
from promotion_run import PromotionRefused, plan_promotion, promote
from promotion_source import ADHOC_DATABASE, PromotionSourceError

LOGGER = logging.getLogger()
LOGGER.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

#: Agent session identifiers. Their presence anywhere in the actor block is
#: sufficient to refuse: an agent that supplies its session id is honest, and an
#: agent that hides it still fails the ``kind == "human"`` check below.
_AGENT_SESSION_RE = re.compile(r"\bENC-SES-[0-9A-Za-z]+\b")

_HUMAN = "human"


class PromotionForbidden(Exception):
    """An agent tried to promote. D-4 says no."""


def _require_human_actor(event: Mapping[str, Any]) -> Dict[str, str]:
    actor = event.get("actor") or {}
    if not isinstance(actor, Mapping):
        raise PromotionForbidden("actor must be an object naming who is promoting")

    kind = str(actor.get("kind") or "").strip().lower()
    identity = str(actor.get("id") or "").strip()
    surface = str(actor.get("surface") or "").strip().lower()

    blob = json.dumps({"actor": dict(actor)}, default=str)
    if _AGENT_SESSION_RE.search(blob):
        raise PromotionForbidden(
            "this invocation carries an agent session id. Promotion is a user action "
            "against a fixed contract (DOC-FF843F9F0E2C, decision D-4): no agent session "
            "initiates or completes a promotion. Have io trigger it from Superset or the "
            "io-graph PWA."
        )
    if kind != _HUMAN:
        raise PromotionForbidden(
            "actor.kind is %r; promotion requires %r. The type declaration and the "
            "ownership declaration are judgements reserved for io -- an agent deciding a "
            "value is 'close enough' to coerce is the exact failure this gate prevents."
            % (kind or "(absent)", _HUMAN)
        )
    if not identity:
        raise PromotionForbidden("actor.id is required: promotion is an attributable act")
    if surface not in ("superset", "pwa", "io-graph", ""):
        raise PromotionForbidden(
            "actor.surface %r is not a sanctioned promotion surface (superset, pwa)" % surface
        )
    return {"kind": kind, "id": identity, "surface": surface or "unspecified"}


def _clients():
    import boto3
    from botocore.config import Config

    config = Config(retries={"max_attempts": 5, "mode": "standard"})
    region = os.environ.get("AWS_REGION", "us-west-2")
    return (
        boto3.client("glue", region_name=region, config=config),
        boto3.client("s3", region_name=region, config=config),
    )


def _response(status: int, body: Mapping[str, Any]) -> Dict[str, Any]:
    return {"statusCode": status, "body": dict(body)}


def lambda_handler(event, context):  # noqa: ANN001 - AWS signature
    event = event or {}
    action = str(event.get("action") or "plan").strip().lower()
    source_table = str(event.get("source_table") or "").strip()
    target_project = str(event.get("target_project") or "").strip()
    target_table = (event.get("target_table") or "").strip() or None
    database = str(event.get("database") or ADHOC_DATABASE).strip()

    try:
        actor = _require_human_actor(event)
    except PromotionForbidden as exc:
        LOGGER.warning("[ERROR] promotion refused: %s", exc)
        return _response(403, {"promoted": False, "error": str(exc)})

    if not source_table:
        return _response(400, {"promoted": False, "error": "source_table is required"})
    if not target_project:
        return _response(400, {"promoted": False, "error": "target_project is required"})

    glue_client, s3_client = _clients()

    try:
        if action == "plan":
            plan = plan_promotion(
                glue_client,
                s3_client,
                source_table=source_table,
                target_project=target_project,
                target_table=target_table,
                database=database,
            )
            LOGGER.info(
                "[SUCCESS] promotion plan for %s by %s/%s: %s",
                plan.source_identifier,
                actor["surface"],
                actor["id"],
                plan.review_summary,
            )
            return _response(200, plan.as_dict())

        if action == "promote":
            result = promote(
                glue_client,
                s3_client,
                source_table=source_table,
                target_project=target_project,
                type_map=event.get("type_map") or {},
                target_table=target_table,
                database=database,
                freshness_value=(event.get("freshness_value") or None),
            )
            LOGGER.info(
                "[SUCCESS] %s promoted %s -> %s (%d rows) via %s",
                actor["id"],
                result.source_identifier,
                result.target_identifier,
                result.row_count,
                actor["surface"],
            )
            return _response(200, result.as_dict())

        return _response(400, {"promoted": False, "error": "unknown action %r" % action})

    except PromotionCoercionError as exc:
        # The gate refusing a table is expected behaviour, not a fault. Nothing
        # was written; io gets every offending row in one round trip.
        LOGGER.info("[INFO] promotion refused %d bad value(s) in %s", exc.total, exc.table)
        return _response(422, exc.as_dict())
    except (PromotionRefused, PromotionSourceError) as exc:
        LOGGER.warning("[ERROR] promotion rejected: %s", exc)
        return _response(400, {"promoted": False, "error": str(exc)})
    except Exception:
        LOGGER.exception("[ERROR] promotion failed unexpectedly")
        raise
