"""Pure helper module for ENC-FTR-098 MENTIONS edge auto-extraction.

ENC-TSK-G34 / DOC-59D2295AA7FD §7.2.2.

Three pure functions consumed by:
  * graph_sync._reconcile_mentions_edges (ENC-TSK-G35) — live emission path
  * one-shot corpus backfill Lambda (ENC-TSK-G42)
  * mentions_drift_audit in devops-deploy-parity-validator (ENC-TSK-G43)

Functions are side-effect-free so the live, backfill, and audit paths are
guaranteed to extract identical token sets from the same input text.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, Set, Tuple

# Triple-backtick fenced code blocks, optionally with a language tag on the
# opening line. Markdown does not nest fences; the first matching closing run
# terminates the block, so a non-greedy match is correct.
_CODE_FENCE_RE = re.compile(r"```.*?```", re.DOTALL)

# Default ID-prefix alphabet. Mirrors ID_PREFIX_TO_LABEL in
# graph_sync/lambda_function.py so _infer_label_from_id can resolve every
# token this module emits. DOC-* and comp-* are handled out-of-band by
# extract_id_tokens because their structure differs from ENC-<TYPE>-<id>.
DEFAULT_ID_ALPHABET = (
    "TSK", "ISS", "FTR", "LSN", "PLN", "GEN", "DPL",
)

# Prose-field allowlist per record_type. Mirrors dictionary entity
# graph_sync.mentions_extraction (Unit 1, ENC-TSK-G33). Owned here so the
# live reconciler (graph_sync._reconcile_mentions_edges) and the daily
# drift audit (deploy_parity_validator._run_mentions_drift_audit) share
# one definition; drift between them would silently emit false-positive
# ENC-ISS records. Document subtype-specific structured fields are
# excluded — those project as typed edges via the document branch in
# graph_sync, so re-extracting them as MENTIONS would double-count.
MENTIONS_PROSE_FIELDS: Dict[str, Tuple[str, ...]] = {
    "task":       ("title", "description", "intent"),
    "issue":      ("title", "description", "hypothesis", "technical_notes",
                   "location_hint"),
    "feature":    ("title", "description", "user_story"),
    "plan":       ("title", "description", "intent"),
    "lesson":     ("title", "description"),
    "generation": ("title", "description", "architectural_thesis"),
    "document":   ("title", "description", "content"),
}

# Pre-compiled extractor for the default alphabet (the hot path).
# Custom alphabets re-build the regex inside extract_id_tokens.
_DEFAULT_TOKEN_RE = re.compile(
    r"\b("
    r"ENC-(?:" + "|".join(DEFAULT_ID_ALPHABET) + r")-[A-Za-z0-9]{3,4}"
    r"|DOC-[A-Fa-f0-9]{12}"
    r"|comp-[a-z0-9-]+"
    r")\b"
)


def strip_code_fences(text: str) -> str:
    """Return ``text`` with all triple-backtick fenced code blocks removed.

    IDs inside fenced code blocks are excluded from MENTIONS extraction
    because they typically represent example payloads, not real references.
    Inline single-backtick spans are NOT stripped — IDs in `inline code`
    stay extractable since they are usually intentional named references.
    """
    if not text:
        return ""
    return _CODE_FENCE_RE.sub("", text)


def _build_token_regex(alphabet: Iterable[str]) -> "re.Pattern[str]":
    return re.compile(
        r"\b("
        r"ENC-(?:" + "|".join(alphabet) + r")-[A-Za-z0-9]{3,4}"
        r"|DOC-[A-Fa-f0-9]{12}"
        r"|comp-[a-z0-9-]+"
        r")\b"
    )


def extract_id_tokens(
    text: str,
    alphabet: Iterable[str] = DEFAULT_ID_ALPHABET,
) -> Set[str]:
    """Return the set of governed-prefix ID tokens present in ``text``.

    Callers should ``strip_code_fences(text)`` first when fenced-block IDs
    must be excluded — this function does NOT strip fences itself, so the
    same alphabet/regex can be reused over already-cleaned input by the
    backfill and drift-audit paths.

    The default alphabet covers the live corpus (ENC-TSK / ISS / FTR / LSN /
    PLN / GEN / DPL plus DOC-* documents and comp-* components). Pass a
    different ``alphabet`` to support future record types without touching
    this module.
    """
    if not text:
        return set()
    alphabet_tuple = tuple(alphabet)
    if alphabet_tuple == DEFAULT_ID_ALPHABET:
        return set(_DEFAULT_TOKEN_RE.findall(text))
    return set(_build_token_regex(alphabet_tuple).findall(text))


def stamp_provenance(
    edge_payload: Dict[str, Any],
    source_field: str,
    source: str = "auto_mention",
) -> Dict[str, Any]:
    """Return a copy of ``edge_payload`` with MENTIONS provenance attached.

    Always returns a NEW dict so callers can build per-edge property bags
    without mutating shared input. ``source`` defaults to ``auto_mention``
    matching the value graph_sync writes on every Cypher MERGE; the field
    is parameterised so the backfill path can stamp ``backfill`` instead.
    """
    out: Dict[str, Any] = dict(edge_payload) if edge_payload else {}
    out["source"] = source
    out["extracted_from_field"] = source_field
    return out
