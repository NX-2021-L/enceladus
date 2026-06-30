"""Convergence Surface canonicalization (ENC-FTR-086 D2 / ENC-TSK-I82).

Pure, dependency-free canonicalization of open-taxonomy attribute values so that
near-synonyms collapse to a single canonical key before they are counted. The
transform is versioned: any change to the algorithm MUST bump ``CANON_VERSION``
so the increment path and the (later) read path can migrate in lockstep and so
the deduplication identity for an observation changes deterministically.

D2 contract:
    Unicode NFC + lowercase + whitespace/underscore -> hyphen + strip
    non-alphanumerics (keep hyphens) + collapse/trim hyphens.

Examples (ENC-TSK-I82 AC-3):
    "Implementation"   -> "implementation"
    " implementation " -> "implementation"
    "IMPLEMENTATION"   -> "implementation"
"""

from __future__ import annotations

import re
import unicodedata
from typing import List

# Bump on ANY change to canonicalize(); it is part of the observation dedup key.
CANON_VERSION = 1

# Open-taxonomy fields whose submitted values are counted by the Convergence
# Surface. Scalar fields contribute a single value; list-typed fields (e.g.
# tags) contribute one observation per element. category/priority are bounded
# enums today but are explicitly in scope for ENC-TSK-I82 telemetry.
OPEN_TAXONOMY_FIELDS = ("category", "priority", "tags")

_WS_OR_UNDERSCORE = re.compile(r"[\s_]+")
_NON_ALNUM_HYPHEN = re.compile(r"[^a-z0-9-]+")
_MULTI_HYPHEN = re.compile(r"-{2,}")


def canonicalize(raw: object) -> str:
    """Return the canonical form of a raw attribute value.

    Returns an empty string for values that canonicalize to nothing (e.g. None,
    whitespace-only, or punctuation-only input); callers skip empty results.
    """
    if raw is None:
        return ""
    text = unicodedata.normalize("NFC", str(raw))
    text = text.strip().lower()
    text = _WS_OR_UNDERSCORE.sub("-", text)
    text = _NON_ALNUM_HYPHEN.sub("", text)
    text = _MULTI_HYPHEN.sub("-", text).strip("-")
    return text


def canonical_values(raw: object) -> List[str]:
    """Canonicalize a scalar or list-typed raw value into distinct canonical keys.

    A list/tuple/set input fans out to one canonical value per element. Empty
    canonical results are dropped and duplicates within a single record are
    de-duplicated (a record mentioning the same tag twice counts once).
    """
    if isinstance(raw, (list, tuple, set)):
        items = list(raw)
    else:
        items = [raw]

    seen: List[str] = []
    for item in items:
        canon = canonicalize(item)
        if canon and canon not in seen:
            seen.append(canon)
    return seen
