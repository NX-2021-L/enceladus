"""Pre-populate the promotion type map from the quarantined table's own data.

DVP-TSK-685. BRD B5-R2 step 1, and the direct mitigation for risk R-6.

R-6, stated plainly: moving the type-declaration burden from the upload dialog to
the promotion boundary RELOCATES that burden, it does not eliminate it. If
promotion asks io to author a schema from a blank form, promotion is *more*
unpleasant than the dialog it replaced -- and io will rationally keep charting
straight off the quarantined table forever. The gate would exist, be correct, and
never be used. That failure is invisible in every test that only checks the gate
works when invoked.

So the design constraint is not "let io declare types". It is:

    **Promotion must be a REVIEW, not an authoring exercise.**

Every column arrives with a proposed SQL type already filled in, the reason it
was proposed, and the sensible alternatives one click away. io corrects the two
columns the platform guessed conservatively about and presses go. Nothing is ever
blank.

Three properties keep the proposals worth trusting:

1. **Evidence, not vibes.** An upgrade is proposed only when EVERY non-null
   sampled value supports it. One counterexample withdraws the upgrade. A
   proposal that failed coercion two screens later would teach io to distrust
   the whole map, which is the R-6 failure by another road.
2. **Conservative by default.** When the evidence is ambiguous the inferred type
   is carried forward unchanged and the upgrade appears in ``alternatives``. The
   platform never spends io's trust on a guess it did not have to make.
3. **Lossy upgrades are refused, loudly.** The leading-zero zip code is the
   canonical case: ``int("01234")`` does not raise, it silently returns 1234.
   A type map that proposed ``int`` there would destroy data through a coercion
   that reports success. Such a type is not merely left unproposed -- it is
   removed from ``alternatives`` and the column carries a warning.

This module reads. It proposes. It decides nothing: the returned plan is a draft
for io to accept or edit, and ``promotion_run`` will not act on a type map that
io did not send back (DOC-FF843F9F0E2C, the no-agent constraint).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date as _date
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:  # deployed: vendored flat by .build_extras
    from enceladus_shared.warehouse_registration import (
        ALLOWED_TYPE_PATTERN,
        DEFAULT_FRESHNESS_COLUMN,
        FRESHNESS_COLUMN_TYPE,
        RESERVED_COLUMN_NAMES,
        COLUMN_NAME_PATTERN,
    )
except ImportError:  # pragma: no cover - import shim, see .build_extras
    from warehouse_registration import (  # type: ignore[no-redef]
        ALLOWED_TYPE_PATTERN,
        DEFAULT_FRESHNESS_COLUMN,
        FRESHNESS_COLUMN_TYPE,
        RESERVED_COLUMN_NAMES,
        COLUMN_NAME_PATTERN,
    )

__all__ = [
    "PLAN_SAMPLE_LIMIT",
    "ColumnProposal",
    "PromotionPlan",
    "build_plan",
    "propose_column",
    "looks_like_currency_name",
]

#: How many rows the planning pass reads. Enough to make an upgrade proposal
#: evidential rather than decorative, small enough that opening the promotion
#: screen is instant. Promotion itself re-reads every row -- the sample decides
#: what to PROPOSE, never what is safe to WRITE.
PLAN_SAMPLE_LIMIT = 5000

# ---------------------------------------------------------------------------
# Shape detectors. Every one of these answers "does the evidence support this
# type", never "is this type plausible".
# ---------------------------------------------------------------------------

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$"
)
_INTEGER_RE = re.compile(r"^[+-]?\d+$")
_DECIMAL_RE = re.compile(r"^[+-]?\d+(\.\d+)?$")
_LEADING_ZERO_RE = re.compile(r"^0\d+$")
_BOOLEAN_TOKENS = {"true", "false"}

#: Column-name tokens that make a floating-point column *currency*. Name-based
#: on purpose: value shape cannot distinguish money from a rating or a ratio,
#: and "0.5 has one decimal place" is not evidence of anything. The acceptance
#: criterion is "DOUBLE currency-like columns proposed as DECIMAL", and
#: currency-like is a fact about what the column MEANS.
_CURRENCY_TOKENS = (
    "amount", "amt", "price", "cost", "total", "subtotal", "balance", "revenue",
    "fee", "salary", "wage", "payment", "paid", "charge", "spend", "budget",
    "income", "expense", "tax", "discount", "refund", "premium", "deposit",
    "withdrawal", "credit", "debit", "invoice", "usd", "eur", "gbp", "cash",
)

#: Column-name tokens whose values are identifiers that merely look numeric.
#: Used only to sharpen a warning message -- the leading-zero evidence is what
#: actually withdraws the integer proposal, not the name.
_IDENTIFIER_TOKENS = ("zip", "postal", "postcode", "fips", "ssn", "phone", "code", "id")

#: The widest DECIMAL Parquet/Trino carry through this path, and the floor scale
#: money is written at.
_MAX_DECIMAL_PRECISION = 38
_MONEY_SCALE = 2


def _text(value: Any) -> str:
    return value if isinstance(value, str) else str(value)


def looks_like_currency_name(column: str) -> bool:
    """True when the column name says this floating-point number is money."""
    lowered = column.lower()
    return any(token in lowered for token in _CURRENCY_TOKENS)


def _looks_like_identifier_name(column: str) -> bool:
    lowered = column.lower()
    return any(token in lowered for token in _IDENTIFIER_TOKENS)


def _all_match(values: Sequence[Any], predicate) -> bool:
    """True when there is evidence AND every piece of it agrees.

    An empty column proves nothing, so it never earns an upgrade. That is the
    conservative branch on purpose: proposing DATE for a column of 4,000 NULLs
    would be the platform inventing a fact it does not have.
    """
    seen = False
    for value in values:
        seen = True
        if not predicate(value):
            return False
    return seen


def _parses_as_date(value: Any) -> bool:
    if isinstance(value, _date) and not isinstance(value, datetime):
        return True
    text = _text(value).strip()
    if not _DATE_RE.match(text):
        return False
    try:
        _date.fromisoformat(text)
    except ValueError:
        return False  # 2026-13-45 matches the shape and is not a date
    return True


def _parses_as_timestamp(value: Any) -> bool:
    if isinstance(value, datetime):
        return True
    text = _text(value).strip()
    if not _TIMESTAMP_RE.match(text):
        return False
    try:
        datetime.fromisoformat(text.replace("Z", "+00:00").replace(" ", "T"))
    except ValueError:
        return False
    return True


def _is_integer_text(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    return bool(_INTEGER_RE.match(_text(value).strip()))


def _is_boolean_text(value: Any) -> bool:
    if isinstance(value, bool):
        return True
    return _text(value).strip().lower() in _BOOLEAN_TOKENS


def _has_significant_leading_zero(value: Any) -> bool:
    """``"01234"`` yes, ``"0"`` no, ``"0.5"`` no.

    The single most important detector here. A string of digits with a leading
    zero is an identifier whose zero is DATA. Coercing it to an integer does not
    fail -- it succeeds and quietly deletes the zero, producing a governed table
    that is wrong in a way no error log will ever mention.
    """
    return bool(_LEADING_ZERO_RE.match(_text(value).strip()))


def _decimal_shape(values: Sequence[Any]) -> Optional[Tuple[int, int]]:
    """``(precision, scale)`` wide enough for every sampled value, or None."""
    max_int_digits = 1
    max_scale = 0
    seen = False
    for value in values:
        text = _text(value).strip()
        if not _DECIMAL_RE.match(text):
            try:
                decimal_value = Decimal(str(value))
            except (InvalidOperation, ValueError, TypeError):
                return None
            text = format(decimal_value, "f")
            if not _DECIMAL_RE.match(text):
                return None
        seen = True
        digits = text.lstrip("+-")
        whole, _, fraction = digits.partition(".")
        max_int_digits = max(max_int_digits, len(whole.lstrip("0")) or 1)
        max_scale = max(max_scale, len(fraction))
    if not seen:
        return None
    scale = min(max(max_scale, _MONEY_SCALE), 10)
    precision = min(max_int_digits + scale + 2, _MAX_DECIMAL_PRECISION)
    if precision <= scale:
        precision = min(scale + 1, _MAX_DECIMAL_PRECISION)
    return precision, scale


def _normalize_inferred(sql_type: str) -> str:
    """Fold the catalog's spelling into a type the warehouse contract accepts.

    Superset's upload path writes Hive spellings that the contract's declared-type
    grammar does not list verbatim. Folding here means the FALLBACK of every
    proposal is already a legal declared type, so a plan io accepts untouched is
    always promotable -- a pre-populated map with an illegal default in it would
    fail at the gate and teach exactly the R-6 lesson we are avoiding.
    """
    normalized = (sql_type or "").strip().lower()
    aliases = {
        "": "string",
        "text": "string",
        "str": "string",
        "object": "string",
        "bool": "boolean",
        "int64": "bigint",
        "long": "bigint",
        "int32": "int",
        "short": "smallint",
        "byte": "tinyint",
        "float64": "double",
        "float32": "float",
        "decimal": "decimal(%d,%d)" % (18, _MONEY_SCALE),
        "datetime": "timestamp",
        "datetime64[ns]": "timestamp",
    }
    normalized = aliases.get(normalized, normalized)
    if ALLOWED_TYPE_PATTERN.match(normalized):
        return normalized
    return "string"


# ---------------------------------------------------------------------------
# Proposal
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ColumnProposal:
    """One row of the pre-populated type map io reviews.

    ``proposed_type`` is never empty. That is the entire R-6 mitigation in one
    invariant: there is no blank field anywhere on the promotion screen.
    """

    name: str
    inferred_type: str
    proposed_type: str
    reason: str
    upgraded: bool = False
    alternatives: Tuple[str, ...] = ()
    warning: str = ""
    system_managed: bool = False
    sample_values: Tuple[str, ...] = ()

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "inferred_type": self.inferred_type,
            "proposed_type": self.proposed_type,
            "reason": self.reason,
            "upgraded": self.upgraded,
            "alternatives": list(self.alternatives),
            "warning": self.warning,
            "system_managed": self.system_managed,
            "sample_values": list(self.sample_values),
        }


def _samples(values: Sequence[Any], count: int = 3) -> Tuple[str, ...]:
    """A few real values, shown beside the proposal so review needs no SQL Lab."""
    out: List[str] = []
    for value in values:
        text = _text(value)
        out.append(text if len(text) <= 40 else text[:37] + "...")
        if len(out) >= count:
            break
    return tuple(out)


def propose_column(name: str, inferred_type: str, values: Sequence[Any]) -> ColumnProposal:
    """Propose the SQL type this column should have in the governed warehouse."""
    inferred = _normalize_inferred(inferred_type)
    observed = [value for value in values if value is not None]
    samples = _samples(observed)
    base = dict(name=name, inferred_type=inferred, sample_values=samples)

    is_texty = inferred == "string" or inferred.startswith("varchar(") or inferred.startswith("char(")
    is_floaty = inferred in ("double", "float", "real")
    is_inty = inferred in ("tinyint", "smallint", "int", "integer", "bigint")

    # -- 1. Leading zeros outrank every other signal on a text column. --------
    # Checked first because the alternatives it removes are ones later branches
    # would happily offer.
    if is_texty and any(_has_significant_leading_zero(value) for value in observed):
        hint = (
            "an identifier, not a quantity"
            if _looks_like_identifier_name(name)
            else "an identifier"
        )
        return ColumnProposal(
            proposed_type="string",
            reason=(
                "kept as text: values carry leading zeros, so this is %s. Note that an "
                "integer type would NOT fail here -- it would silently drop the zero "
                "(int('01234') == 1234) and write a wrong governed table without error." % hint
            ),
            alternatives=("varchar(64)",),  # deliberately NO integer type offered
            warning=(
                "Declaring an integer type for this column would destroy the leading "
                "zeros. Promotion refuses that coercion as lossy rather than performing it."
            ),
            **base,
        )

    # -- 2. Date and timestamp: the types the upload dialog cannot express. ---
    if is_texty or inferred in ("date", "timestamp"):
        if _all_match(observed, _parses_as_timestamp):
            return ColumnProposal(
                proposed_type="timestamp",
                reason=(
                    "every sampled value parses as an ISO-8601 date-time. TIMESTAMP is "
                    "unreachable through the Superset upload dialog, which is why this "
                    "upgrade is offered here."
                ),
                upgraded=inferred != "timestamp",
                alternatives=("string", "date"),
                **base,
            )
        if _all_match(observed, _parses_as_date):
            return ColumnProposal(
                proposed_type="date",
                reason=(
                    "every sampled value parses as an ISO-8601 calendar date. DATE is "
                    "unreachable through the Superset upload dialog, which is why this "
                    "upgrade is offered here."
                ),
                upgraded=inferred != "date",
                alternatives=("string", "timestamp"),
                **base,
            )

    # -- 3. Money. The type no amount of diligence reaches at the dialog. -----
    if (is_floaty or is_texty or is_inty) and looks_like_currency_name(name):
        shape = _decimal_shape(observed)
        if shape:
            precision, scale = shape
            decimal_type = "decimal(%d,%d)" % (precision, scale)
            return ColumnProposal(
                proposed_type=decimal_type,
                reason=(
                    "the column name says this is currency and every sampled value fits "
                    "%s. DECIMAL is unreachable at the upload dialog at ANY level of user "
                    "diligence -- money arriving as DOUBLE is the dialog's limit, not a "
                    "mistake you made." % decimal_type
                ),
                upgraded=not inferred.startswith("decimal("),
                alternatives=("double", "string"),
                **base,
            )

    # -- 4. Text that is plainly a number or a flag. Modest, evidenced. -------
    if is_texty and observed:
        if _all_match(observed, _is_boolean_text):
            return ColumnProposal(
                proposed_type="boolean",
                reason="every sampled value is true or false.",
                upgraded=True,
                alternatives=("string",),
                **base,
            )
        if _all_match(observed, _is_integer_text):
            return ColumnProposal(
                proposed_type="bigint",
                reason=(
                    "every sampled value is a whole number and none carries a leading "
                    "zero, so no identifier semantics are at risk."
                ),
                upgraded=True,
                alternatives=("string", "int"),
                **base,
            )

    # -- 5. No evidence for an upgrade. Carry the inferred type forward. ------
    return ColumnProposal(
        proposed_type=inferred,
        reason=(
            "the type inferred at upload is carried forward -- the sampled values gave "
            "no unambiguous evidence for a stronger type."
        ),
        upgraded=False,
        alternatives=tuple(
            alt for alt in ("string", "bigint", "double", "date", "timestamp") if alt != inferred
        )[:3],
        **base,
    )


# ---------------------------------------------------------------------------
# Plan
# ---------------------------------------------------------------------------


@dataclass
class PromotionPlan:
    """The pre-populated draft io reviews, edits, and sends back."""

    source_table: str
    source_identifier: str
    target_project: str
    target_table: str
    columns: List[ColumnProposal] = field(default_factory=list)
    freshness_column: str = DEFAULT_FRESHNESS_COLUMN
    provenance: Dict[str, str] = field(default_factory=dict)
    rows_sampled: int = 0
    sample_truncated: bool = False

    @property
    def type_map(self) -> Dict[str, str]:
        """The map as it would be submitted if io changed nothing.

        Accepting the draft unedited is a supported outcome, not a shortcut: the
        proposals are evidenced and the fallbacks are legal declared types, so
        the untouched plan always promotes.
        """
        return {column.name: column.proposed_type for column in self.columns}

    @property
    def upgrade_count(self) -> int:
        return sum(1 for column in self.columns if column.upgraded)

    @property
    def review_summary(self) -> str:
        """The one line the promotion screen leads with.

        Named and computed rather than left to the UI because it is the R-6
        measurement surface: it states how much of this map io did not have to
        write.
        """
        total = len(self.columns)
        return (
            "%d of %d columns pre-filled from the quarantined table; %d proposed as a "
            "stronger SQL type than the upload dialog could express. Review and correct "
            "-- nothing here is blank." % (total, total, self.upgrade_count)
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "source_table": self.source_table,
            "source_identifier": self.source_identifier,
            "target_project": self.target_project,
            "target_table": self.target_table,
            "columns": [column.as_dict() for column in self.columns],
            "type_map": self.type_map,
            "freshness_column": self.freshness_column,
            "provenance": self.provenance,
            "rows_sampled": self.rows_sampled,
            "sample_truncated": self.sample_truncated,
            "upgrade_count": self.upgrade_count,
            "review_summary": self.review_summary,
        }


def _freshness_proposal(existing: Optional[ColumnProposal], column_name: str) -> ColumnProposal:
    """The mandatory T2 freshness stamp, always present, never blank."""
    return ColumnProposal(
        name=column_name,
        inferred_type=existing.inferred_type if existing else "(absent)",
        proposed_type=FRESHNESS_COLUMN_TYPE,
        reason=(
            "mandatory freshness stamp on every governed T2 table (DOC-04AF8A02A8F7). "
            "Carried through from the quarantined table's upload time so the promoted "
            "table reports when the DATA arrived, not when promotion ran."
        ),
        upgraded=existing is None,
        alternatives=(),
        system_managed=True,
        sample_values=existing.sample_values if existing else (),
    )


def build_plan(
    source,
    target_project: str,
    target_table: Optional[str] = None,
    freshness_column: str = DEFAULT_FRESHNESS_COLUMN,
) -> PromotionPlan:
    """Build the pre-populated promotion plan for one quarantined table.

    ``source`` is a ``promotion_source.QuarantinedTable``.
    """
    target = target_table or source.name
    proposals: List[ColumnProposal] = []
    existing_freshness: Optional[ColumnProposal] = None

    for name, inferred in source.columns:
        values = list(source.values(name))
        proposal = propose_column(name, inferred, values)
        if name == freshness_column:
            existing_freshness = proposal
            continue
        proposals.append(proposal)

    proposals.append(_freshness_proposal(existing_freshness, freshness_column))

    return PromotionPlan(
        source_table=source.name,
        source_identifier=source.trino_identifier,
        target_project=target_project,
        target_table=target,
        columns=proposals,
        freshness_column=freshness_column,
        provenance=source.provenance(),
        rows_sampled=len(source.rows),
        sample_truncated=len(source.rows) >= PLAN_SAMPLE_LIMIT,
    )
