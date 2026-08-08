"""Apply io's declared SQL types to a quarantined table, all-or-nothing.

DVP-TSK-686. BRD B5-R2 step 2, and the ``failure_mode`` clause of DOC-FF843F9F0E2C:

    A promotion run that encounters a single value it cannot coerce to its
    declared type FAILS THE ENTIRE PROMOTION and reports the offending rows
    (table, column, row identifier, raw value) back to io.

The reasoning, restated because it drives every decision below: a partially typed
governed table is *worse* than a quarantined untyped one. A half-typed table
looks governed -- it lives at ``hive.<project>.*``, it has a declared schema --
while silently carrying unverified data in whichever columns failed. A
quarantined table carries no such false signal; its untyped status is legible
from its namespace alone.

Two properties this module adds over the shared library's ``_coerce_value``:

**Every offender, not the first.** ``_coerce_value`` raises on the first bad
value, which is correct for an export job whose input it controls. Promotion's
input is a CSV a human uploaded, and "fix this one, resubmit, discover the next
one" is precisely the R-6 unpleasantness that drives io back to charting from
quarantine. So this module collects the full report in one pass.

**Lossy coercions are failures.** This is the part that is not obvious and
matters most. Coercion failing is the easy case -- ``int("NULL")`` raises and
gets reported. The dangerous case is coercion SUCCEEDING and destroying data:

    >>> int("01234")
    1234

No exception. A governed table silently missing its leading zeros, and nothing
in any log to say so. So a value is accepted only when it round-trips: the
coerced value must render back to the same text it came from. A coercion that
cannot be undone is reported as an offender exactly like one that raised, with a
message that says which is which. This is what makes the criterion "verified
against the adhoc_probe_01.csv failure cases: leading-zero zip codes, a literal
NULL in an integer column, and currency requiring DECIMAL" mean three genuinely
different mechanisms rather than three spellings of ValueError.

Nothing here writes. Coercion completes entirely in memory and either returns
rows or raises; ``promotion_run`` calls AWS only after this module has returned.
All-or-nothing is therefore structural, not a promise -- there is no code path
in which a partial result reaches S3.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date as _date
from datetime import datetime
from decimal import Decimal
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:  # deployed: vendored flat by .build_extras
    from enceladus_shared.warehouse_registration import ContractViolation, _coerce_value
except ImportError:  # pragma: no cover - import shim, see .build_extras
    from warehouse_registration import ContractViolation, _coerce_value  # type: ignore[no-redef]

__all__ = [
    "MAX_REPORTED_OFFENDERS",
    "NULL_TOKENS",
    "OffendingValue",
    "PromotionCoercionError",
    "coerce_rows",
    "round_trips",
]

#: Offenders are counted in full and reported in bounded detail. A 40,000-row
#: CSV with a systematically wrong column would otherwise produce a report no
#: one can read and a payload no API should return. The count is always exact;
#: the sample is capped.
MAX_REPORTED_OFFENDERS = 50

#: Text that a human spreadsheet uses to mean "empty". Deliberately NOT treated
#: as SQL NULL. The upload path already had its chance to express nullity, and
#: guessing that the literal string ``NULL`` in an integer column means absence
#: -- rather than a real value someone typed -- is exactly the judgement call
#: DOC-FF843F9F0E2C reserves for io: "prevents an agent from ever being the
#: entity that decides a value 'close enough' to coerce." These tokens are
#: reported as offenders with a message naming the choice io has to make.
NULL_TOKENS = ("null", "none", "n/a", "na", "nan", "nil", "-", "?")

#: Boolean text, handled HERE rather than deferred to the shared library.
#:
#: The library's ``_coerce_value`` implements boolean as ``bool(value)``, which
#: is right for the export jobs it was written for -- they hand it real Python
#: bools out of DynamoDB. Promotion hands it text out of a CSV, and ``bool()``
#: over text is catastrophic rather than merely wrong::
#:
#:     >>> bool("false")
#:     True
#:
#: Every non-empty string is truthy, so an entire boolean column would promote
#: as all-True without raising. Recognising the tokens explicitly here, and
#: reporting anything else as an offender, keeps that failure impossible without
#: reaching into a merged library that four other callers depend on.
_TRUE_TOKENS = ("true", "t", "yes", "y", "1")
_FALSE_TOKENS = ("false", "f", "no", "n", "0")


@dataclass(frozen=True)
class OffendingValue:
    """One value that stopped the promotion. The full four-part identifier."""

    table: str
    column: str
    row_index: int
    raw_value: str
    declared_type: str
    reason: str
    lossy: bool = False

    @property
    def row_number(self) -> int:
        """1-based, and +1 again for the CSV header io is looking at.

        io is reading a spreadsheet, not a Python list. A report that says
        "row 0" sends them to the wrong line.
        """
        return self.row_index + 2

    def as_dict(self) -> Dict[str, Any]:
        return {
            "table": self.table,
            "column": self.column,
            "row_index": self.row_index,
            "row_number": self.row_number,
            "raw_value": self.raw_value,
            "declared_type": self.declared_type,
            "reason": self.reason,
            "lossy": self.lossy,
        }

    def __str__(self) -> str:
        return "row %d, column %r: %s (declared %s) -- %s" % (
            self.row_number,
            self.column,
            self.raw_value,
            self.declared_type,
            self.reason,
        )


class PromotionCoercionError(Exception):
    """The promotion failed as a whole. Nothing was written anywhere.

    Carries every offender it found, so one round trip tells io everything that
    needs fixing.
    """

    def __init__(self, table: str, offenders: Sequence[OffendingValue], total: int):
        self.table = table
        self.offenders = list(offenders)
        self.total = total
        super().__init__(self.summary())

    def summary(self) -> str:
        shown = len(self.offenders)
        header = (
            "promotion of %s FAILED: %d value%s could not be coerced to the declared "
            "type. Nothing was written -- promotion is all-or-nothing, because a "
            "partially typed governed table is worse than a quarantined untyped one."
            % (self.table, self.total, "" if self.total == 1 else "s")
        )
        if self.total > shown:
            header += " Showing the first %d." % shown
        lines = [header] + ["  - %s" % offender for offender in self.offenders]
        return "\n".join(lines)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "promoted": False,
            "table": self.table,
            "offending_row_count": self.total,
            "offending_rows": [offender.as_dict() for offender in self.offenders],
            "truncated": self.total > len(self.offenders),
            "message": self.summary(),
        }


def _render(value: Any) -> str:
    """Render a coerced value back to comparable text."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, Decimal):
        return format(value.normalize(), "f")
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, _date):
        return value.isoformat()
    if isinstance(value, float):
        return repr(value)
    return str(value)


_INTEGER_TYPES = ("tinyint", "smallint", "int", "integer", "bigint")
_FLOATING_TYPES = ("float", "real", "double")

#: A leading zero followed by another DIGIT. ``"01234"`` and ``"007"`` match;
#: ``"0"`` and ``"0.5"`` do not, because there the zero is arithmetic rather
#: than information.
_SIGNIFICANT_LEADING_ZERO_RE = re.compile(r"^[+-]?0\d")


def _numeric_key(text: str) -> str:
    """Normalise notation that carries no information for a numeric type."""
    try:
        return format(Decimal(text.strip()).normalize(), "f")
    except Exception:  # noqa: BLE001
        return text.strip()


def round_trips(raw: Any, coerced: Any, sql_type: str) -> bool:
    """True when coercion preserved the information in ``raw``.

    The subtlety that makes this function worth having: the comparison must NOT
    normalise the raw side the way it normalises the coerced side. An earlier
    draft ran ``int()`` over both, which folded ``"01234"`` to ``"1234"`` on the
    left as well and made the check pass -- a leading-zero detector that could
    never detect a leading zero. The raw text is the ground truth and is
    compared as written, with only genuinely non-informational notation
    (surrounding space, a leading ``+``, trailing decimal zeros) discounted.

    Leading zeros are handled first and unconditionally for every numeric type,
    because no numeric type can represent one: ``decimal`` and ``double`` lose
    it exactly as ``bigint`` does.
    """
    if raw is None or coerced is None:
        return raw is None and coerced is None
    if not isinstance(raw, str):
        # A typed value out of Parquet was never text; there is no textual
        # information for a round trip to lose.
        return True

    left = raw.strip()
    is_numeric = (
        sql_type in _INTEGER_TYPES
        or sql_type in _FLOATING_TYPES
        or sql_type.startswith("decimal(")
    )
    if is_numeric and _SIGNIFICANT_LEADING_ZERO_RE.match(left):
        return False

    right = _render(coerced)
    if sql_type in _INTEGER_TYPES:
        return left.lstrip("+") == right
    if sql_type in _FLOATING_TYPES or sql_type.startswith("decimal("):
        return _numeric_key(left) == _numeric_key(right)
    if sql_type == "boolean":
        return left.lower() == right.lower()
    if sql_type in ("date", "timestamp"):
        return left.replace(" ", "T").replace("Z", "+00:00") == right.replace(
            " ", "T"
        ).replace("Z", "+00:00")
    return left == right


def _null_token_reason(text: str, sql_type: str) -> str:
    return (
        "the literal text %r is not a %s. If this cell means 'no value', clear it in the "
        "source and re-upload so it arrives as a true NULL -- promotion will not decide "
        "on your behalf that a spelled-out %s means absence." % (text, sql_type, text.strip())
    )


def coerce_rows(
    rows: Sequence[Mapping[str, Any]],
    type_map: Mapping[str, str],
    table: str,
    freshness_column: Optional[str] = None,
    freshness_value: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Coerce every row to the declared types, or raise naming every offender.

    Returns rows shaped for ``warehouse_registration.register_table``. Raises
    ``PromotionCoercionError`` if ANY value in ANY row fails -- there is no
    partial-success return value, by design.
    """
    offenders: List[OffendingValue] = []
    total_offenders = 0
    coerced_rows: List[Dict[str, Any]] = []

    for index, row in enumerate(rows):
        coerced_row: Dict[str, Any] = {}
        for column, declared in type_map.items():
            declared_type = (declared or "").strip().lower()

            if freshness_column and column == freshness_column and freshness_value is not None:
                coerced_row[column] = freshness_value
                continue

            raw = row.get(column)

            if isinstance(raw, str) and raw.strip().lower() in NULL_TOKENS:
                if declared_type != "string" and not declared_type.startswith(("varchar(", "char(")):
                    total_offenders += 1
                    if len(offenders) < MAX_REPORTED_OFFENDERS:
                        offenders.append(
                            OffendingValue(
                                table=table,
                                column=column,
                                row_index=index,
                                raw_value=raw,
                                declared_type=declared_type,
                                reason=_null_token_reason(raw, declared_type),
                            )
                        )
                    continue

            if declared_type == "boolean" and isinstance(raw, str):
                token = raw.strip().lower()
                if token in _TRUE_TOKENS:
                    coerced_row[column] = True
                elif token in _FALSE_TOKENS:
                    coerced_row[column] = False
                else:
                    total_offenders += 1
                    if len(offenders) < MAX_REPORTED_OFFENDERS:
                        offenders.append(
                            OffendingValue(
                                table=table,
                                column=column,
                                row_index=index,
                                raw_value=raw,
                                declared_type=declared_type,
                                reason=(
                                    "%r is not a boolean. Recognised: %s / %s."
                                    % (raw, ", ".join(_TRUE_TOKENS), ", ".join(_FALSE_TOKENS))
                                ),
                            )
                        )
                continue

            try:
                value = _coerce_value(column, declared_type, raw)
            except ContractViolation as exc:
                total_offenders += 1
                if len(offenders) < MAX_REPORTED_OFFENDERS:
                    offenders.append(
                        OffendingValue(
                            table=table,
                            column=column,
                            row_index=index,
                            raw_value=_render(raw),
                            declared_type=declared_type,
                            reason=str(exc).split(": ", 1)[-1],
                        )
                    )
                continue

            if not round_trips(raw, value, declared_type):
                total_offenders += 1
                if len(offenders) < MAX_REPORTED_OFFENDERS:
                    offenders.append(
                        OffendingValue(
                            table=table,
                            column=column,
                            row_index=index,
                            raw_value=_render(raw),
                            declared_type=declared_type,
                            reason=(
                                "coercing to %s would silently change this value to %r. The "
                                "conversion does not raise -- it loses information. Declare a "
                                "text type to keep the value exactly as written."
                                % (declared_type, _render(value))
                            ),
                            lossy=True,
                        )
                    )
                continue

            coerced_row[column] = value
        coerced_rows.append(coerced_row)

    if total_offenders:
        raise PromotionCoercionError(table, offenders, total_offenders)
    return coerced_rows
