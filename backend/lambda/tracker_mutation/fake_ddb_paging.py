"""fake_ddb_paging.py — Multi-page DynamoDB Query() fake (ENC-TSK-Q13 / O1.4).

A minimal in-memory stand-in for the subset of the boto3 DynamoDB Query API
that _handle_list_records (and its cursor-walk tests) rely on:

  * Limit / ExclusiveStartKey / LastEvaluatedKey pagination.
  * FilterExpression applied AFTER Limit -- Limit counts EVALUATED
    (pre-filter) items, not post-filter matches, so a raw page can come
    back with fewer -- including zero -- Items than Limit while
    LastEvaluatedKey is still present.
  * LastEvaluatedKey present on every non-final raw page and absent on the
    truly final one, for both the base-table branch (KeyConditionExpression
    on project_id alone) and the project-type-index GSI branch
    (KeyConditionExpression on project_id + record_type), matching the two
    call shapes _handle_list_records builds.

`raw_page_size` (constructor) models DynamoDB's own physical per-call cap,
independent of whatever `Limit` a caller passes -- the effective per-call
item budget is min(kwargs Limit, raw_page_size). Real DynamoDB can return
fewer items than a caller's Limit for its own reasons (the 1MB response
cap, chiefly); this lets a test force that without inventing giant items.

Intentionally NOT implemented: multiple partitions/projects sharing one
table instance behaving independently is fine (KeyConditionExpression on
project_id is honoured), but arbitrary FilterExpression syntax is not --
only the simple `attr = :placeholder [AND attr = :placeholder ...]` shape
_handle_list_records emits (optionally via an ExpressionAttributeNames
placeholder like "#st") is evaluated.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple


class PagingTable:
    """Fakes ddb.query() over a fixed, pre-sorted list of raw DDB items.

    `items` must already be in the order the real table/index would return
    them (base branch: record_id ascending within project_id; GSI branch:
    whatever order the test wants to assert on -- D6 leaves GSI-branch
    order unspecified). Each item is a raw DDB attribute-value dict, e.g.
    {"project_id": {"S": ...}, "record_id": {"S": ...}, ...}.
    """

    def __init__(self, items: List[Dict[str, Any]], raw_page_size: int):
        if raw_page_size < 1:
            raise ValueError("raw_page_size must be >= 1")
        self.items = list(items)
        self.raw_page_size = raw_page_size
        self.calls: List[Dict[str, Any]] = []

    # -- key helpers ---------------------------------------------------

    @staticmethod
    def _s(item: Dict[str, Any], attr: str) -> Optional[str]:
        val = item.get(attr)
        return val.get("S") if val is not None else None

    def _key_tuple(self, item: Dict[str, Any], is_gsi: bool) -> Tuple[Optional[str], ...]:
        if is_gsi:
            return (
                self._s(item, "project_id"),
                self._s(item, "record_type"),
                self._s(item, "record_id"),
            )
        return (self._s(item, "project_id"), self._s(item, "record_id"))

    @staticmethod
    def _make_key(item: Dict[str, Any], is_gsi: bool) -> Dict[str, Any]:
        key = {"project_id": item["project_id"], "record_id": item["record_id"]}
        if is_gsi:
            key["record_type"] = item["record_type"]
        return key

    # -- filter evaluation ----------------------------------------------

    @staticmethod
    def _eval_filter(expr: Optional[str], item: Dict[str, Any],
                      expr_values: Dict[str, Any], expr_names: Dict[str, str]) -> bool:
        """Evaluate the simple ANDed-equality FilterExpression shape
        _handle_list_records builds. Not a general parser."""
        if not expr:
            return True
        for clause in expr.split(" AND "):
            attr, _, placeholder = clause.strip().partition("=")
            attr = attr.strip()
            placeholder = placeholder.strip()
            if attr.startswith("#"):
                attr = expr_names.get(attr, attr)
            want = expr_values.get(placeholder)
            if want is None or item.get(attr) != want:
                return False
        return True

    # -- the fake itself --------------------------------------------------

    def query(self, **kwargs) -> Dict[str, Any]:
        self.calls.append(dict(kwargs))
        is_gsi = "IndexName" in kwargs
        expr_values = kwargs.get("ExpressionAttributeValues", {}) or {}
        expr_names = kwargs.get("ExpressionAttributeNames", {}) or {}
        requested_limit = kwargs.get("Limit")
        effective_limit = (
            min(requested_limit, self.raw_page_size) if requested_limit else self.raw_page_size
        )

        pid = (expr_values.get(":pid") or {}).get("S")
        rtype = (expr_values.get(":rtype") or {}).get("S") if is_gsi else None
        pool = [
            it for it in self.items
            if self._s(it, "project_id") == pid
            and (rtype is None or self._s(it, "record_type") == rtype)
        ]

        start_idx = 0
        exclusive_start = kwargs.get("ExclusiveStartKey")
        if exclusive_start:
            target = self._key_tuple(exclusive_start, is_gsi)
            for idx, it in enumerate(pool):
                if self._key_tuple(it, is_gsi) == target:
                    start_idx = idx + 1
                    break
            else:
                start_idx = len(pool)

        raw_slice = pool[start_idx:start_idx + effective_limit]
        more_beyond = (start_idx + len(raw_slice)) < len(pool)

        filter_expr = kwargs.get("FilterExpression")
        out_items = [
            it for it in raw_slice
            if self._eval_filter(filter_expr, it, expr_values, expr_names)
        ]

        resp: Dict[str, Any] = {"Items": out_items}
        if more_beyond and raw_slice:
            resp["LastEvaluatedKey"] = self._make_key(raw_slice[-1], is_gsi)
        return resp
