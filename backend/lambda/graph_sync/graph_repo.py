"""ENC-TSK-S47-0C (ENC-PLN-104 W6b.3): graph repository seam for graph_sync.

lambda_function.py builds Cypher with its existing helpers (_upsert_node, _reconcile_edges,
_merge_placeholder, ...) against a capturing transaction; the repository decides how the
captured statements reach the store. Neo4jRepository commits every staged record of a stream
batch in ONE write transaction: identical statements across records are collapsed into one
``UNWIND $__rows AS __row CALL { WITH __row <statement> }`` each. The ENC-TSK-Q62 FalkorDB
adapter implements the same GraphRepository surface.

Ordering contract (why grouping is safe):
  * a record's own statements keep their order (each statement is placed at a level strictly
    above the record's previous statement; levels run in ascending order);
  * a node key (label, record_id) appears at most once per wave; a repeat starts a new wave,
    so two versions of one record never interleave (owner-scoped reconcile, ENC-TSK-S33,
    deletes and re-creates only the edges the record owns, so distinct keys commute);
  * any non-batched graph access (repo.session()) flushes the pending batch first.

Failure contract: if the batch transaction fails (or a statement cannot be rewritten), each
staged record is re-run in its own transaction with its original, unrewritten statements, so
ReportBatchItemFailures still names the failing record; the record is marked
batch_tx_fallback = True.
"""
from __future__ import annotations

import logging
import re
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

NodeKey = Tuple[str, str]

_PARAM_RE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")
# A WITH clause drops every variable it does not name; carry __row through it. STARTS/ENDS WITH
# are string predicates, not clauses.
_WITH_RE = re.compile(r"(?<![A-Za-z_])(?<!STARTS )(?<!ENDS )WITH\s+(DISTINCT\s+)?(?!\*)")
_RETURN_RE = re.compile(r"(?<![A-Za-z_])RETURN\s+(.*)$", re.S)
_ALIAS_RE = re.compile(r"\bAS\s+([A-Za-z_][A-Za-z0-9_]*)\s*$")


class UnbatchableStatement(ValueError):
    """A captured statement the UNWIND rewrite cannot express safely."""


class DeferredResult:
    """Stands in for a driver Result while a statement is staged. ``single()`` answers None at
    capture time; the committed row (or None) is attached after the transaction and handed to
    callbacks via ``resolve()``."""

    __slots__ = ("callbacks", "row")

    def __init__(self) -> None:
        self.callbacks: List[Callable[[Optional[Dict[str, Any]]], None]] = []
        self.row: Optional[Dict[str, Any]] = None

    def single(self, *args: Any, **kwargs: Any) -> None:
        return None

    def add_callback(self, fn: Callable[[Optional[Dict[str, Any]]], None]) -> None:
        self.callbacks.append(fn)

    def resolve(self) -> None:
        for fn in self.callbacks:
            fn(self.row)


class StagedStatement:
    __slots__ = ("query", "params", "deferred", "optional")

    def __init__(self, query: str, params: Dict[str, Any], optional: bool) -> None:
        self.query = query
        self.params = params
        self.deferred = DeferredResult()
        self.optional = optional


class StagedRecord:
    """One stream record's captured statements plus its per-record audit outcome."""

    def __init__(self, key: NodeKey) -> None:
        self.key = key
        self.statements: List[StagedStatement] = []
        self.post_commit: Optional[Callable[[], None]] = None
        self.meta: Any = None  # handler-owned (position, raw record, timestamps)
        self.guard_stats: Dict[str, int] = {}
        self.store_ms = 0.0
        self.store_calls = 0
        self.store_statements = 0
        self.batch_tx_fallback = False
        self.error: Optional[BaseException] = None

    def capture(self, optional: bool = False) -> "CaptureTx":
        return CaptureTx(self, optional)

    def resolve_results(self) -> None:
        for st in self.statements:
            st.deferred.resolve()


class CaptureTx:
    """Transaction stand-in: records ``tx.run`` calls instead of sending them."""

    def __init__(self, record: StagedRecord, optional: bool) -> None:
        self._record = record
        self._optional = optional

    def run(self, query: str, parameters: Optional[Dict[str, Any]] = None, **kwargs: Any) -> DeferredResult:
        params = dict(parameters or {})
        params.update(kwargs)
        st = StagedStatement(str(query), params, self._optional)
        self._record.statements.append(st)
        return st.deferred


class CaptureSession:
    """Session stand-in for helpers that take a session (e.g. _project_mutated_edge)."""

    def __init__(self, tx: CaptureTx) -> None:
        self._tx = tx

    def execute_write(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        return fn(self._tx, *args, **kwargs)


def _return_columns(query: str) -> List[str]:
    m = _RETURN_RE.search(query)
    if not m:
        return []
    items, depth, cur = [], 0, ""
    for ch in m.group(1):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            items.append(cur)
            cur = ""
        else:
            cur += ch
    items.append(cur)
    cols = []
    for item in items:
        am = _ALIAS_RE.search(item.strip())
        if not am:
            raise UnbatchableStatement(f"RETURN item without alias: {item.strip()!r}")
        cols.append(am.group(1))
    return cols


def rewrite_for_unwind(query: str) -> Tuple[str, List[str]]:
    """Rewrite one parameterised statement to run once per ``$__rows`` element.

    ``$name`` -> ``__row.name``; every inner WITH also carries ``__row``. Returns the wrapped
    query and the statement's RETURN aliases (projected beside ``__row.__i``)."""
    if "CALL {" in query or "UNION" in query or "__row" in query:
        raise UnbatchableStatement("nested subquery / UNION / reserved name")
    cols = _return_columns(query)
    inner = _WITH_RE.sub(lambda m: f"WITH {m.group(1) or ''}__row, ", query)
    inner = _PARAM_RE.sub(lambda m: f"__row.{m.group(1)}", inner)
    head = f"UNWIND $__rows AS __row CALL {{ WITH __row {inner} }} "
    if cols:
        return head + "RETURN __row.__i AS __i, " + ", ".join(cols), cols
    return head + "RETURN count(*) AS __n", []


class _Group:
    __slots__ = ("query", "cols", "rows", "level", "seq", "members")

    def __init__(self, query: str, cols: List[str], level: int, seq: int) -> None:
        self.query, self.cols, self.level, self.seq = query, cols, level, seq
        self.rows: List[Dict[str, Any]] = []
        self.members: List[StagedStatement] = []


def build_plan(records: List[StagedRecord]) -> List[List[_Group]]:
    """Waves of UNWIND groups. Raises UnbatchableStatement if any statement cannot be rewritten."""
    waves: List[List[_Group]] = []
    rewrite_cache: Dict[str, Tuple[str, List[str]]] = {}
    seen: Set[NodeKey] = set()
    groups: Dict[Tuple[str, int], _Group] = {}
    levels: Dict[str, List[int]] = {}

    def _close() -> None:
        if groups:
            waves.append(sorted(groups.values(), key=lambda g: (g.level, g.seq)))

    for rec in records:
        if rec.key in seen:
            _close()
            seen, groups, levels = set(), {}, {}
        seen.add(rec.key)
        prev = -1
        involved: Set[int] = set()
        for st in rec.statements:
            if st.query not in rewrite_cache:
                rewrite_cache[st.query] = rewrite_for_unwind(st.query)
            wrapped, cols = rewrite_cache[st.query]
            floor = prev + 1
            usable = [lv for lv in levels.get(st.query, []) if lv >= floor]
            level = min(usable) if usable else floor
            g = groups.get((st.query, level))
            if g is None:
                g = groups[(st.query, level)] = _Group(wrapped, cols, level, len(groups))
                levels.setdefault(st.query, []).append(level)
            row = dict(st.params)
            row["__i"] = len(g.members)
            g.rows.append(row)
            g.members.append(st)
            involved.add(id(g))
            prev = level
        rec.store_statements = len(involved)
    _close()
    return waves


class GraphRepository:
    """Store-agnostic surface graph_sync writes through (Neo4j today, FalkorDB via ENC-TSK-Q62)."""

    batching = False

    def session(self) -> Any:  # non-batched access; flushes the pending batch first
        raise NotImplementedError

    def prefetch_node_state(self, keys: Iterable[NodeKey]) -> None:
        raise NotImplementedError

    def node_state(self, label: str, record_id: str) -> Dict[str, Any]:
        raise NotImplementedError

    def begin_record(self, key: NodeKey) -> StagedRecord:
        return StagedRecord(key)

    def stage(self, record: StagedRecord, version_seq: Any = None, embedding_hash: Optional[str] = None) -> None:
        raise NotImplementedError

    def take_last_staged(self) -> Optional[StagedRecord]:
        raise NotImplementedError

    def flush(self) -> None:
        raise NotImplementedError


class Neo4jRepository(GraphRepository):
    """Neo4j implementation. ``driver`` is the module-level driver (built once per container);
    ``session_wrapper`` wraps non-batched sessions (per-record stage timing); ``on_commit`` is
    called with the flushed StagedRecords, in stream order, after every flush."""

    def __init__(self, driver: Any, *, session_wrapper: Callable[[Any], Any] = lambda s: s,
                 on_commit: Callable[[List[StagedRecord]], None] = lambda recs: None,
                 batching: bool = True, state_property_hash: str = "embedding_text_hash") -> None:
        self._driver = driver
        self._wrap = session_wrapper
        self._on_commit = on_commit
        self.batching = batching
        self._hash_prop = state_property_hash
        self._pending: List[StagedRecord] = []
        self._last: Optional[StagedRecord] = None
        self._state: Dict[NodeKey, Dict[str, Any]] = {}
        self._carry_ms = 0.0  # node-state reads, folded into the next batch's per-record share

    # ---- non-batched path --------------------------------------------------------------
    def session(self) -> Any:
        self.flush()
        return self._wrap(self._driver.session())

    # ---- node state (version_seq idempotence + embedding hash) -------------------------
    def _read_state(self, keys: Iterable[NodeKey]) -> None:
        by_label: Dict[str, List[str]] = {}
        for label, rid in keys:
            if (label, rid) not in self._state:
                by_label.setdefault(label, []).append(rid)
        if not by_label:
            return

        def _work(tx: Any) -> List[Tuple[str, Dict[str, Any]]]:
            out = []
            for label, rids in by_label.items():
                res = tx.run(
                    f"UNWIND $rids AS rid MATCH (n:{label} {{record_id: rid}}) "
                    f"RETURN rid AS rid, n.version_seq AS v, n.{self._hash_prop} AS h",
                    rids=rids,
                )
                for row in res:
                    out.append((label, row))
            return out

        t0 = time.perf_counter()
        try:
            with self._driver.session() as s:
                rows = s.execute_read(_work)
        finally:
            self._carry_ms += (time.perf_counter() - t0) * 1000.0
        for label, rids in by_label.items():
            for rid in rids:
                self._state[(label, rid)] = {"v": None, "h": ""}
        for label, row in rows if isinstance(rows, list) else []:
            v, h = row["v"], row["h"]
            self._state[(label, str(row["rid"]))] = {
                "v": int(v) if v is not None else None,
                "h": str(h) if h is not None else "",
            }

    def prefetch_node_state(self, keys: Iterable[NodeKey]) -> None:
        keys = list(keys)
        if not keys:
            return
        try:
            self._read_state(keys)
        except Exception:  # noqa: BLE001 - prefetch is an optimisation; misses read singly
            logger.warning("[WARNING] graph node-state prefetch failed; falling back to per-record reads",
                           exc_info=True)
            for k in keys:
                self._state.pop(k, None)

    def node_state(self, label: str, record_id: str) -> Dict[str, Any]:
        key = (label, record_id)
        if key not in self._state:
            self._read_state([key])
        return self._state[key]

    # ---- staging -----------------------------------------------------------------------
    def stage(self, record: StagedRecord, version_seq: Any = None, embedding_hash: Optional[str] = None) -> None:
        state = self._state.setdefault(record.key, {"v": None, "h": ""})
        if version_seq is not None:
            state["v"] = int(version_seq)
        if embedding_hash is not None:
            state["h"] = embedding_hash
        self._pending.append(record)
        self._last = record

    def take_last_staged(self) -> Optional[StagedRecord]:
        rec, self._last = self._last, None
        return rec

    def flush(self) -> None:
        records, self._pending = self._pending, []
        if not records:
            return
        carry, self._carry_ms = self._carry_ms, 0.0
        try:
            waves = build_plan(records)
            t0 = time.perf_counter()
            with self._driver.session() as s:
                s.execute_write(lambda tx: _run_waves(tx, waves))
            share = (carry + (time.perf_counter() - t0) * 1000.0) / len(records)
            for rec in records:
                rec.store_ms, rec.store_calls = share, 1
        except Exception:  # noqa: BLE001 - per-record fallback keeps batchItemFailures exact
            logger.warning("[WARNING] graph batch transaction failed for %d records; "
                           "falling back to per-record transactions", len(records), exc_info=True)
            for rec in records:
                self._run_single(rec)
        self._on_commit(records)

    def _run_single(self, rec: StagedRecord) -> None:
        rec.batch_tx_fallback = True
        rec.store_ms = rec.store_calls = rec.store_statements = 0
        required = [st for st in rec.statements if not st.optional]
        optional = [st for st in rec.statements if st.optional]
        for part, must in ((required, True), (optional, False)):
            if not part:
                continue
            t0 = time.perf_counter()
            try:
                with self._driver.session() as s:
                    s.execute_write(lambda tx: _run_plain(tx, part))
            except Exception as exc:  # noqa: BLE001
                if must:
                    rec.error = exc
                    return
                logger.exception("[ERROR] optional graph statements failed for %s; primary projection preserved",
                                 rec.key)
            finally:
                rec.store_calls += 1
                rec.store_statements += len(part)
                rec.store_ms += (time.perf_counter() - t0) * 1000.0


def _row_dict(row: Any) -> Optional[Dict[str, Any]]:
    if row is None:
        return None
    if hasattr(row, "data"):
        return row.data()
    return dict(row)


def _run_plain(tx: Any, statements: List[StagedStatement]) -> None:
    for st in statements:
        res = tx.run(st.query, **st.params)
        st.deferred.row = _row_dict(res.single()) if st.deferred.callbacks and res is not None else None


def _run_waves(tx: Any, waves: List[List[_Group]]) -> None:
    for wave in waves:
        for g in wave:
            res = tx.run(g.query, __rows=g.rows)
            if not g.cols:
                if res is not None and hasattr(res, "consume"):
                    res.consume()
                continue
            for st in g.members:
                st.deferred.row = None
            for row in res or []:
                d = _row_dict(row) or {}
                g.members[int(d.pop("__i"))].deferred.row = d
