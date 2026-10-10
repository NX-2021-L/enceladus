"""Static introspection of how a server.py tool handler reads its ``args`` dict.

DVP-TSK-843: the action registry declares an inputSchema for every action.  For
the actions whose underlying tool has no raw ``Tool(...)`` definition the schema
is declared once in ``mcp_server/action_schemas.py``; this module reads the
handler source (AST, no execution) and reports which argument keys the handler
actually consumes, so a test can fail the build when the declaration and the
handler disagree.  Nothing here runs at request time.

Resolution rules (all literal, nothing guessed):
  * ``args["k"]``                 -> hard read of ``k`` (KeyError when absent)
  * ``args.get("k"[, d])``        -> soft read of ``k``
  * ``"k" in args``               -> soft read of ``k``
  * ``for key in ("a", "b"):``    -> ``args.get(key)`` / ``args[key]`` inside the
                                     loop read every literal in the tuple/list
  * ``helper(args)``              -> the module-level helper in the same file is
                                     analysed with its first parameter bound to
                                     ``args`` (depth limited), so
                                     ``_require_governance_hash(args)`` yields
                                     ``governance_hash``.
A handler that forwards the whole dict (``dict(args)``, ``**args``, ``args``
passed to an unresolved callee) is reported in ``opaque`` and must be declared
with ``passthrough`` in the schema table.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

MAX_DEPTH = 3


@dataclass
class ArgReads:
    hard: Set[str] = field(default_factory=set)
    soft: Set[str] = field(default_factory=set)
    opaque: List[str] = field(default_factory=list)

    @property
    def keys(self) -> Set[str]:
        return self.hard | self.soft

    def merge(self, other: "ArgReads") -> None:
        self.hard |= other.hard
        self.soft |= other.soft
        self.opaque.extend(other.opaque)


class _Index:
    def __init__(self, source: str) -> None:
        self.tree = ast.parse(source)
        self.functions: Dict[str, ast.AST] = {}
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions.setdefault(node.name, node)


_CACHE: Dict[str, _Index] = {}


def _index(path: Path) -> _Index:
    key = str(path)
    if key not in _CACHE:
        _CACHE[key] = _Index(path.read_text(encoding="utf-8"))
    return _CACHE[key]


def _literal_strings(node: ast.AST) -> Optional[List[str]]:
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        out: List[str] = []
        for elt in node.elts:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                out.append(elt.value)
            else:
                return None
        return out
    return None


class _Reader(ast.NodeVisitor):
    def __init__(self, idx: _Index, param: str, depth: int, where: str) -> None:
        self.idx = idx
        self.param = param
        self.depth = depth
        self.where = where
        self.reads = ArgReads()
        self.loop_vars: Dict[str, List[str]] = {}
        self._handled_names: Set[int] = set()

    def _is_args(self, node: ast.AST) -> bool:
        return isinstance(node, ast.Name) and node.id == self.param

    def _key_names(self, node: ast.AST) -> Optional[List[str]]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return [node.value]
        if isinstance(node, ast.Name) and node.id in self.loop_vars:
            return self.loop_vars[node.id]
        return None

    def visit_For(self, node: ast.For) -> None:
        names = _literal_strings(node.iter)
        if names is not None and isinstance(node.target, ast.Name):
            self.loop_vars[node.target.id] = names
            for child in node.body + node.orelse:
                self.visit(child)
            del self.loop_vars[node.target.id]
            self.visit(node.iter)
            return
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if self._is_args(node.value):
            self._handled_names.add(id(node.value))
            keys = self._key_names(node.slice)
            if keys is None:
                self.reads.opaque.append(f"{self.where}: dynamic args[...] subscript")
            else:
                self.reads.hard.update(keys)
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        if (
            len(node.ops) == 1
            and isinstance(node.ops[0], (ast.In, ast.NotIn))
            and self._is_args(node.comparators[0])
        ):
            self._handled_names.add(id(node.comparators[0]))
            keys = self._key_names(node.left)
            if keys:
                self.reads.soft.update(keys)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and self._is_args(func.value):
            self._handled_names.add(id(func.value))
            if func.attr == "get" and node.args:
                keys = self._key_names(node.args[0])
                if keys is None:
                    self.reads.opaque.append(f"{self.where}: dynamic args.get(...)")
                else:
                    self.reads.soft.update(keys)
            elif func.attr in {"items", "keys", "values", "copy", "update"}:
                self.reads.opaque.append(f"{self.where}: args.{func.attr}()")
        # helper(args, ...) -> analyse the helper with the parameter rebound.
        for pos, arg in enumerate(node.args):
            if self._is_args(arg):
                self._handled_names.add(id(arg))
                callee = func.id if isinstance(func, ast.Name) else None
                if callee == "dict":
                    self.reads.opaque.append(f"{self.where}: dict(args)")
                elif callee in self.idx.functions and self.depth < MAX_DEPTH:
                    fn = self.idx.functions[callee]
                    params = [a.arg for a in fn.args.args]  # type: ignore[attr-defined]
                    if pos < len(params):
                        sub = _Reader(self.idx, params[pos], self.depth + 1, callee)
                        for stmt in fn.body:  # type: ignore[attr-defined]
                            sub.visit(stmt)
                        self.reads.merge(sub.reads)
                else:
                    self.reads.opaque.append(f"{self.where}: args passed to {callee or 'unresolved callee'}")
        for kw in node.keywords:
            if kw.arg is None and self._is_args(kw.value):
                self._handled_names.add(id(kw.value))
                self.reads.opaque.append(f"{self.where}: **args")
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        # A bare ``args`` that none of the patterns above claimed (e.g. ``x = args``).
        if self._is_args(node) and id(node) not in self._handled_names and isinstance(node.ctx, ast.Load):
            self.reads.opaque.append(f"{self.where}: bare reference to {self.param}")


def handler_arg_reads(server_path: Path, handler_name: str) -> ArgReads:
    """Return the argument keys the named handler (and its arg-forwarding helpers) read."""
    idx = _index(Path(server_path))
    fn = idx.functions[handler_name]
    params = [a.arg for a in fn.args.args]  # type: ignore[attr-defined]
    reader = _Reader(idx, params[0], 0, handler_name)
    for stmt in fn.body:  # type: ignore[attr-defined]
        reader.visit(stmt)
    return reader.reads
