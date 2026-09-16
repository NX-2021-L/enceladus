"""tests/test_stdlib_only.py -- ENC-TSK-P79 (T-B6, FR-B4-15..16) AC-3.

Two things must hold for ELR's "Python 3.11 standard library only"
promise to be real rather than aspirational:

  1. Every ELR runtime module -- elr_lib/*.py, elr_lib/vendor/*.py, and
     every top-level elr_*.py script -- imports cleanly on a machine
     that does not have ``certifi`` installed at all.
  2. ``certifi`` is the ONLY optional third-party import anywhere in
     that runtime file set, and it is always guarded by
     ``try/except ImportError`` (elr_lib/tls.py's ca-bundle chain) --
     never a bare top-level ``import certifi`` that would crash every
     other module on a certifi-less host.

Test 1 is enforced dynamically: a meta-path finder makes ``import
certifi`` raise ImportError regardless of whether certifi happens to be
pip-installed in THIS test environment, so the guarded except branch is
actually exercised rather than passively relying on certifi's absence.
Every elr module is then freshly re-imported (evicted from sys.modules
first) under that block.

Test 2 is enforced statically via ``ast``: every runtime .py file
(using elr_sync.collect_runtime_files() as the authoritative file set,
so this test automatically tracks AC-1's manifest include-rule) is
scanned for an ``import certifi`` / ``from certifi import ...`` node,
and any such node must sit directly in the body of a ``try`` block
whose handlers include ``ImportError`` (or a broader catch-all).

Discovery is filesystem-based (mirrors elr_sync.collect_runtime_files's
own include rule) rather than pkgutil.walk_packages: walk_packages
silently swallows ImportError while walking (its documented default
behavior), which would let a genuinely broken module quietly vanish
from the discovered set instead of failing the test -- filesystem
enumeration plus an explicit unguarded importlib.import_module() call
per name avoids that footgun.
"""

from __future__ import annotations

import ast
import importlib
import sys
import unittest
from pathlib import Path
from typing import List

_ELR_ROOT = Path(__file__).resolve().parent.parent

if str(_ELR_ROOT) not in sys.path:
    sys.path.insert(0, str(_ELR_ROOT))


def _elr_lib_module_names() -> List[str]:
    lib_dir = _ELR_ROOT / "elr_lib"
    names = ["elr_lib"]
    for py in sorted(lib_dir.glob("*.py")):
        if py.name == "__init__.py":
            continue
        names.append(f"elr_lib.{py.stem}")

    vendor_dir = lib_dir / "vendor"
    if vendor_dir.is_dir():
        names.append("elr_lib.vendor")
        for py in sorted(vendor_dir.glob("*.py")):
            if py.name == "__init__.py":
                continue
            names.append(f"elr_lib.vendor.{py.stem}")
    return names


def _top_level_script_module_names() -> List[str]:
    return sorted(p.stem for p in _ELR_ROOT.glob("elr_*.py"))


def _all_elr_module_names() -> List[str]:
    return _elr_lib_module_names() + _top_level_script_module_names()


class _BlockCertifiFinder:
    """Meta-path finder: any import of ``certifi`` (or a submodule)
    raises ImportError immediately, so the guarded except branch in
    elr_lib/tls.py is genuinely exercised by this test rather than
    coincidentally passing because certifi is not installed here.
    """

    def find_spec(self, fullname, path, target=None):  # noqa: D401 -- importlib protocol
        if fullname == "certifi" or fullname.startswith("certifi."):
            raise ImportError(f"certifi blocked by test_stdlib_only guard: {fullname}")
        return None


class StdlibOnlyImportTests(unittest.TestCase):
    """AC-3, dynamic half: every elr module imports with certifi both
    absent from sys.modules and unimportable.
    """

    def setUp(self) -> None:
        self._finder = _BlockCertifiFinder()
        sys.meta_path.insert(0, self._finder)

        # Evict certifi AND every already-imported elr module from
        # sys.modules so re-import actually re-executes top-level code
        # (including tls.py's guarded `import certifi`) under the
        # block, then restore the exact pre-test cache in tearDown so
        # this test cannot leak state into the rest of the suite.
        self._saved: dict = {}
        for name in list(sys.modules):
            if name == "certifi" or name.startswith("certifi."):
                self._saved[name] = sys.modules.pop(name)
        for name in _all_elr_module_names():
            if name in sys.modules:
                self._saved[name] = sys.modules.pop(name)

    def tearDown(self) -> None:
        sys.meta_path.remove(self._finder)
        for name in list(sys.modules):
            if name == "certifi" or name.startswith("certifi.") or name in _all_elr_module_names():
                if name not in self._saved:
                    sys.modules.pop(name, None)
        sys.modules.update(self._saved)

    def test_certifi_itself_is_unimportable_under_the_guard(self):
        with self.assertRaises(ImportError):
            importlib.import_module("certifi")

    def test_discovers_a_non_trivial_module_set(self):
        # Guards against a discovery-logic regression silently reducing
        # this test to a no-op (e.g. an empty elr_lib glob).
        names = _all_elr_module_names()
        self.assertGreaterEqual(len(names), 15, names)
        self.assertIn("elr_lib.tls", names)
        self.assertIn("elr_lib.vendor.document_api_outline", names)
        self.assertIn("elr_lib.vendor.document_api_sections", names)
        self.assertIn("elr_sync", names)
        self.assertIn("elr_doc_patch", names)

    def test_every_elr_lib_module_imports_with_certifi_blocked(self):
        for name in _elr_lib_module_names():
            with self.subTest(module=name):
                importlib.import_module(name)

    def test_every_top_level_script_imports_with_certifi_blocked(self):
        for name in _top_level_script_module_names():
            with self.subTest(module=name):
                importlib.import_module(name)

    def test_tls_module_falls_back_to_none_when_certifi_blocked(self):
        tls = importlib.import_module("elr_lib.tls")
        self.assertIsNone(tls.certifi)


class CertifiIsTheOnlyGuardedOptionalImportTests(unittest.TestCase):
    """AC-3, static half: certifi is the only optional third-party
    import in the runtime file set, and it is always guarded.
    """

    @staticmethod
    def _runtime_files() -> List[Path]:
        import elr_sync  # local import: exercises the real, current include-rule

        return elr_sync.collect_runtime_files(_ELR_ROOT)

    @staticmethod
    def _certifi_import_nodes(tree: ast.AST) -> List[ast.stmt]:
        nodes: List[ast.stmt] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import) and any(a.name.split(".")[0] == "certifi" for a in node.names):
                nodes.append(node)
            elif isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "certifi":
                nodes.append(node)
        return nodes

    @staticmethod
    def _handler_catches(handler: ast.ExceptHandler) -> bool:
        if handler.type is None:  # bare `except:`
            return True
        candidates = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
        names = [n.id for n in candidates if isinstance(n, ast.Name)]
        return any(n in ("ImportError", "ModuleNotFoundError", "Exception", "BaseException") for n in names)

    @classmethod
    def _is_guarded(cls, tree: ast.AST, target: ast.stmt) -> bool:
        for node in ast.walk(tree):
            if isinstance(node, ast.Try) and target in node.body:
                if any(cls._handler_catches(h) for h in node.handlers):
                    return True
        return False

    def test_certifi_import_is_guarded_and_is_the_only_optional_import(self):
        offending_files: List[str] = []
        unguarded: List[str] = []

        for path in self._runtime_files():
            if path.suffix != ".py":
                continue
            source = path.read_text(encoding="utf-8")
            if "certifi" not in source:
                continue

            rel = str(path.relative_to(_ELR_ROOT))
            tree = ast.parse(source, filename=str(path))
            nodes = self._certifi_import_nodes(tree)
            if not nodes:
                continue
            offending_files.append(rel)
            for node in nodes:
                if not self._is_guarded(tree, node):
                    unguarded.append(rel)

        self.assertEqual(unguarded, [], f"unguarded certifi import(s) in: {unguarded}")
        self.assertEqual(
            sorted(set(offending_files)),
            ["elr_lib/tls.py"],
            "certifi must be imported in exactly one place: elr_lib/tls.py's guarded ca-bundle chain",
        )


if __name__ == "__main__":
    unittest.main()
