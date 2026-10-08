"""Offline tests for the read-through ledger and retention (ENC-TSK-Q52,
FR-10 / FR-11 / M-6 / M-7): ledger line shape and forbidden-content rule,
the batch_get read_through join and its no-op path, and run pruning on both
triggers (24 h age, B_session bytes).
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import stat
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import elr_batch_get
import elr_compact_context as cc
from elr_lib import context_store as store

try:  # pytest (package) and unittest-discover (rootdir=tests) both work
    from tests.test_compact_context import FakeClient, hybrid_body, record_routes, run_verb
except ImportError:  # pragma: no cover
    from test_compact_context import FakeClient, hybrid_body, record_routes, run_verb

_ELR_ROOT = Path(__file__).resolve().parent.parent
LEDGER_KEYS = {
    "ts", "run_id", "mode", "anchor", "intent_signature", "wave_id", "profile", "signals_present",
    "graph_algorithm", "ranked_ids", "per_signal_ranks", "fused_ranks", "final_ranks", "k_corr",
    "digest_bytes", "wall_ms",
}


def _read_ledger(root) -> list:
    return [json.loads(line) for line in (Path(root) / "ledger.jsonl").read_text().splitlines()]


class LedgerLineTests(unittest.TestCase):
    def test_each_run_appends_one_line_with_the_fr10_shape_and_0600(self):
        client = FakeClient(record_routes(hybrid_body(6)))
        with tempfile.TemporaryDirectory() as tmp:
            digest, code = run_verb(["--record-id", "ENC-TSK-Q33", "--top-n", "6", "--wave-id", "w1"], client, tmp)
            run_verb(["--record-id", "ENC-TSK-Q33", "--top-n", "6"], FakeClient(record_routes(hybrid_body(6))), tmp)
            lines = _read_ledger(tmp)
            mode_bits = stat.S_IMODE(os.stat(Path(tmp) / "ledger.jsonl").st_mode)
        self.assertEqual(code, 0)
        self.assertEqual(len(lines), 2)
        self.assertEqual(mode_bits, 0o600)
        line = lines[0]
        self.assertEqual(set(line), LEDGER_KEYS)
        self.assertEqual(line["run_id"], digest["header"]["run_id"])
        self.assertEqual(line["mode"], "record")
        self.assertEqual(line["anchor"], "ENC-TSK-Q33")
        self.assertEqual(line["profile"], "prod")
        self.assertEqual(line["signals_present"], ["vector", "graph", "keyword"])
        self.assertEqual(line["graph_algorithm"], "cypher_fallback")
        self.assertTrue(line["intent_signature"].startswith("sha256:"))
        self.assertEqual(line["digest_bytes"], digest["header"]["digest_bytes"])
        self.assertEqual(len(line["ranked_ids"]), 6)
        for aligned in ("per_signal_ranks", "fused_ranks", "final_ranks", "k_corr"):
            self.assertEqual(len(line[aligned]), 6, aligned)
        self.assertEqual(line["per_signal_ranks"][0], {"v": 12, "g": 34, "k": 56})
        self.assertEqual(line["final_ranks"], [1, 2, 3, 4, 5, 6])

    def test_wave_id_is_the_server_echo_not_the_flag(self):
        body = hybrid_body(2)
        body["pathway"]["wave_id"] = "wave-7"
        with tempfile.TemporaryDirectory() as tmp:
            run_verb(["--record-id", "ENC-TSK-Q33", "--wave-id", "wave-7"], FakeClient(record_routes(body)), tmp)
            self.assertEqual(_read_ledger(tmp)[0]["wave_id"], "wave-7")

    def test_no_key_body_or_long_title_reaches_the_ledger(self):
        secret = "SENTINEL-SECRET-KEY-VALUE-0123456789"
        with patch.dict(os.environ, {"ENCELADUS_INTERNAL_API_KEY": secret}):
            client = FakeClient(record_routes(hybrid_body(8)))
            with tempfile.TemporaryDirectory() as tmp:
                run_verb(["--record-id", "ENC-TSK-Q33", "--top-n", "8"], client, tmp)
                text = (Path(tmp) / "ledger.jsonl").read_text()
        self.assertNotIn(secret, text)
        entry = json.loads(text)
        for node in hybrid_body(8)["nodes"]:
            self.assertNotIn(node["title"], text)
        for name, value in entry.items():
            if isinstance(value, str) and name != "intent_signature":
                self.assertLessEqual(len(value), 64, name)
        store.validate_ledger_entry(entry)  # the shipped line passes its own rule

    def test_validator_rejects_keys_bodies_and_long_strings(self):
        good = {"run_id": "r", "ranked_ids": ["ENC-TSK-1"], "intent_signature": "sha256:" + "a" * 64}
        store.validate_ledger_entry(good)
        for bad in (
            {**good, "title": "x"},
            {**good, "api_key": "x"},
            {**good, "body": {"a": 1}},
            {**good, "note": "n" * 65},
            {**good, "ranked_ids": ["T" * 65]},
            {**good, "nested": {"deep": {"content": "x"}}},
        ):
            with self.subTest(bad=list(bad)):
                with self.assertRaises(ValueError):
                    store.validate_ledger_entry(bad)
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                store.append_ledger(Path(tmp), {**good, "title": "x"})
            self.assertFalse((Path(tmp) / "ledger.jsonl").exists())

    def test_failed_runs_write_no_ledger_line(self):
        client = FakeClient(record_routes(extra={("graph_query", ""): (404, {"error": "x"})}))
        with tempfile.TemporaryDirectory() as tmp:
            _, code = run_verb(["--record-id", "ENC-TSK-Q33"], client, tmp)
            self.assertEqual(code, 6)
            self.assertFalse((Path(tmp) / "ledger.jsonl").exists())


class ReadThroughTests(unittest.TestCase):
    def _digest(self, *found, missing=()):
        rows = [{"id": i, "outcome": "found"} for i in found] + [{"id": i, "outcome": "not_found"} for i in missing]
        return {"rows": rows, "ok": True}

    def test_ids_file_under_a_run_dir_appends_a_read_through_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ids_path = store.write_ids_file(root / "RUN123", "RUN123", ["ENC-TSK-1", "ENC-TSK-2"])
            appended = elr_batch_get.record_read_through(str(ids_path), self._digest("ENC-TSK-1", missing=["ENC-TSK-2"]), root)
            (event,) = _read_ledger(root)
        self.assertTrue(appended)
        self.assertEqual(set(event), {"ts", "run_id", "event", "ids"})
        self.assertEqual(event["run_id"], "RUN123")
        self.assertEqual(event["event"], "read_through")
        self.assertEqual(event["ids"], ["ENC-TSK-1"])  # only ids actually read

    def test_ids_files_elsewhere_are_a_no_op(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as other:
            root = Path(tmp)
            elsewhere = Path(other) / "ids.txt"
            elsewhere.write_text("ENC-TSK-1\n")
            direct_child = root / "stray.ids"  # inside root but not inside a run dir
            direct_child.write_text("ENC-TSK-1\n")
            for path in (elsewhere, direct_child, None):
                with self.subTest(path=str(path)):
                    self.assertFalse(elr_batch_get.record_read_through(str(path) if path else None, self._digest("ENC-TSK-1"), root))
            self.assertFalse((root / "ledger.jsonl").exists())

    def test_nothing_found_appends_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ids_path = store.write_ids_file(root / "RUN9", "RUN9", ["ENC-TSK-1"])
            self.assertFalse(elr_batch_get.record_read_through(str(ids_path), self._digest(missing=["ENC-TSK-1"]), root))

    def test_main_wires_the_join_through_the_context_root_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ids_path = store.write_ids_file(root / "RUNZ", "RUNZ", ["ENC-TSK-1"])
            fake = {"ok": True, "status": 200, "rows": [{"id": "ENC-TSK-1", "outcome": "found"}]}
            with patch.dict(os.environ, {store.CONTEXT_DIR_ENV: str(root)}), patch.object(
                elr_batch_get.elr_identity, "credential_refusal", return_value=None
            ), patch.object(elr_batch_get, "run_batch_get", return_value=fake), contextlib.redirect_stdout(io.StringIO()):
                code = elr_batch_get.main(["--ids-file", str(ids_path)])
            self.assertEqual(code, 0)
            self.assertEqual(_read_ledger(root)[0]["run_id"], "RUNZ")


def _make_run(root: Path, run_id: str, size: int, age_s: float, now: float) -> Path:
    directory = root / run_id
    directory.mkdir(parents=True)
    (directory / "hybrid.json").write_bytes(b"x" * size)
    stamp = now - age_s
    os.utime(directory / "hybrid.json", (stamp, stamp))
    os.utime(directory, (stamp, stamp))
    return directory


class PruneTests(unittest.TestCase):
    def test_constant_is_the_f11_fixed_point_and_lives_in_one_place(self):
        self.assertEqual(store.F11_B_SESSION_BYTES, 40_200_000)
        self.assertEqual(store.RUN_MAX_AGE_SECONDS, 86_400)
        self.assertIs(cc.context_store, store)
        source = (_ELR_ROOT / "elr_compact_context.py").read_text()
        self.assertNotIn("40_200_000", source)
        self.assertNotIn("40200000", source)
        self.assertNotIn("40.2", source)

    def test_age_trigger_removes_only_runs_older_than_24h(self):
        now = time.time()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _make_run(root, "OLD", 10, 25 * 3600, now)
            _make_run(root, "NEW", 10, 3600, now)
            (root / "ledger.jsonl").write_text('{"a":1}\n')
            removed = store.prune_runs(root, now=now)
            survivors = sorted(p.name for p in root.iterdir())
        self.assertEqual(removed, ["OLD"])
        self.assertEqual(survivors, ["NEW", "ledger.jsonl"])

    def test_size_trigger_prunes_oldest_run_first_until_under_the_cap(self):
        now = time.time()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _make_run(root, "R1", 400, 3000, now)  # oldest
            _make_run(root, "R2", 400, 2000, now)
            _make_run(root, "R3", 400, 1000, now)  # newest
            removed = store.prune_runs(root, now=now, max_bytes=900)
            survivors = sorted(p.name for p in root.iterdir())
        self.assertEqual(removed, ["R1"])
        self.assertEqual(survivors, ["R2", "R3"])

    def test_size_trigger_with_the_real_cap_uses_f11(self):
        now = time.time()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _make_run(root, "A", 1000, 100, now)
            self.assertEqual(store.prune_runs(root, now=now), [])  # far below 40.2 MB

    def test_protected_run_is_never_removed_and_ledger_survives_any_prune(self):
        now = time.time()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _make_run(root, "CURRENT", 5000, 90 * 3600, now)
            _make_run(root, "OTHER", 100, 80 * 3600, now)
            (root / "ledger.jsonl").write_text("x" * 10_000)
            removed = store.prune_runs(root, now=now, max_bytes=10, protect=("CURRENT",))
            self.assertEqual(removed, ["OTHER"])
            self.assertTrue((root / "CURRENT").is_dir())
            self.assertEqual((root / "ledger.jsonl").stat().st_size, 10_000)

    def test_the_verb_prunes_on_every_run_but_keeps_its_own_run_and_the_ledger(self):
        now = time.time()
        client = FakeClient(record_routes(hybrid_body(3)))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _make_run(root, "STALE", 50, 30 * 3600, now)
            digest, code = run_verb(["--record-id", "ENC-TSK-Q33", "--top-n", "3"], client, root)
            names = {p.name for p in root.iterdir()}
        self.assertEqual(code, 0)
        self.assertNotIn("STALE", names)
        self.assertIn(digest["header"]["run_id"], names)
        self.assertIn("ledger.jsonl", names)


if __name__ == "__main__":
    unittest.main()
