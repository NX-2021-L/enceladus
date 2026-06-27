"""Tests for backfill_governance_version — ENC-TSK-I32 / DOC-6F7A14667E7D §8.

Covers:
  - build_seed_state captures generation 1, per-file checksum+versionId,
    governance_revision, and the §4.3 bundle hash from live S3
  - dry-run (default) performs NO write and emits before/after evidence
  - --commit on an empty table performs a first-write seed
  - backfill is idempotent: an existing record is never overwritten
  - source_event marks the seed as a backfill with an empty sequencer
"""

import backfill_governance_version as bf
import lambda_function as recompute


def _stub_live(monkeypatch, files=None, revision="2026-06-27.01"):
    if files is None:
        files = [("governance://agents.md", "governance/live/agents.md")]
    monkeypatch.setattr(recompute, "_list_canonical_files", lambda: files)
    checksums = {s3_key: (f"sum{i}", f"vid-{i}") for i, (_, s3_key) in enumerate(files)}
    monkeypatch.setattr(recompute, "_get_file_checksum", lambda key: checksums[key])
    monkeypatch.setattr(recompute, "_read_governance_revision", lambda key: revision)


def test_build_seed_state_shape(monkeypatch):
    _stub_live(
        monkeypatch,
        files=[
            ("governance://agents.md", "governance/live/agents.md"),
            ("governance://agents/plan.md", "governance/live/agents/plan.md"),
        ],
    )

    seed = bf.build_seed_state()

    assert seed["version_id"] == recompute.CANONICAL_ITEM_KEY
    assert seed["generation"] == 1
    assert seed["cas_version"] == 1
    assert seed["governance_revision"] == "2026-06-27.01"
    assert len(seed["files"]) == 2
    # per-file checksum + versionId captured
    assert seed["files"][0]["checksum_sha256_hex"] == "sum0"
    assert seed["files"][0]["s3_version_id"] == "vid-0"
    # bundle hash equals the §4.3 contract value from the recompute module
    assert seed["governance_hash"] == recompute._compute_bundle_hash(seed["files"])
    # backfill provenance: empty sequencer so the first real event advances gen
    assert seed["source_event"]["backfill"] is True
    assert seed["source_event"]["s3_sequencer"] == ""


def test_build_seed_state_refuses_empty_file_set(monkeypatch):
    monkeypatch.setattr(recompute, "_list_canonical_files", lambda: [])
    try:
        bf.build_seed_state()
        assert False, "expected RuntimeError on empty canonical set"
    except RuntimeError:
        pass


def test_dry_run_performs_no_write(monkeypatch):
    _stub_live(monkeypatch)
    monkeypatch.setattr(bf, "_read_full_record", lambda: None)

    cas_calls = []
    monkeypatch.setattr(recompute, "_cas_write", lambda **kwargs: cas_calls.append(kwargs) or True)

    evidence = bf.perform_backfill(commit=False)
    ev = evidence["backfill_evidence"]

    assert not cas_calls, "dry-run must not write"
    assert ev["dry_run"] is True
    assert ev["committed"] is False
    assert ev["before"] is None
    assert ev["seed"]["generation"] == 1


def test_commit_first_write_seeds_record(monkeypatch):
    _stub_live(monkeypatch)

    # before: empty; after: the seeded record
    states = iter([None, {"generation": 1, "governance_hash": "h"}])
    monkeypatch.setattr(bf, "_read_full_record", lambda: next(states))

    cas_calls = []

    def _cas(**kwargs):
        cas_calls.append(kwargs)
        return True

    monkeypatch.setattr(recompute, "_cas_write", _cas)

    evidence = bf.perform_backfill(commit=True)
    ev = evidence["backfill_evidence"]

    assert len(cas_calls) == 1
    assert cas_calls[0]["expected_cas"] is None  # first-write guard
    assert cas_calls[0]["generation"] == 1
    assert ev["committed"] is True
    assert ev["already_seeded"] is False


def test_backfill_is_idempotent_when_record_exists(monkeypatch):
    _stub_live(monkeypatch)
    monkeypatch.setattr(bf, "_read_full_record", lambda: {"generation": 7, "governance_hash": "h"})

    cas_calls = []
    monkeypatch.setattr(recompute, "_cas_write", lambda **kwargs: cas_calls.append(kwargs) or True)

    evidence = bf.perform_backfill(commit=True)
    ev = evidence["backfill_evidence"]

    assert not cas_calls, "existing record must never be overwritten by backfill"
    assert ev["already_seeded"] is True
    assert ev["committed"] is False


def test_main_dry_run_exit_zero(monkeypatch, capsys):
    _stub_live(monkeypatch)
    monkeypatch.setattr(bf, "_read_full_record", lambda: None)
    monkeypatch.setattr(recompute, "_cas_write", lambda **kwargs: True)

    rc = bf.main([])

    assert rc == 0
    out = capsys.readouterr().out
    assert "backfill_evidence" in out
