"""Tests for apply_rhythm_artifact_lifecycle.py (ENC-TSK-N49)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import apply_rhythm_artifact_lifecycle as mod  # noqa: E402


def test_build_rhythm_rules_covers_all_tiers():
    rules = mod.build_rhythm_rules("gamma", "rhythm-cycle", 7)
    ids = {r["ID"] for r in rules}
    assert ids == {
        "RhythmArtifact-sense",
        "RhythmArtifact-light_integrate",
        "RhythmArtifact-decide",
        "RhythmArtifact-heavy_integrate",
        "RhythmArtifact-coherence",
        "RhythmArtifact-tenant-results",
    }
    for rule in rules:
        assert rule["Expiration"]["Days"] == 7
        assert rule["Filter"]["Prefix"].startswith("gamma/rhythm-cycle/")


def test_merge_lifecycle_replaces_prior_rhythm_rules():
    existing = {
        "Rules": [
            {"ID": "RhythmArtifact-sense", "Status": "Enabled", "Expiration": {"Days": 1}},
            {"ID": "UnrelatedRule", "Status": "Enabled", "Expiration": {"Days": 30}},
        ]
    }
    rhythm = mod.build_rhythm_rules("gamma", "rhythm-cycle", 7)
    merged = mod.merge_lifecycle(existing, rhythm)
    ids = [r["ID"] for r in merged["Rules"]]
    assert ids.count("RhythmArtifact-sense") == 1
    assert merged["Rules"][0]["ID"] == "UnrelatedRule"
    assert merged["Rules"][0]["Expiration"]["Days"] == 30
