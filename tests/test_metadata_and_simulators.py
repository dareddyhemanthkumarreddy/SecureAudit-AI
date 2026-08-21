"""
Tests for features/metadata_tracker.py and the simulation modules -
confirms metadata initialization, trust score updates, and the
critical tracked-vs-untracked tampering distinction that the whole
project's two-layer defense argument depends on.
"""

import os
import sys
import pytest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config
from partition.partition import FilePartitionManager
from features.metadata_tracker import MetadataTracker
from simulation.modification_simulator import ModificationSimulator
from simulation.corruption_simulator import CorruptionSimulator


@pytest.fixture
def test_file(tmp_path):
    file_path = tmp_path / "test_file.bin"
    file_path.write_bytes(os.urandom(20000))
    return str(file_path)


@pytest.fixture
def initialized_partition(test_file):
    manager = FilePartitionManager(block_size=4096, sub_block_size=512)
    info = manager.partition_file(test_file)
    info = MetadataTracker.initialize(info)
    return info


def test_metadata_initialization_defaults(initialized_partition):
    first_sub = initialized_partition["blocks"][0]["sub_blocks"][0]

    assert first_sub["version"] == 1
    assert first_sub["modified"] is False
    assert first_sub["trust_score"] == config.INITIAL_TRUST
    assert first_sub["verification_count"] == 0
    assert first_sub["challenge_count"] == 0


def test_stability_index_never_edited(initialized_partition):
    first_sub = initialized_partition["blocks"][0]["sub_blocks"][0]
    stability = MetadataTracker.calculate_stability(first_sub)
    assert stability == 1.0


def test_stability_index_decreases_with_edits(initialized_partition):
    first_sub = initialized_partition["blocks"][0]["sub_blocks"][0]

    stability_before = MetadataTracker.calculate_stability(first_sub)
    MetadataTracker.apply_modification(first_sub, b"X" * len(first_sub["data"]), track_properly=True)
    stability_after = MetadataTracker.calculate_stability(first_sub)

    assert stability_after < stability_before


def test_tracked_modification_updates_metadata(initialized_partition):
    first_sub = initialized_partition["blocks"][0]["sub_blocks"][0]
    original_trust = first_sub["trust_score"]

    MetadataTracker.apply_modification(first_sub, b"X" * len(first_sub["data"]), track_properly=True)

    assert first_sub["modified"] is True
    assert first_sub["version"] == 2
    assert first_sub["trust_score"] == original_trust - config.TRUST_PENALTY_MODIFIED


def test_untracked_corruption_leaves_metadata_unchanged(initialized_partition):
    """
    This is the critical test protecting the project's central finding:
    silent corruption must NOT touch metadata, or the entire two-layer
    defense argument (Phase 5's key finding) becomes invalid.
    """
    first_sub = initialized_partition["blocks"][0]["sub_blocks"][0]

    original_version = first_sub["version"]
    original_modified = first_sub["modified"]
    original_trust = first_sub["trust_score"]

    MetadataTracker.apply_modification(first_sub, b"X" * len(first_sub["data"]), track_properly=False)

    assert first_sub["version"] == original_version
    assert first_sub["modified"] == original_modified
    assert first_sub["trust_score"] == original_trust


def test_modification_simulator_respects_rate(initialized_partition):
    total_sub_blocks = initialized_partition["total_sub_blocks"]
    modified = ModificationSimulator.simulate(initialized_partition, rate=0.10, seed=42)

    expected = max(1, int(total_sub_blocks * 0.10))
    assert len(modified) == expected


def test_corruption_simulator_is_silent(initialized_partition):
    """Confirms corruption simulator produces changes invisible to metadata."""
    corrupted = CorruptionSimulator.simulate(initialized_partition, rate=0.05, seed=42)

    block_lookup = {
        block["block_id"]: {sb["sub_block_id"]: sb for sb in block["sub_blocks"]}
        for block in initialized_partition["blocks"]
    }

    for block_id, sub_block_id in corrupted:
        sub = block_lookup[block_id][sub_block_id]
        assert sub["modified"] is False
        assert sub["version"] == 1
        assert sub["trust_score"] == config.INITIAL_TRUST