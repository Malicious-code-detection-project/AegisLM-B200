from __future__ import annotations

import copy
from typing import Any

import pytest

from aegislm.datasets.alignment_supply import (
    AlignmentSupplyError,
    audit_alignment_supply,
)


def _registry() -> dict[str, Any]:
    revision = "a" * 40
    return {
        "profile": "test",
        "observed_at": "2026-07-31",
        "storage": {"minimum_artifact_multiplier": 3.0},
        "sources": [
            {
                "source_id": "selected",
                "dataset_role": "source_assembly_alignment_feasibility",
                "requested_scope": "one_shard_alignment_feasibility",
                "revision": revision,
                "public": True,
                "gated": False,
                "dataset_license": "CC0-1.0",
                "training_requested": False,
                "acquire_now": True,
                "artifact": {
                    "url": f"https://example.test/resolve/{revision}/data.arrow",
                    "bytes": 100,
                    "sha256": "b" * 64,
                },
                "required_fields": ["source_code", "assembly"],
                "field_evidence": {
                    "source_code": True,
                    "assembly": True,
                },
                "selected_components": ["arrow_text_shard"],
            },
            {
                "source_id": "benchmark",
                "dataset_role": "independent_decompilation_benchmark",
                "requested_scope": "reserved_benchmark",
                "revision": "c" * 40,
                "public": True,
                "gated": False,
                "dataset_license": "CC0-1.0",
                "training_requested": False,
                "acquire_now": False,
                "artifact": {
                    "url": (f"https://example.test/resolve/{'c' * 40}/eval.arrow"),
                    "bytes": 50,
                    "sha256": "d" * 64,
                },
                "required_fields": ["source_code", "assembly", "pseudo_c"],
                "field_evidence": {
                    "source_code": True,
                    "assembly": True,
                    "pseudo_c": True,
                },
                "selected_components": ["arrow_text_shard", "pseudo_c"],
            },
        ],
    }


def test_alignment_preflight_selects_exactly_one_payload_free_candidate() -> None:
    result = audit_alignment_supply(_registry(), available_bytes=1_000)

    assert result["decision"] == "single_alignment_candidate_ready"
    assert result["acquisition_ready_source_ids"] == ["selected"]
    assert result["sources"][0]["decision"] == "acquisition_ready"
    assert result["sources"][1]["decision"] == "benchmark_reserved"
    assert result["approved_for_training"] is False
    assert result["safety"]["artifact_download_count"] == 0
    assert result["safety"]["raw_binary_read_count"] == 0


def test_alignment_preflight_holds_unknown_hash_and_raw_binary() -> None:
    registry = copy.deepcopy(_registry())
    source = registry["sources"][0]
    source["artifact"]["sha256"] = ""
    source["selected_components"] = ["raw_binary"]

    result = audit_alignment_supply(registry, available_bytes=1_000)

    assert result["decision"] == "alignment_preflight_requires_decision"
    assert result["sources"][0]["decision"] == "metadata_hold"
    assert "artifact_sha256_known" in result["sources"][0]["failure_reasons"]
    assert "selected_components_payload_free" in result["sources"][0]["failure_reasons"]
    assert result["sources"][0]["approved_for_download"] is False


def test_alignment_preflight_validates_storage_and_registry() -> None:
    result = audit_alignment_supply(_registry(), available_bytes=299)
    assert result["sources"][0]["checks"]["storage_headroom"] is False

    with pytest.raises(AlignmentSupplyError, match="positive"):
        audit_alignment_supply(_registry(), available_bytes=0)
