from __future__ import annotations

import pytest

from aegislm.datasets.patch_supply import (
    PatchSupplyError,
    audit_patch_label_supply,
)


def _registry() -> dict:
    fields = {
        "cve_id": True,
        "cwe_ids": True,
        "repository": True,
        "fix_commit": True,
        "function_before": True,
        "function_after": True,
        "localized_diff": True,
    }
    return {
        "profile": "test",
        "observed_at": "2026-07-31",
        "storage": {"minimum_archive_multiplier": 5.0},
        "sources": [
            {
                "source_id": "ready",
                "dataset_role": "patch_localized_cwe_label_supply",
                "version": "v1",
                "immutable_release": True,
                "artifact": {
                    "url": "https://example.test/data.zip",
                    "archive_bytes": 100,
                    "upstream_checksum": "sha256:" + "a" * 64,
                    "post_download_sha256_required": True,
                },
                "licenses": {"dataset": "CC-BY-4.0", "collector": "MIT"},
                "required_field_evidence": fields,
                "selected_components": ["relational_database"],
            },
            {
                "source_id": "hold",
                "dataset_role": "patch_localized_cwe_label_supply",
                "version": "main",
                "immutable_release": False,
                "artifact": {
                    "url": "",
                    "archive_bytes": None,
                    "upstream_checksum": "",
                    "post_download_sha256_required": True,
                },
                "licenses": {"dataset": "unverified", "collector": "GPL-3.0"},
                "required_field_evidence": fields,
                "selected_components": ["simple_json"],
            },
        ],
    }


def test_patch_supply_preflight_separates_ready_and_hold_sources() -> None:
    result = audit_patch_label_supply(_registry(), available_bytes=10_000)
    assert result["decision"] == "acquisition_candidate_ready"
    assert result["ready_source_ids"] == ["ready"]
    assert result["sources"][0]["decision"] == "acquisition_ready"
    assert result["sources"][1]["decision"] == "metadata_hold"
    assert set(result["sources"][1]["failure_reasons"]) == {
        "archive_size_known",
        "artifact_url_https",
        "dataset_license_known",
        "immutable_release",
        "storage_headroom",
        "upstream_checksum_available",
    }
    assert result["approved_for_training"] is False
    assert result["safety"]["archive_download_count"] == 0


def test_patch_supply_preflight_rejects_payload_components() -> None:
    registry = _registry()
    registry["sources"] = [registry["sources"][0]]
    registry["sources"][0]["selected_components"] = [
        "relational_database",
        "graph_archive",
    ]
    result = audit_patch_label_supply(registry, available_bytes=10_000)
    source = result["sources"][0]
    assert source["decision"] == "metadata_hold"
    assert source["forbidden_components"] == ["graph_archive"]
    assert "selected_components_payload_free" in source["failure_reasons"]


def test_patch_supply_preflight_requires_storage_headroom() -> None:
    registry = _registry()
    registry["sources"] = [registry["sources"][0]]
    result = audit_patch_label_supply(registry, available_bytes=499)
    assert result["ready_source_ids"] == []
    assert result["sources"][0]["storage"]["required_bytes"] == 500
    assert "storage_headroom" in result["sources"][0]["failure_reasons"]


def test_patch_supply_preflight_rejects_invalid_registry() -> None:
    registry = _registry()
    registry["sources"][0]["source_id"] = ""
    with pytest.raises(PatchSupplyError, match="missing source_id"):
        audit_patch_label_supply(registry, available_bytes=1)
    with pytest.raises(PatchSupplyError, match="available_bytes"):
        audit_patch_label_supply(_registry(), available_bytes=0)
