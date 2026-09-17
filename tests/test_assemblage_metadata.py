from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from aegislm.datasets.assemblage_metadata import (
    AssemblageMetadataError,
    build_field_audit,
    build_schema_inventory,
    schema_field_candidates,
    verify_compressed_metadata_artifact,
)


def test_fixed_compressed_artifact_verification(tmp_path: Path) -> None:
    artifact = tmp_path / "metadata.zst"
    artifact.write_bytes(b"fixed metadata")
    expected_sha256 = hashlib.sha256(artifact.read_bytes()).hexdigest()

    result = verify_compressed_metadata_artifact(
        artifact,
        expected_bytes=artifact.stat().st_size,
        expected_sha256=expected_sha256,
    )

    assert result["decision"] == "compressed_artifact_verified"
    assert result["approved_for_decompression"] is True
    assert result["approved_for_training"] is False
    assert result["safety"]["raw_binary_read_count"] == 0


def test_fixed_compressed_artifact_rejects_mismatch(tmp_path: Path) -> None:
    artifact = tmp_path / "metadata.zst"
    artifact.write_bytes(b"unexpected")

    result = verify_compressed_metadata_artifact(
        artifact,
        expected_bytes=1,
        expected_sha256="0" * 64,
    )

    assert result["decision"] == "compressed_artifact_rejected"
    assert result["approved_for_decompression"] is False

    with pytest.raises(AssemblageMetadataError, match="lowercase SHA-256"):
        verify_compressed_metadata_artifact(
            artifact,
            expected_bytes=1,
            expected_sha256="not-a-hash",
        )


def test_schema_inventory_is_value_free_and_maps_candidates(
    tmp_path: Path,
) -> None:
    database = tmp_path / "metadata.duckdb"
    database.write_bytes(b"DUCK")
    schema_rows = [
        ("binaries", "id", "BIGINT", 1, "NO"),
        ("binaries", "github_url", "VARCHAR", 2, "YES"),
        ("binaries", "license", "VARCHAR", 3, "YES"),
        ("binaries", "compiler", "VARCHAR", 4, "YES"),
        ("binaries", "optimization", "VARCHAR", 5, "YES"),
        ("binaries", "path", "VARCHAR", 6, "YES"),
        ("functions", "name", "VARCHAR", 1, "YES"),
        ("functions", "source_code", "VARCHAR", 2, "YES"),
        ("rvas", "function_id", "BIGINT", 1, "NO"),
        ("lines", "source_file", "VARCHAR", 1, "YES"),
    ]

    result = build_schema_inventory(
        database_path=database,
        database_sha256=hashlib.sha256(database.read_bytes()).hexdigest(),
        schema_rows=schema_rows,
        table_rows=[
            ("binaries", 10),
            ("functions", 20),
            ("rvas", 30),
            ("lines", 40),
        ],
        constraint_rows=[("functions", "FOREIGN KEY", "id", "binaries")],
    )
    candidates = schema_field_candidates(result)

    assert result["decision"] == "schema_inventory_pass"
    assert result["approved_for_training"] is False
    assert result["safety"]["source_code_value_read_count"] == 0
    assert candidates["repository"] == ["binaries.github_url"]
    assert candidates["repository_license"] == ["binaries.license"]
    assert candidates["optimization"] == ["binaries.optimization"]


def test_schema_inventory_requires_core_tables(tmp_path: Path) -> None:
    database = tmp_path / "metadata.duckdb"
    database.write_bytes(b"DUCK")

    result = build_schema_inventory(
        database_path=database,
        database_sha256=hashlib.sha256(database.read_bytes()).hexdigest(),
        schema_rows=[("binaries", "id", "BIGINT", 1, "NO")],
        table_rows=[("binaries", 10)],
        constraint_rows=[],
    )

    assert result["decision"] == "schema_inventory_fail"
    assert result["checks"]["expected_core_tables_present"] is False


def test_field_audit_separates_declared_from_actionable_license() -> None:
    result = build_field_audit(
        total_rows=1_000,
        expected_rows=1_000,
        coverage_counts={
            "repository": 1_000,
            "license_declared": 1_000,
            "license_actionable": 700,
            "compiler": 1_000,
            "optimization": 1_000,
            "architecture": 300,
            "binary_format": 300,
            "repo_commit": 300,
            "build_mode": 300,
            "binary_pointer": 1_000,
            "binary_hash": 1_000,
        },
        distinct_counts={"repositories": 100},
        strict_complete_rows=0,
        trace_without_architecture_rows=250,
        architecture_without_trace_rows=250,
        distributions={"license": [("mit", 700), ("other", 300)]},
    )

    assert result["decision"] == "metadata_quality_fail"
    assert result["coverage"]["license_declared"]["rate"] == 1.0
    assert result["coverage"]["license_actionable"]["rate"] == 0.7
    assert result["checks"]["strict_complete_supply_at_least_200"] is False
    assert result["approved_for_binary_download"] is False
    assert result["safety"]["source_code_value_read_count"] == 0


def test_field_audit_passes_only_complete_metadata() -> None:
    coverage = {
        "repository": 1_000,
        "license_declared": 1_000,
        "license_actionable": 1_000,
        "compiler": 1_000,
        "optimization": 1_000,
        "architecture": 1_000,
        "binary_format": 1_000,
        "repo_commit": 1_000,
        "build_mode": 1_000,
        "binary_pointer": 1_000,
        "binary_hash": 1_000,
    }

    result = build_field_audit(
        total_rows=1_000,
        expected_rows=1_000,
        coverage_counts=coverage,
        distinct_counts={"repositories": 100},
        strict_complete_rows=1_000,
        trace_without_architecture_rows=1_000,
        architecture_without_trace_rows=1_000,
        distributions={},
    )

    assert result["decision"] == "metadata_quality_pass"
    assert result["approved_for_filtered_subset_design"] is True
