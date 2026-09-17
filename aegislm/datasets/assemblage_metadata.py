"""Read-only artifact and schema audit helpers for Assemblage metadata."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

ASSEMBLAGE_SCHEMA_INVENTORY_VERSION = (
    "aegislm.phase-f-assemblage-metadata-schema-inventory.v1"
)
ASSEMBLAGE_FIELD_AUDIT_VERSION = "aegislm.phase-f-assemblage-metadata-field-audit.v1"
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_EXPECTED_TABLES = {"binaries", "functions", "lines", "rvas"}


class AssemblageMetadataError(ValueError):
    """Raised when an Assemblage metadata artifact violates the audit contract."""


def verify_compressed_metadata_artifact(
    artifact_path: Path,
    *,
    expected_bytes: int,
    expected_sha256: str,
) -> dict[str, Any]:
    """Verify the fixed compressed metadata artifact without decompressing it."""
    if expected_bytes <= 0:
        raise AssemblageMetadataError("expected_bytes must be positive")
    if not _SHA256_PATTERN.fullmatch(expected_sha256):
        raise AssemblageMetadataError("expected_sha256 must be lowercase SHA-256")
    if not artifact_path.is_file():
        raise AssemblageMetadataError(f"artifact does not exist: {artifact_path}")

    observed_bytes = artifact_path.stat().st_size
    observed_sha256 = _sha256(artifact_path)
    checks = {
        "artifact_size_matches": observed_bytes == expected_bytes,
        "artifact_sha256_matches": observed_sha256 == expected_sha256,
    }
    return {
        "artifact": {
            "name": artifact_path.name,
            "expected_bytes": expected_bytes,
            "observed_bytes": observed_bytes,
            "expected_sha256": expected_sha256,
            "observed_sha256": observed_sha256,
        },
        "checks": checks,
        "decision": "compressed_artifact_verified"
        if all(checks.values())
        else "compressed_artifact_rejected",
        "approved_for_decompression": all(checks.values()),
        "approved_for_training": False,
        "safety": {
            "decompressed_member_count": 0,
            "database_query_count": 0,
            "source_code_value_read_count": 0,
            "raw_binary_read_count": 0,
            "executable_execution_count": 0,
        },
    }


def build_schema_inventory(
    *,
    database_path: Path,
    database_sha256: str,
    schema_rows: Iterable[Sequence[Any]],
    table_rows: Iterable[Sequence[Any]],
    constraint_rows: Iterable[Sequence[Any]],
) -> dict[str, Any]:
    """Build a value-free schema inventory from DuckDB catalog query results."""
    if not database_path.is_file():
        raise AssemblageMetadataError(f"database does not exist: {database_path}")
    if not _SHA256_PATTERN.fullmatch(database_sha256):
        raise AssemblageMetadataError("database_sha256 must be lowercase SHA-256")

    columns_by_table: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for raw_row in schema_rows:
        if len(raw_row) != 5:
            raise AssemblageMetadataError("schema row must contain five values")
        table_name, column_name, data_type, ordinal_position, is_nullable = raw_row
        columns_by_table[str(table_name)].append(
            {
                "name": str(column_name),
                "data_type": str(data_type),
                "ordinal_position": int(ordinal_position),
                "nullable": str(is_nullable).upper() == "YES",
            }
        )

    table_estimates: dict[str, int | None] = {}
    for raw_row in table_rows:
        if len(raw_row) != 2:
            raise AssemblageMetadataError("table row must contain two values")
        table_name, estimated_size = raw_row
        table_estimates[str(table_name)] = (
            int(estimated_size) if estimated_size is not None else None
        )

    constraints: list[dict[str, str]] = []
    for raw_row in constraint_rows:
        if len(raw_row) != 4:
            raise AssemblageMetadataError("constraint row must contain four values")
        table_name, constraint_type, expression, referenced_table = raw_row
        constraints.append(
            {
                "table": str(table_name),
                "type": str(constraint_type),
                "expression": str(expression or ""),
                "referenced_table": str(referenced_table or ""),
            }
        )

    tables = []
    for table_name in sorted(columns_by_table):
        tables.append(
            {
                "name": table_name,
                "estimated_rows": table_estimates.get(table_name),
                "columns": sorted(
                    columns_by_table[table_name],
                    key=lambda item: int(item["ordinal_position"]),
                ),
            }
        )

    observed_tables = set(columns_by_table)
    checks = {
        "database_nonempty": database_path.stat().st_size > 0,
        "expected_core_tables_present": _EXPECTED_TABLES <= observed_tables,
        "schema_catalog_nonempty": bool(tables),
        "source_values_not_queried": True,
        "binary_payload_not_queried": True,
    }
    return {
        "schema_version": ASSEMBLAGE_SCHEMA_INVENTORY_VERSION,
        "database": {
            "name": database_path.name,
            "bytes": database_path.stat().st_size,
            "sha256": database_sha256,
            "read_only": True,
        },
        "tables": tables,
        "constraints": constraints,
        "checks": checks,
        "decision": "schema_inventory_pass"
        if all(checks.values())
        else "schema_inventory_fail",
        "approved_for_field_gate": all(checks.values()),
        "approved_for_training": False,
        "safety": {
            "schema_query_count": 3,
            "source_code_value_read_count": 0,
            "raw_binary_read_count": 0,
            "executable_execution_count": 0,
        },
    }


def schema_field_candidates(
    inventory: Mapping[str, Any],
) -> dict[str, list[str]]:
    """Map schema-only column names to fields that need a later value audit."""
    aliases = {
        "repository": ("repo", "repository", "github", "url"),
        "repository_license": ("license", "licence", "spdx"),
        "compiler": ("compiler", "toolchain"),
        "optimization": ("optimization", "opt", "cflags", "flags"),
        "architecture": ("architecture", "arch", "machine"),
        "binary_pointer": ("path", "binary", "file"),
        "source_code": ("source", "code", "content"),
        "function_identity": ("function", "name", "rva", "address"),
    }
    qualified_columns: list[str] = []
    tables = inventory.get("tables")
    if not isinstance(tables, list):
        raise AssemblageMetadataError("inventory tables must be a list")
    for table in tables:
        if not isinstance(table, Mapping):
            raise AssemblageMetadataError("inventory table must be an object")
        table_name = str(table.get("name") or "")
        columns = table.get("columns")
        if not isinstance(columns, list):
            raise AssemblageMetadataError("inventory columns must be a list")
        for column in columns:
            if not isinstance(column, Mapping):
                raise AssemblageMetadataError("inventory column must be an object")
            qualified_columns.append(f"{table_name}.{column.get('name', '')}")

    result: dict[str, list[str]] = {}
    for field, markers in aliases.items():
        result[field] = sorted(
            qualified
            for qualified in qualified_columns
            if any(marker in qualified.rsplit(".", 1)[-1].lower() for marker in markers)
        )
    return result


def build_field_audit(
    *,
    total_rows: int,
    expected_rows: int,
    coverage_counts: Mapping[str, int],
    distinct_counts: Mapping[str, int],
    strict_complete_rows: int,
    trace_without_architecture_rows: int,
    architecture_without_trace_rows: int,
    distributions: Mapping[str, Sequence[Sequence[Any]]],
) -> dict[str, Any]:
    """Evaluate aggregate-only Assemblage binary metadata coverage."""
    if total_rows <= 0 or expected_rows <= 0:
        raise AssemblageMetadataError("row counts must be positive")
    required_counts = {
        "repository",
        "license_declared",
        "license_actionable",
        "compiler",
        "optimization",
        "architecture",
        "binary_format",
        "repo_commit",
        "build_mode",
        "binary_pointer",
        "binary_hash",
    }
    missing_counts = sorted(required_counts - set(coverage_counts))
    if missing_counts:
        raise AssemblageMetadataError(
            f"coverage counts are missing fields: {missing_counts}"
        )

    coverage = {
        name: {
            "count": int(count),
            "rate": int(count) / total_rows,
        }
        for name, count in sorted(coverage_counts.items())
    }
    checks = {
        "documented_binary_count_matches": total_rows == expected_rows,
        "repository_coverage_at_least_0_99": coverage["repository"]["rate"] >= 0.99,
        "actionable_license_coverage_at_least_0_99": coverage["license_actionable"][
            "rate"
        ]
        >= 0.99,
        "compiler_coverage_at_least_0_99": coverage["compiler"]["rate"] >= 0.99,
        "optimization_coverage_at_least_0_99": coverage["optimization"]["rate"] >= 0.99,
        "architecture_coverage_at_least_0_99": coverage["architecture"]["rate"] >= 0.99,
        "binary_format_coverage_at_least_0_99": coverage["binary_format"]["rate"]
        >= 0.99,
        "repo_commit_coverage_at_least_0_99": coverage["repo_commit"]["rate"] >= 0.99,
        "build_mode_coverage_at_least_0_99": coverage["build_mode"]["rate"] >= 0.99,
        "strict_complete_supply_at_least_200": strict_complete_rows >= 200,
        "source_values_not_queried": True,
        "binary_payload_not_queried": True,
    }
    failures = sorted(name for name, passed in checks.items() if not passed)
    return {
        "schema_version": ASSEMBLAGE_FIELD_AUDIT_VERSION,
        "summary": {
            "total_binary_rows": total_rows,
            "expected_binary_rows": expected_rows,
            "strict_complete_rows": strict_complete_rows,
            "trace_without_architecture_rows": trace_without_architecture_rows,
            "architecture_without_trace_rows": architecture_without_trace_rows,
        },
        "coverage": coverage,
        "distinct_counts": {
            name: int(value) for name, value in sorted(distinct_counts.items())
        },
        "distributions": {
            name: [
                {
                    "value": str(row[0] or ""),
                    "count": int(row[1]),
                }
                for row in rows
            ]
            for name, rows in sorted(distributions.items())
        },
        "checks": checks,
        "failure_reasons": failures,
        "decision": (
            "metadata_quality_pass" if all(checks.values()) else "metadata_quality_fail"
        ),
        "approved_for_filtered_subset_design": all(checks.values()),
        "approved_for_binary_download": False,
        "approved_for_training": False,
        "safety": {
            "aggregate_metadata_queries_only": True,
            "source_code_value_read_count": 0,
            "binary_path_value_export_count": 0,
            "raw_binary_read_count": 0,
            "executable_execution_count": 0,
        },
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
