"""Non-executing inventory and metadata catalog for Decompile-Bench Arrow."""

from __future__ import annotations

import hashlib
import statistics
from collections import Counter
from pathlib import Path
from typing import Any

import pyarrow as pa  # type: ignore[import-untyped]
import pyarrow.ipc as ipc  # type: ignore[import-untyped]

DECOMPILE_BENCH_INVENTORY_SCHEMA_VERSION = (
    "aegislm.phase-f-decompile-bench-arrow-inventory.v1"
)
EXPECTED_COLUMNS = {"name", "code", "asm", "file"}
_FORBIDDEN_COLUMN_MARKERS = {
    "binary",
    "bytes",
    "executable",
    "label",
    "cve",
    "cwe",
    "target",
}


class DecompileBenchError(ValueError):
    """Raised when the fixed Arrow shard violates the alignment contract."""


def inventory_decompile_bench_shard(
    shard_path: Path,
    *,
    expected_bytes: int,
    expected_sha256: str,
    selection_seed: int = 20_260_731,
    sample_size: int = 100,
) -> dict[str, Any]:
    """Scan source/assembly text without returning or executing record payloads."""
    if not shard_path.is_file():
        raise DecompileBenchError(f"shard is not a regular file: {shard_path}")
    if expected_bytes <= 0 or sample_size <= 0 or selection_seed < 0:
        raise DecompileBenchError("size, sample, and seed inputs are invalid")
    if len(expected_sha256) != 64:
        raise DecompileBenchError("expected_sha256 must be 64 hex characters")
    observed_bytes = shard_path.stat().st_size
    observed_sha256 = _sha256_file(shard_path)
    if observed_bytes != expected_bytes:
        raise DecompileBenchError(
            f"shard size mismatch: {observed_bytes} != {expected_bytes}"
        )
    if observed_sha256 != expected_sha256:
        raise DecompileBenchError("shard SHA-256 mismatch")

    source_lengths: list[int] = []
    assembly_lengths: list[int] = []
    null_counts: Counter[str] = Counter()
    empty_counts: Counter[str] = Counter()
    pair_hash_counts: Counter[str] = Counter()
    candidates: list[dict[str, Any]] = []
    row_count = 0
    batch_count = 0

    with pa.memory_map(str(shard_path), "r") as source:
        reader = ipc.open_stream(source)
        schema = reader.schema
        column_names = set(schema.names)
        missing_columns = sorted(EXPECTED_COLUMNS - column_names)
        forbidden_columns = sorted(
            column
            for column in schema.names
            if any(marker in column.lower() for marker in _FORBIDDEN_COLUMN_MARKERS)
        )
        for batch in reader:
            batch_count += 1
            rows = batch.to_pylist()
            for row in rows:
                row_count += 1
                values = {column: row.get(column) for column in EXPECTED_COLUMNS}
                for column, value in values.items():
                    if value is None:
                        null_counts[column] += 1
                    elif not str(value):
                        empty_counts[column] += 1
                name = str(values["name"] or "")
                code = str(values["code"] or "")
                assembly = str(values["asm"] or "")
                source_path = str(values["file"] or "")
                source_lengths.append(len(code))
                assembly_lengths.append(len(assembly))
                code_sha256 = _sha256_text(code)
                assembly_sha256 = _sha256_text(assembly)
                pair_sha256 = _sha256_text(f"{code_sha256}\0{assembly_sha256}")
                pair_hash_counts[pair_sha256] += 1
                identity = _sha256_text(f"{name}\0{source_path}\0{pair_sha256}")
                candidates.append(
                    {
                        "candidate_id": f"decompile-bench-{identity[:16]}",
                        "row_index": row_count - 1,
                        "function_identity_sha256": identity,
                        "function_name_sha256": _sha256_text(name),
                        "source_path_sha256": _sha256_text(source_path),
                        "source_code_sha256": code_sha256,
                        "assembly_sha256": assembly_sha256,
                        "pair_sha256": pair_sha256,
                        "source_chars": len(code),
                        "assembly_chars": len(assembly),
                    }
                )

    ranked = sorted(
        candidates,
        key=lambda row: _sha256_text(f"{selection_seed}\0{row['candidate_id']}"),
    )
    selected = ranked[:sample_size]
    selected_ids = [str(row["candidate_id"]) for row in selected]
    nonempty_source = row_count - null_counts["code"] - empty_counts["code"]
    nonempty_assembly = row_count - null_counts["asm"] - empty_counts["asm"]
    exact_duplicate_rows = sum(
        count - 1 for count in pair_hash_counts.values() if count > 1
    )
    checks = {
        "expected_columns_present": not missing_columns,
        "forbidden_columns_absent": not forbidden_columns,
        "row_count_sufficient": row_count >= sample_size,
        "source_nonempty_rate_at_least_0_99": (
            nonempty_source / row_count if row_count else 0
        )
        >= 0.99,
        "assembly_nonempty_rate_at_least_0_99": (
            nonempty_assembly / row_count if row_count else 0
        )
        >= 0.99,
        "selected_count_exact": len(selected) == sample_size,
        "selected_ids_unique": len(selected_ids) == len(set(selected_ids)),
        "raw_payload_omitted_from_report": True,
        "repository_provenance_available": False,
        "repository_license_available": False,
        "compiler_metadata_available": False,
        "optimization_metadata_available": False,
    }
    feasibility_checks = {
        key: value
        for key, value in checks.items()
        if key
        not in {
            "repository_provenance_available",
            "repository_license_available",
            "compiler_metadata_available",
            "optimization_metadata_available",
        }
    }
    passed = all(feasibility_checks.values())
    return {
        "schema_version": DECOMPILE_BENCH_INVENTORY_SCHEMA_VERSION,
        "profile": "phase-f-decompile-bench-shard-00000-inventory-v1",
        "artifact": {
            "path": str(shard_path.resolve()),
            "bytes": observed_bytes,
            "sha256": observed_sha256,
            "arrow_format": "ipc_stream",
        },
        "schema": [{"name": field.name, "type": str(field.type)} for field in schema],
        "row_count": row_count,
        "record_batch_count": batch_count,
        "null_counts": dict(sorted(null_counts.items())),
        "empty_counts": dict(sorted(empty_counts.items())),
        "lengths": {
            "source": _length_summary(source_lengths),
            "assembly": _length_summary(assembly_lengths),
        },
        "exact_pair_duplicates": {
            "duplicate_rows": exact_duplicate_rows,
            "duplicate_rate": (exact_duplicate_rows / row_count if row_count else 0),
        },
        "selection": {
            "seed": selection_seed,
            "sample_size": sample_size,
            "strategy": "deterministic_hash_rank",
            "records": selected,
        },
        "checks": checks,
        "failure_reasons": sorted(
            key for key, value in feasibility_checks.items() if not value
        ),
        "decision": (
            "selective_alignment_review_ready" if passed else "arrow_inventory_fail"
        ),
        "approved_for_selective_alignment_review": passed,
        "approved_for_training": False,
        "training_blockers": [
            "repository_provenance_missing",
            "repository_license_missing",
            "compiler_metadata_missing",
            "optimization_metadata_missing",
            "manual_alignment_quality_not_reviewed",
        ],
        "safety": {
            "source_code_read_count": row_count,
            "assembly_read_count": row_count,
            "raw_binary_read_count": 0,
            "source_code_return_count": 0,
            "assembly_return_count": 0,
            "source_code_execution_count": 0,
            "assembly_execution_count": 0,
            "test_execution_count": 0,
            "object_execution_count": 0,
        },
    }


def _length_summary(values: list[int]) -> dict[str, int | float]:
    if not values:
        return {"min": 0, "median": 0, "p95": 0, "max": 0}
    ordered = sorted(values)
    p95_index = min(len(ordered) - 1, int(len(ordered) * 0.95))
    return {
        "min": min(values),
        "median": statistics.median(values),
        "p95": ordered[p95_index],
        "max": max(values),
    }


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
