"""Selective source-assembly review materialization for Decompile-Bench."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pyarrow as pa  # type: ignore[import-untyped]
import pyarrow.ipc as ipc  # type: ignore[import-untyped]

from aegislm.datasets.decompile_bench import (
    DECOMPILE_BENCH_INVENTORY_SCHEMA_VERSION,
)

DECOMPILE_BENCH_REVIEW_QUEUE_SCHEMA_VERSION = (
    "aegislm.phase-f-decompile-bench-alignment-review-queue.v1"
)


class DecompileBenchReviewError(ValueError):
    """Raised when selective alignment materialization cannot be verified."""


def materialize_decompile_bench_review_queue(
    shard_path: Path,
    inventory_path: Path,
) -> dict[str, Any]:
    """Read only selected rows and verify their hash-bound source/assembly pair."""
    if not shard_path.is_file():
        raise DecompileBenchReviewError(f"shard is not a regular file: {shard_path}")
    if not inventory_path.is_file():
        raise DecompileBenchReviewError(
            f"inventory is not a regular file: {inventory_path}"
        )
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    _validate_inventory(shard_path, inventory)
    selected = inventory["selection"]["records"]
    selected_by_index = {int(record["row_index"]): record for record in selected}
    materialized: dict[int, dict[str, Any]] = {}
    row_index = 0

    with pa.memory_map(str(shard_path), "r") as source:
        reader = ipc.open_stream(source)
        for batch in reader:
            rows = batch.to_pylist()
            for row in rows:
                if row_index in selected_by_index:
                    materialized[row_index] = _materialize_record(
                        row,
                        selected_by_index[row_index],
                    )
                row_index += 1

    missing_indices = sorted(set(selected_by_index) - set(materialized))
    records = [materialized[index] for index in sorted(materialized)]
    hash_errors = [
        str(record["candidate_id"])
        for record in records
        if record["materialization_errors"]
    ]
    checks = {
        "inventory_gate_pass": True,
        "selected_count_exact": len(records) == len(selected),
        "selected_rows_found": not missing_indices,
        "selected_hashes_match": not hash_errors,
        "operator_decisions_complete": False,
    }
    automatic_checks = {
        key: value
        for key, value in checks.items()
        if key != "operator_decisions_complete"
    }
    passed = all(automatic_checks.values())
    return {
        "schema_version": DECOMPILE_BENCH_REVIEW_QUEUE_SCHEMA_VERSION,
        "profile": "phase-f-decompile-bench-alignment-review-v1",
        "model_visible": False,
        "source_artifacts": {
            "shard_sha256": _sha256_file(shard_path),
            "inventory_sha256": _sha256_file(inventory_path),
        },
        "summary": {
            "requested_records": len(selected),
            "materialized_records": len(records),
            "missing_records": len(missing_indices),
            "hash_error_records": len(hash_errors),
            "unfinished_operator_decisions": len(records),
        },
        "checks": checks,
        "failure_reasons": sorted(
            key for key, value in automatic_checks.items() if not value
        ),
        "missing_row_indices": missing_indices,
        "hash_error_candidate_ids": hash_errors,
        "records": records,
        "decision": (
            "manual_alignment_review_ready"
            if passed
            else "alignment_materialization_fail"
        ),
        "approved_for_manual_alignment_review": passed,
        "approved_for_training": False,
        "safety": {
            "selected_source_read_count": len(records),
            "selected_assembly_read_count": len(records),
            "raw_binary_read_count": 0,
            "source_code_execution_count": 0,
            "assembly_execution_count": 0,
            "test_execution_count": 0,
            "object_execution_count": 0,
        },
    }


def _validate_inventory(
    shard_path: Path,
    inventory: dict[str, Any],
) -> None:
    if inventory.get("schema_version") != DECOMPILE_BENCH_INVENTORY_SCHEMA_VERSION:
        raise DecompileBenchReviewError("unsupported inventory schema")
    if inventory.get("decision") != "selective_alignment_review_ready":
        raise DecompileBenchReviewError("inventory gate has not passed")
    if inventory.get("approved_for_selective_alignment_review") is not True:
        raise DecompileBenchReviewError("selective review is not approved")
    if inventory.get("approved_for_training") is not False:
        raise DecompileBenchReviewError("inventory training approval must remain false")
    if inventory["artifact"]["sha256"] != _sha256_file(shard_path):
        raise DecompileBenchReviewError("inventory shard hash mismatch")
    selected = inventory.get("selection", {}).get("records")
    if not isinstance(selected, list) or not selected:
        raise DecompileBenchReviewError("inventory selection is empty")
    row_indices = [int(record["row_index"]) for record in selected]
    if len(row_indices) != len(set(row_indices)):
        raise DecompileBenchReviewError("selected row indices repeat")


def _materialize_record(
    row: dict[str, Any],
    selected: dict[str, Any],
) -> dict[str, Any]:
    name = str(row.get("name") or "")
    code = str(row.get("code") or "")
    assembly = str(row.get("asm") or "")
    source_path = str(row.get("file") or "")
    code_sha256 = _sha256_text(code)
    assembly_sha256 = _sha256_text(assembly)
    pair_sha256 = _sha256_text(f"{code_sha256}\0{assembly_sha256}")
    observed = {
        "function_identity_sha256": _sha256_text(
            f"{name}\0{source_path}\0{pair_sha256}"
        ),
        "function_name_sha256": _sha256_text(name),
        "source_path_sha256": _sha256_text(source_path),
        "source_code_sha256": code_sha256,
        "assembly_sha256": assembly_sha256,
        "pair_sha256": pair_sha256,
    }
    errors = sorted(
        key for key, value in observed.items() if str(selected.get(key)) != value
    )
    return {
        "candidate_id": str(selected["candidate_id"]),
        "row_index": int(selected["row_index"]),
        "function_name": name,
        "source_path_sha256": observed["source_path_sha256"],
        "source_code": code if not errors else "",
        "assembly": assembly if not errors else "",
        "source_code_sha256": observed["source_code_sha256"],
        "assembly_sha256": observed["assembly_sha256"],
        "pair_sha256": observed["pair_sha256"],
        "source_chars": len(code),
        "assembly_chars": len(assembly),
        "materialization_errors": errors,
        "operator_same_function": None,
        "operator_source_complete": None,
        "operator_semantic_alignment": None,
        "operator_notes": "",
        "disposition": "pending_manual_alignment_review",
    }


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
