"""Aggregate Decompile-Bench repository provenance without returning payloads."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

import pyarrow as pa  # type: ignore[import-untyped]
import pyarrow.ipc as ipc  # type: ignore[import-untyped]

from aegislm.datasets.decompile_bench import (
    DECOMPILE_BENCH_INVENTORY_SCHEMA_VERSION,
)
from aegislm.datasets.decompile_bench_review_decision import (
    DECOMPILE_BENCH_REVIEW_RESULT_SCHEMA_VERSION,
)

DECOMPILE_BENCH_PROVENANCE_AUDIT_SCHEMA_VERSION = (
    "aegislm.phase-f-decompile-bench-provenance-audit.v1"
)
_PROJECT_PATH = re.compile(
    r"^/(?P<owner>[A-Za-z0-9_.-]+)\[P\]"
    r"(?P<repository>[A-Za-z0-9_.-]+)/"
)


class DecompileBenchProvenanceError(ValueError):
    """Raised when provenance inputs are not bound to the reviewed shard."""


def audit_decompile_bench_provenance(
    shard_path: Path,
    inventory_path: Path,
    review_result_path: Path,
    *,
    dataset_revision: str,
    dataset_license: str,
) -> dict[str, Any]:
    """Measure repository attribution coverage and retain training blockers."""
    if not shard_path.is_file():
        raise DecompileBenchProvenanceError(
            f"shard is not a regular file: {shard_path}"
        )
    inventory = _load_json(inventory_path, "inventory")
    review = _load_json(review_result_path, "review result")
    _validate_inputs(shard_path, inventory, review)
    if not dataset_revision or not dataset_license:
        raise DecompileBenchProvenanceError(
            "dataset revision and license must be explicit"
        )

    selected_by_index = {
        int(record["row_index"]): str(record["candidate_id"])
        for record in inventory["selection"]["records"]
    }
    failed_ids = {
        str(record["candidate_id"])
        for record in review["records"]
        if record["counts_as_error"] is True
    }
    project_rows: Counter[str] = Counter()
    unresolved_prefixes: Counter[str] = Counter()
    selected_explicit = 0
    selected_unresolved = 0
    selected_explicit_aligned = 0
    row_index = 0

    with pa.memory_map(str(shard_path), "r") as source:
        reader = ipc.open_stream(source)
        file_index = reader.schema.get_field_index("file")
        if file_index < 0:
            raise DecompileBenchProvenanceError("Arrow shard has no file column")
        for batch in reader:
            for value in batch.column(file_index).to_pylist():
                source_path = str(value or "")
                project = parse_decompile_bench_project(source_path)
                candidate_id = selected_by_index.get(row_index)
                if project is None:
                    unresolved_prefixes[_path_prefix(source_path)] += 1
                    if candidate_id is not None:
                        selected_unresolved += 1
                else:
                    project_rows[project] += 1
                    if candidate_id is not None:
                        selected_explicit += 1
                        if candidate_id not in failed_ids:
                            selected_explicit_aligned += 1
                row_index += 1

    total_rows = row_index
    explicit_rows = sum(project_rows.values())
    unresolved_rows = sum(unresolved_prefixes.values())
    selected_count = len(selected_by_index)
    checks = {
        "review_alignment_gate_passed": True,
        "inventory_row_count_matches": total_rows == int(inventory["row_count"]),
        "selected_count_matches": (
            selected_explicit + selected_unresolved == selected_count
        ),
        "dataset_revision_recorded": bool(dataset_revision),
        "dataset_license_recorded": bool(dataset_license),
        "repository_provenance_complete": unresolved_rows == 0,
        "repository_license_evidence_complete": False,
        "compiler_metadata_available": False,
        "optimization_metadata_available": False,
    }
    automatic_integrity_checks = {
        key: checks[key]
        for key in (
            "review_alignment_gate_passed",
            "inventory_row_count_matches",
            "selected_count_matches",
            "dataset_revision_recorded",
            "dataset_license_recorded",
        )
    }
    if not all(automatic_integrity_checks.values()):
        decision = "provenance_audit_invalid"
    else:
        decision = "alignment_reference_only"

    return {
        "schema_version": DECOMPILE_BENCH_PROVENANCE_AUDIT_SCHEMA_VERSION,
        "profile": "phase-f-decompile-bench-shard-00000-provenance-v1",
        "source_artifacts": {
            "shard_sha256": _sha256_file(shard_path),
            "inventory_sha256": _sha256_file(inventory_path),
            "review_result_sha256": _sha256_file(review_result_path),
            "dataset_revision": dataset_revision,
            "dataset_license": dataset_license,
        },
        "summary": {
            "total_rows": total_rows,
            "explicit_repository_rows": explicit_rows,
            "explicit_repository_rate": (
                explicit_rows / total_rows if total_rows else 0
            ),
            "unresolved_repository_rows": unresolved_rows,
            "unique_explicit_repositories": len(project_rows),
            "selected_records": selected_count,
            "selected_explicit_repository_records": selected_explicit,
            "selected_unresolved_repository_records": selected_unresolved,
            "selected_explicit_and_alignment_pass_records": (selected_explicit_aligned),
            "manual_alignment_error_records": len(failed_ids),
        },
        "repositories": [
            {
                "repository": project,
                "row_count": count,
                "repository_license_status": "unverified",
            }
            for project, count in sorted(
                project_rows.items(),
                key=lambda item: (-item[1], item[0]),
            )
        ],
        "unresolved_path_prefix_counts": dict(sorted(unresolved_prefixes.items())),
        "checks": checks,
        "training_blockers": [
            "repository_provenance_incomplete",
            "repository_license_evidence_incomplete",
            "compiler_metadata_missing",
            "optimization_metadata_missing",
            "no_vulnerability_label_or_patch_grounding",
        ],
        "decision": decision,
        "approved_for_alignment_reference": decision == "alignment_reference_only",
        "approved_for_filtered_license_review": (
            decision == "alignment_reference_only" and explicit_rows > 0
        ),
        "approved_for_processing": False,
        "approved_for_training": False,
        "safety": {
            "source_path_read_count": total_rows,
            "source_path_return_count": 0,
            "source_code_read_count": 0,
            "assembly_read_count": 0,
            "raw_binary_read_count": 0,
            "source_code_execution_count": 0,
            "assembly_execution_count": 0,
        },
    }


def parse_decompile_bench_project(source_path: str) -> str | None:
    """Extract the explicit owner[P]repository prefix, without guessing."""
    match = _PROJECT_PATH.match(source_path)
    if match is None:
        return None
    return f"{match.group('owner')}/{match.group('repository')}"


def _validate_inputs(
    shard_path: Path,
    inventory: dict[str, Any],
    review: dict[str, Any],
) -> None:
    if inventory.get("schema_version") != DECOMPILE_BENCH_INVENTORY_SCHEMA_VERSION:
        raise DecompileBenchProvenanceError("unsupported inventory schema")
    if inventory["artifact"]["sha256"] != _sha256_file(shard_path):
        raise DecompileBenchProvenanceError("inventory shard hash mismatch")
    if review.get("schema_version") != DECOMPILE_BENCH_REVIEW_RESULT_SCHEMA_VERSION:
        raise DecompileBenchProvenanceError("unsupported review result schema")
    if review.get("decision") != "manual_alignment_review_pass":
        raise DecompileBenchProvenanceError("manual alignment gate has not passed")
    if review.get("approved_for_alignment_quality") is not True:
        raise DecompileBenchProvenanceError("alignment quality is not approved")
    if review.get("approved_for_training") is not False:
        raise DecompileBenchProvenanceError(
            "review result training approval must remain false"
        )


def _path_prefix(source_path: str) -> str:
    if not source_path:
        return "<empty>"
    if source_path.startswith("/"):
        parts = source_path.split("/", 2)
        if len(parts) > 1 and parts[1]:
            return parts[1]
    return "<unparsed>"


def _load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        raise DecompileBenchProvenanceError(f"{label} is not a regular file: {path}")
    result = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(result, dict):
        raise DecompileBenchProvenanceError(f"{label} must be a JSON object")
    return result


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
