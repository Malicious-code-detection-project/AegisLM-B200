from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pyarrow as pa  # type: ignore[import-untyped]
import pyarrow.ipc as ipc  # type: ignore[import-untyped]
import pytest

from aegislm.datasets.decompile_bench import (
    inventory_decompile_bench_shard,
)
from aegislm.datasets.decompile_bench_provenance import (
    DecompileBenchProvenanceError,
    audit_decompile_bench_provenance,
    parse_decompile_bench_project,
)
from aegislm.datasets.decompile_bench_review_decision import (
    DECOMPILE_BENCH_REVIEW_RESULT_SCHEMA_VERSION,
)


def _arrow(path: Path) -> None:
    table = pa.table(
        {
            "name": ["f", "g", "h"],
            "code": ["int f();", "int g();", "int h();"],
            "asm": ["ret", "ret", "ret"],
            "file": [
                "/owner[P]repo/src/f.cpp",
                "/llvm/lib/IR/g.cpp",
                "/owner[P]repo/src/h.cpp",
            ],
        }
    )
    with path.open("wb") as handle:
        with ipc.new_stream(handle, table.schema) as writer:
            writer.write_table(table)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    shard = tmp_path / "data.arrow"
    inventory_path = tmp_path / "inventory.json"
    review_path = tmp_path / "review-result.json"
    _arrow(shard)
    inventory = inventory_decompile_bench_shard(
        shard,
        expected_bytes=shard.stat().st_size,
        expected_sha256=_sha256(shard),
        sample_size=3,
    )
    inventory_path.write_text(json.dumps(inventory), encoding="utf-8")
    selected_ids = [
        str(record["candidate_id"]) for record in inventory["selection"]["records"]
    ]
    review_path.write_text(
        json.dumps(
            {
                "schema_version": DECOMPILE_BENCH_REVIEW_RESULT_SCHEMA_VERSION,
                "decision": "manual_alignment_review_pass",
                "approved_for_alignment_quality": True,
                "approved_for_training": False,
                "records": [
                    {
                        "candidate_id": candidate_id,
                        "counts_as_error": index == 0,
                    }
                    for index, candidate_id in enumerate(selected_ids)
                ],
            }
        ),
        encoding="utf-8",
    )
    return shard, inventory_path, review_path


def test_project_parser_requires_explicit_owner_marker() -> None:
    assert parse_decompile_bench_project("/owner[P]repo/src/file.cpp") == "owner/repo"
    assert parse_decompile_bench_project("/llvm/lib/IR/file.cpp") is None
    assert parse_decompile_bench_project("../owner[P]repo/file.cpp") is None


def test_provenance_audit_keeps_partial_rows_out_of_training(
    tmp_path: Path,
) -> None:
    shard, inventory, review = _inputs(tmp_path)

    result = audit_decompile_bench_provenance(
        shard,
        inventory,
        review,
        dataset_revision="fixed-revision",
        dataset_license="CC0-1.0",
    )

    assert result["decision"] == "alignment_reference_only"
    assert result["summary"]["total_rows"] == 3
    assert result["summary"]["explicit_repository_rows"] == 2
    assert result["summary"]["unresolved_repository_rows"] == 1
    assert result["summary"]["unique_explicit_repositories"] == 1
    assert result["repositories"][0]["repository"] == "owner/repo"
    assert result["checks"]["repository_provenance_complete"] is False
    assert result["approved_for_filtered_license_review"] is True
    assert result["approved_for_training"] is False
    assert result["safety"]["source_code_read_count"] == 0


def test_provenance_audit_rejects_unpassed_alignment(tmp_path: Path) -> None:
    shard, inventory, review = _inputs(tmp_path)
    document = json.loads(review.read_text(encoding="utf-8"))
    document["decision"] = "manual_alignment_review_fail_early"
    review.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(
        DecompileBenchProvenanceError,
        match="alignment gate has not passed",
    ):
        audit_decompile_bench_provenance(
            shard,
            inventory,
            review,
            dataset_revision="fixed-revision",
            dataset_license="CC0-1.0",
        )
