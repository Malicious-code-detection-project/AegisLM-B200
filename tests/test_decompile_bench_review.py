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
from aegislm.datasets.decompile_bench_review import (
    DecompileBenchReviewError,
    materialize_decompile_bench_review_queue,
)


def _arrow(path: Path) -> None:
    table = pa.table(
        {
            "name": ["f", "g", "h"],
            "code": [
                "int f(){return 1;}",
                "int g(){return 2;}",
                "int h(){return 3;}",
            ],
            "asm": ["mov eax,1", "mov eax,2", "mov eax,3"],
            "file": ["a.c", "b.c", "c.c"],
        }
    )
    with path.open("wb") as handle:
        with ipc.new_stream(handle, table.schema) as writer:
            writer.write_table(table)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _inventory(shard: Path, output: Path) -> None:
    result = inventory_decompile_bench_shard(
        shard,
        expected_bytes=shard.stat().st_size,
        expected_sha256=_sha256(shard),
        sample_size=2,
    )
    output.write_text(json.dumps(result), encoding="utf-8")


def test_review_materializes_only_hash_bound_selected_rows(
    tmp_path: Path,
) -> None:
    shard = tmp_path / "data.arrow"
    inventory = tmp_path / "inventory.json"
    _arrow(shard)
    _inventory(shard, inventory)

    result = materialize_decompile_bench_review_queue(shard, inventory)

    assert result["decision"] == "manual_alignment_review_ready"
    assert result["summary"]["materialized_records"] == 2
    assert result["summary"]["hash_error_records"] == 0
    assert result["records"][0]["source_code"]
    assert result["records"][0]["assembly"]
    assert result["safety"]["selected_source_read_count"] == 2
    assert result["safety"]["raw_binary_read_count"] == 0
    assert result["approved_for_training"] is False


def test_review_rejects_inventory_hash_mismatch(tmp_path: Path) -> None:
    shard = tmp_path / "data.arrow"
    inventory = tmp_path / "inventory.json"
    _arrow(shard)
    _inventory(shard, inventory)
    document = json.loads(inventory.read_text(encoding="utf-8"))
    document["artifact"]["sha256"] = "0" * 64
    inventory.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(DecompileBenchReviewError, match="hash mismatch"):
        materialize_decompile_bench_review_queue(shard, inventory)
