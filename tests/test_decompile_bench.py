from __future__ import annotations

import hashlib
from pathlib import Path

import pyarrow as pa  # type: ignore[import-untyped]
import pyarrow.ipc as ipc  # type: ignore[import-untyped]
import pytest

from aegislm.datasets.decompile_bench import (
    DecompileBenchError,
    inventory_decompile_bench_shard,
)


def _arrow(path: Path, *, include_assembly: bool = True) -> None:
    data: dict[str, list[str]] = {
        "name": ["f", "g", "h"],
        "code": ["int f(){return 1;}", "int g(){return 2;}", "int h(){}"],
        "file": ["a.c", "b.c", "c.c"],
    }
    if include_assembly:
        data["asm"] = ["mov eax,1", "mov eax,2", "ret"]
    table = pa.table(data)
    with path.open("wb") as handle:
        with ipc.new_stream(handle, table.schema) as writer:
            writer.write_table(table)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_decompile_bench_inventory_is_payload_free_and_deterministic(
    tmp_path: Path,
) -> None:
    shard = tmp_path / "data.arrow"
    _arrow(shard)

    first = inventory_decompile_bench_shard(
        shard,
        expected_bytes=shard.stat().st_size,
        expected_sha256=_sha256(shard),
        selection_seed=7,
        sample_size=2,
    )
    second = inventory_decompile_bench_shard(
        shard,
        expected_bytes=shard.stat().st_size,
        expected_sha256=_sha256(shard),
        selection_seed=7,
        sample_size=2,
    )

    assert first["decision"] == "selective_alignment_review_ready"
    assert first["row_count"] == 3
    assert first["selection"]["records"] == second["selection"]["records"]
    assert all(
        isinstance(record["row_index"], int) for record in first["selection"]["records"]
    )
    assert first["safety"]["source_code_return_count"] == 0
    assert first["safety"]["assembly_return_count"] == 0
    assert first["approved_for_training"] is False
    serialized = str(first["selection"]["records"])
    assert "int f()" not in serialized
    assert "mov eax" not in serialized


def test_decompile_bench_inventory_rejects_hash_mismatch(tmp_path: Path) -> None:
    shard = tmp_path / "data.arrow"
    _arrow(shard)

    with pytest.raises(DecompileBenchError, match="SHA-256 mismatch"):
        inventory_decompile_bench_shard(
            shard,
            expected_bytes=shard.stat().st_size,
            expected_sha256="0" * 64,
        )


def test_decompile_bench_inventory_fails_missing_required_column(
    tmp_path: Path,
) -> None:
    shard = tmp_path / "data.arrow"
    _arrow(shard, include_assembly=False)

    result = inventory_decompile_bench_shard(
        shard,
        expected_bytes=shard.stat().st_size,
        expected_sha256=_sha256(shard),
        sample_size=2,
    )

    assert result["decision"] == "arrow_inventory_fail"
    assert result["checks"]["expected_columns_present"] is False
    assert "expected_columns_present" in result["failure_reasons"]
