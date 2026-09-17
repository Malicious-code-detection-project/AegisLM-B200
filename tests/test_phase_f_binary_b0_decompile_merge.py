import json
from pathlib import Path

import pytest

from scripts.merge_phase_f_binary_b0_decompile_shards import merge_shards


def _shard(root: Path, start: int, end: int) -> Path:
    root.mkdir()
    (root / "pseudo-c" / f"pair-{start}").mkdir(parents=True)
    (root / "pseudo-c" / f"pair-{start}" / "functions.tsv").write_text(
        "x", encoding="utf-8"
    )
    results = [
        {
            "decompile_success": True,
            "source_binary_function_linked": True,
        }
        for _ in range(end - start)
    ]
    (root / "decompile-summary.json").write_text(
        json.dumps(
            {
                "start_index": start,
                "end_index": end,
                "results": results,
            }
        ),
        encoding="utf-8",
    )
    return root


def test_merge_shards_requires_contiguous_ranges(tmp_path: Path) -> None:
    first = _shard(tmp_path / "s0", 0, 2)
    second = _shard(tmp_path / "s1", 2, 4)

    result = merge_shards(
        shards=[second, first],
        output_dir=tmp_path / "merged",
        expected_variants=4,
    )

    assert result["variant_count"] == 4
    assert result["decompile_success"]["rate"] == 1.0


def test_merge_shards_rejects_gap(tmp_path: Path) -> None:
    first = _shard(tmp_path / "s0", 0, 1)
    second = _shard(tmp_path / "s1", 2, 3)

    with pytest.raises(ValueError, match="non-contiguous"):
        merge_shards(
            shards=[first, second],
            output_dir=tmp_path / "merged",
            expected_variants=3,
        )
