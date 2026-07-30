"""Merge disjoint B0 decompile shards into one auditable artifact."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any


def merge_shards(
    *,
    shards: list[Path],
    output_dir: Path,
    expected_variants: int,
) -> dict[str, Any]:
    """Copy disjoint pseudo/log artifacts and combine their summaries."""
    if output_dir.exists() and any(output_dir.iterdir()):
        raise ValueError(f"output directory is not empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    summaries = [
        json.loads((shard / "decompile-summary.json").read_text(encoding="utf-8"))
        for shard in shards
    ]
    ranges = sorted(
        (int(summary["start_index"]), int(summary["end_index"]))
        for summary in summaries
    )
    cursor = 0
    for start, end in ranges:
        if start != cursor or end <= start:
            raise ValueError(f"non-contiguous shard range: {start}:{end}")
        cursor = end
    if cursor != expected_variants:
        raise ValueError(f"shards cover {cursor}, expected {expected_variants}")

    for shard in shards:
        _copy_tree_disjoint(shard / "pseudo-c", output_dir / "pseudo-c")
        _copy_tree_disjoint(shard / "logs", output_dir / "logs")
    results = [
        result
        for summary in sorted(summaries, key=lambda item: item["start_index"])
        for result in summary["results"]
    ]
    passed = sum(bool(row["decompile_success"]) for row in results)
    linked = sum(bool(row["source_binary_function_linked"]) for row in results)
    summary = {
        "schema_version": "aegislm.phase-f-binary-b0-decompile-merged.v1",
        "scope": "merged disjoint Ghidra shards; not the B0 target-preservation gate",
        "shard_count": len(shards),
        "ranges": ranges,
        "variant_count": len(results),
        "decompile_success": {
            "passed": passed,
            "total": len(results),
            "rate": passed / len(results),
        },
        "source_binary_function_link": {
            "passed": linked,
            "total": len(results),
            "rate": linked / len(results),
        },
        "object_execution_count": 0,
        "target_preservation_status": "pending_operator_review",
        "ready_for_target_preservation_audit": (
            passed / len(results) >= 0.90 and linked / len(results) >= 0.95
        ),
        "results": results,
    }
    (output_dir / "decompile-summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


def _copy_tree_disjoint(source: Path, destination: Path) -> None:
    for path in source.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(source)
        target = destination / relative
        if target.exists():
            raise ValueError(f"overlapping shard artifact: {relative}")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shard", type=Path, action="append", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--expected-variants", type=int, required=True)
    args = parser.parse_args()
    result = merge_shards(
        shards=args.shard,
        output_dir=args.output_dir,
        expected_variants=args.expected_variants,
    )
    print(
        "Phase F binary decompile shards merged: "
        f"decompile={result['decompile_success']['passed']}/"
        f"{result['variant_count']}, "
        f"link={result['source_binary_function_link']['passed']}/"
        f"{result['variant_count']}"
    )


if __name__ == "__main__":
    main()
