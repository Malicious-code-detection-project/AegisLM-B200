"""Inventory one fixed Decompile-Bench Arrow shard without executing records."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.datasets.decompile_bench import (  # noqa: E402
    inventory_decompile_bench_shard,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shard", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-bytes", type=int, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--selection-seed", type=int, default=20_260_731)
    parser.add_argument("--sample-size", type=int, default=100)
    args = parser.parse_args()

    result = inventory_decompile_bench_shard(
        args.shard,
        expected_bytes=args.expected_bytes,
        expected_sha256=args.expected_sha256,
        selection_seed=args.selection_seed,
        sample_size=args.sample_size,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Phase F Decompile-Bench inventory: "
        f"decision={result['decision']}, "
        f"rows={result['row_count']}, "
        f"selected={result['selection']['sample_size']}, "
        f"duplicates={result['exact_pair_duplicates']['duplicate_rows']}"
    )
    if result["decision"] != "selective_alignment_review_ready":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
