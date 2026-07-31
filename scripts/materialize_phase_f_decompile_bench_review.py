"""Materialize the fixed Decompile-Bench source-assembly review queue."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.datasets.decompile_bench_review import (  # noqa: E402
    materialize_decompile_bench_review_queue,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shard", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    result = materialize_decompile_bench_review_queue(
        args.shard,
        args.inventory,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Phase F Decompile-Bench review materialization: "
        f"decision={result['decision']}, "
        f"materialized={result['summary']['materialized_records']}, "
        f"errors={result['summary']['hash_error_records']}"
    )
    if result["decision"] != "manual_alignment_review_ready":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
