"""Apply a reviewed Decompile-Bench alignment decision batch."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.datasets.decompile_bench_review_decision import (  # noqa: E402
    apply_decompile_bench_review_updates,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--decisions", type=Path, required=True)
    parser.add_argument("--updates", type=Path, required=True)
    args = parser.parse_args()

    result = apply_decompile_bench_review_updates(args.decisions, args.updates)
    print(
        "Phase F Decompile-Bench decisions recorded: "
        f"applied={result['applied_records']}, "
        f"unchanged={result['unchanged_records']}, "
        f"sha256={result['decisions_sha256']}"
    )


if __name__ == "__main__":
    main()
