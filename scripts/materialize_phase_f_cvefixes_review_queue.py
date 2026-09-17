"""Materialize the selected CVEfixes function pairs for manual review."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.datasets.cvefixes_review import (  # noqa: E402
    materialize_cvefixes_review_queue,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-code-chars", type=int, default=100_000)
    parser.add_argument("--max-diff-chars", type=int, default=100_000)
    args = parser.parse_args()

    result = materialize_cvefixes_review_queue(
        args.database,
        args.catalog,
        max_code_chars=args.max_code_chars,
        max_diff_chars=args.max_diff_chars,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Phase F CVEfixes review materialization: "
        f"decision={result['decision']}, "
        f"materialized={result['summary']['materialized_records']}, "
        f"errors={result['summary']['error_records']}, "
        f"unfinished={result['summary']['unfinished_operator_decisions']}"
    )
    if result["decision"] != "manual_review_ready":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
