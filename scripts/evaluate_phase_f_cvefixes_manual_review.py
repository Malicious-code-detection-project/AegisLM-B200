"""Evaluate CVEfixes operator decisions with the fixed fail-early budget."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.datasets.cvefixes_review_decision import (  # noqa: E402
    evaluate_cvefixes_review_decisions,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queue", type=Path, required=True)
    parser.add_argument("--decisions", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    result = evaluate_cvefixes_review_decisions(
        args.queue,
        args.decisions,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Phase F CVEfixes manual review: "
        f"decision={result['decision']}, "
        f"finished={result['summary']['finished_records']}, "
        f"errors={result['summary']['error_records']}, "
        f"unfinished={result['summary']['unfinished_records']}"
    )
    if result["decision"] == "manual_review_fail_early":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
