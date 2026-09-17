"""Apply ARVO operator decisions and emit a hash-bound manual gate result."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.datasets.arvo_patch import (  # noqa: E402
    apply_arvo_patch_manual_decisions,
    summarize_arvo_patch_manual_review,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review-json", type=Path, required=True)
    parser.add_argument("--decisions", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    review_bytes = args.review_json.read_bytes()
    manifest = json.loads(review_bytes)
    decisions = json.loads(args.decisions.read_text(encoding="utf-8"))
    records = apply_arvo_patch_manual_decisions(
        manifest["review_records"],
        decisions,
    )
    summary = summarize_arvo_patch_manual_review(
        records,
        required_count=int(manifest["selection"]["expected_count"]),
        maximum_error_rate=float(manifest["gate"]["maximum_error_rate"]),
    )
    result = {
        "schema_version": "aegislm.phase-f-arvo-patch-manual-decision.v1",
        "source_review": {
            "path": str(args.review_json),
            "sha256": hashlib.sha256(review_bytes).hexdigest(),
        },
        "manual_review": summary,
        "approved_for_training": bool(summary["pass"]),
        "reviewed_records": [
            row for row in records if isinstance(row.get("operator_family_match"), bool)
        ],
        "safety": manifest["safety"],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Phase F ARVO manual gate: "
        f"status={summary['status']}, reviewed={summary['reviewed_count']}, "
        f"errors={summary['error_count']}/{summary['required_count']}, "
        f"approved_for_training={result['approved_for_training']}"
    )


if __name__ == "__main__":
    main()
