"""Finalize the standalone v2 binary role-target manual review."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.datasets.binary_v1 import summarize_binary_manual_review  # noqa: E402
from aegislm.datasets.phase_f import load_jsonl  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review-dir", type=Path, required=True)
    args = parser.parse_args()
    manifest_path = args.review_dir / "review_manifest.json"
    review_path = args.review_dir / "manual_review_100.jsonl"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    result = summarize_binary_manual_review(
        load_jsonl(review_path),
        required_count=int(manifest["review_record_count"]),
        maximum_error_rate=float(manifest["maximum_label_or_evidence_error_rate"]),
    )
    manifest["manual_review"] = result
    manifest["status"] = (
        "manual_target_quality_gate_passed"
        if result["pass"]
        else "manual_target_quality_gate_failed"
    )
    manifest["approved_for_materialization"] = bool(result["pass"])
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Phase F binary role review finalized: "
        f"status={result['status']}, "
        f"reviewed={result['reviewed_count']}/{result['required_count']}, "
        f"errors={result['error_count']}, "
        f"approved={manifest['approved_for_materialization']}"
    )
    if not result["pass"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
