"""Build the fixed 100-record pre-training review for binary role targets v2."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.datasets.binary_v2 import (  # noqa: E402
    BINARY_V2_MANUAL_REVIEW_RECORDS,
    BINARY_V2_SEED,
    build_binary_role_manual_review,
    render_binary_role_manual_review,
)
from aegislm.datasets.phase_f import load_jsonl, write_jsonl  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tokenizer-gate", type=Path, required=True)
    parser.add_argument("--records", type=Path, action="append", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=BINARY_V2_SEED)
    parser.add_argument(
        "--review-records",
        type=int,
        default=BINARY_V2_MANUAL_REVIEW_RECORDS,
    )
    args = parser.parse_args()
    gate = json.loads(args.tokenizer_gate.read_text(encoding="utf-8"))
    prepared = build_binary_role_manual_review(
        [row for path in args.records for row in load_jsonl(path)],
        gate,
        seed=args.seed,
        review_records=args.review_records,
    )
    args.output_dir.mkdir(parents=True, exist_ok=False)
    review_path = args.output_dir / "manual_review_100.jsonl"
    write_jsonl(prepared["rows"], review_path)
    markdown_path = args.output_dir / "manual_review_100.md"
    markdown_path.write_text(
        render_binary_role_manual_review(prepared["rows"]),
        encoding="utf-8",
    )
    manifest = dict(prepared["manifest"])
    manifest["source_sha256"] = {
        "tokenizer_gate": _sha256(args.tokenizer_gate),
        "record_sources": {str(path): _sha256(path) for path in args.records},
    }
    manifest["review_artifact_sha256"] = _sha256(review_path)
    manifest["rendered_review_sha256"] = _sha256(markdown_path)
    (args.output_dir / "review_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Phase F binary role review: "
        f"pairs={manifest['review_pair_count']}, "
        f"records={manifest['review_record_count']}, "
        f"sha256={manifest['review_artifact_sha256']}"
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    main()
