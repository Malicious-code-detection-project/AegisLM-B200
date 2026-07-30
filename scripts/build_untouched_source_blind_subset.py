"""Exclude previously exposed IDs from a source-code blind challenge."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def main() -> None:
    from aegislm.datasets.source_blind_subset import build_untouched_blind_subset
    from aegislm.evaluation.harness import load_jsonl

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--challenge", type=Path, required=True)
    parser.add_argument("--gold", type=Path, required=True)
    parser.add_argument("--private-records", type=Path, required=True)
    parser.add_argument(
        "--exposed-predictions",
        type=Path,
        action="append",
        required=True,
        help="Prediction JSONL previously run against the source challenge; repeatable.",
    )
    parser.add_argument("--expected-count", type=int, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    exposed_rows: list[dict[str, Any]] = []
    for path in args.exposed_predictions:
        exposed_rows.extend(load_jsonl(path))
    subset = build_untouched_blind_subset(
        load_jsonl(args.challenge),
        load_jsonl(args.gold),
        load_jsonl(args.private_records),
        exposed_rows,
        expected_count=args.expected_count,
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    outputs = {
        "challenge.jsonl": subset.challenge,
        "gold.jsonl": subset.gold,
        "private-records.jsonl": subset.private_records,
    }
    for name, rows in outputs.items():
        _write_jsonl(args.output_dir / name, rows)
    manifest = {
        **subset.manifest,
        "inputs": {
            "challenge_sha256": _sha256(args.challenge),
            "gold_sha256": _sha256(args.gold),
            "private_records_sha256": _sha256(args.private_records),
            "exposed_prediction_sha256s": [
                _sha256(path) for path in args.exposed_predictions
            ],
        },
        "outputs": {name: _sha256(args.output_dir / name) for name in outputs},
    }
    manifest_path = args.output_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Untouched source blind subset complete: "
        f"source={manifest['source_count']}, "
        f"exposed={manifest['exposed_count']}, "
        f"untouched={manifest['untouched_count']}, "
        f"manifest={manifest_path}"
    )


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text(
        "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows
        ),
        encoding="utf-8",
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    main()
