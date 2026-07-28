"""Build a deterministic label-blind source-code challenge and separate gold."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from collections.abc import Iterator
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _iter_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    with path.open(encoding="utf-8") as input_file:
        for line_number, line in enumerate(input_file, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"{path}:{line_number}: invalid JSONL: {exc.msg}"
                ) from exc
            if not isinstance(record, dict):
                raise ValueError(f"{path}:{line_number}: record must be an object")
            yield record


def main() -> None:
    from aegislm.evaluation import (
        build_blind_code_challenge,
        collect_training_fingerprints,
        write_jsonl,
    )

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-dataset", type=Path, required=True)
    parser.add_argument(
        "--train-dataset",
        type=Path,
        help="Optional normalized train JSONL used for exact-hash decontamination.",
    )
    parser.add_argument("--challenge-output", type=Path, required=True)
    parser.add_argument("--gold-output", type=Path, required=True)
    parser.add_argument("--per-class", type=int, default=250)
    parser.add_argument("--seed", type=int, default=20260727)
    args = parser.parse_args()

    training_fingerprints: set[str] = set()
    if args.train_dataset:
        training_fingerprints = collect_training_fingerprints(
            _iter_jsonl(args.train_dataset)
        )
    prompts, gold, summary = build_blind_code_challenge(
        _iter_jsonl(args.test_dataset),
        per_class=args.per_class,
        seed=args.seed,
        training_fingerprints=training_fingerprints,
    )
    write_jsonl(prompts, args.challenge_output)
    write_jsonl(gold, args.gold_output)
    print(
        "AegisLM blind code challenge complete: "
        f"records={summary['selected_total']}, "
        f"excluded_training_overlap={summary['excluded_training_overlap']}, "
        f"challenge={args.challenge_output}, gold={args.gold_output}"
    )


if __name__ == "__main__":
    main()
