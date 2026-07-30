"""Build a balanced answer-free canary from a decision training-style split."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def main() -> None:
    from aegislm.datasets.phase_f import load_jsonl, write_jsonl
    from aegislm.datasets.source_decision import (
        build_decision_development_subset,
    )

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--challenge-output", type=Path, required=True)
    parser.add_argument("--gold-output", type=Path, required=True)
    parser.add_argument("--per-class", type=int, default=50)
    parser.add_argument("--seed", type=int, default=20260728)
    args = parser.parse_args()

    challenge, gold = build_decision_development_subset(
        load_jsonl(args.input),
        per_class=args.per_class,
        seed=args.seed,
    )
    write_jsonl(challenge, args.challenge_output)
    write_jsonl(gold, args.gold_output)
    print(
        "Source decision development subset complete: "
        f"records={len(challenge)}, per_class={args.per_class}, "
        f"challenge={args.challenge_output}"
    )


if __name__ == "__main__":
    main()
