"""Build a deterministic balanced source challenge subset without gold leakage."""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def main() -> None:
    from aegislm.datasets.phase_f import load_jsonl, write_jsonl

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--challenge", type=Path, required=True)
    parser.add_argument("--gold", type=Path, required=True)
    parser.add_argument("--challenge-output", type=Path, required=True)
    parser.add_argument("--gold-output", type=Path, required=True)
    parser.add_argument("--per-class", type=int, default=10)
    parser.add_argument("--seed", type=int, default=20260728)
    args = parser.parse_args()

    challenge = load_jsonl(args.challenge)
    gold = load_jsonl(args.gold)
    challenge_by_id = {str(row["id"]): row for row in challenge}
    if len(challenge_by_id) != len(challenge):
        raise SystemExit("challenge ids must be unique")
    gold_by_id = {str(row["id"]): row for row in gold}
    if len(gold_by_id) != len(gold) or set(challenge_by_id) != set(gold_by_id):
        raise SystemExit("challenge and gold ids must match one-to-one")

    selected_ids: list[str] = []
    for label in ("present", "not_observed"):
        candidates = [
            record_id
            for record_id, row in gold_by_id.items()
            if row.get("expected_output", {}).get("assessment") == label
        ]
        ordered = sorted(
            candidates,
            key=lambda record_id: hashlib.sha256(
                f"{args.seed}:smoke:{record_id}".encode()
            ).hexdigest(),
        )
        if len(ordered) < args.per_class:
            raise SystemExit(f"not enough {label} records for smoke subset")
        selected_ids.extend(ordered[: args.per_class])
    selected_ids.sort(
        key=lambda record_id: hashlib.sha256(
            f"{args.seed}:smoke-order:{record_id}".encode()
        ).hexdigest()
    )
    write_jsonl(
        [challenge_by_id[record_id] for record_id in selected_ids],
        args.challenge_output,
    )
    write_jsonl(
        [gold_by_id[record_id] for record_id in selected_ids],
        args.gold_output,
    )
    print(
        f"Source smoke subset complete: records={len(selected_ids)}, "
        f"per_class={args.per_class}, output={args.challenge_output}"
    )


if __name__ == "__main__":
    main()
