"""Build the next B0 audit batch from explicit canary review decisions."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def build_batch_queue(
    queue: dict[str, Any],
    reviews: list[dict[str, Any]],
    *,
    required_accepted_canary_pairs: int,
    batch_pairs: int,
) -> dict[str, Any]:
    """Freeze accepted canary pairs and choose unreviewed candidates in rank order."""
    decisions: dict[str, bool] = {}
    for review in reviews:
        for pair_id, passed in review["pair_decisions"].items():
            value = bool(passed)
            if pair_id in decisions and decisions[pair_id] != value:
                raise ValueError(f"conflicting pair decision: {pair_id}")
            decisions[pair_id] = value
    by_id = {str(row["pair_id"]): row for row in queue["candidates"]}
    unknown = sorted(set(decisions) - set(by_id))
    if unknown:
        raise ValueError(
            "reviewed pair missing from source queue: " + ", ".join(unknown)
        )
    accepted_ids = sorted(pair_id for pair_id, passed in decisions.items() if passed)
    failed_ids = sorted(pair_id for pair_id, passed in decisions.items() if not passed)
    if len(accepted_ids) < required_accepted_canary_pairs:
        raise ValueError(
            "accepted canary supply below gate: "
            f"{len(accepted_ids)} < {required_accepted_canary_pairs}"
        )
    unreviewed = sorted(
        (row for row in queue["candidates"] if str(row["pair_id"]) not in decisions),
        key=lambda row: (
            0 if row["queue"] == "primary" else 1,
            int(row["queue_rank"]),
        ),
    )
    if len(unreviewed) < batch_pairs:
        raise ValueError("unreviewed candidate supply below batch quota")
    batch = []
    for rank, row in enumerate(unreviewed[:batch_pairs], start=1):
        batch.append(
            {
                **row,
                "queue": "primary",
                "queue_rank": rank,
                "disposition": "b0_batch_pending_target_preservation_audit",
            }
        )
    return {
        "schema_version": "aegislm.phase-f-binary-b0-batch-queue.v1",
        "profile": queue["profile"],
        "seed": queue["seed"],
        "required_accepted_canary_pairs": required_accepted_canary_pairs,
        "accepted_canary_pair_ids": accepted_ids,
        "failed_canary_pair_ids": failed_ids,
        "reviewed_pair_count": len(decisions),
        "batch_pair_count": len(batch),
        "candidates": batch,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queue", type=Path, required=True)
    parser.add_argument(
        "--review-summary",
        type=Path,
        action="append",
        required=True,
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--required-canary-pairs", type=int, default=10)
    parser.add_argument("--batch-pairs", type=int, default=90)
    args = parser.parse_args()
    queue = json.loads(args.queue.read_text(encoding="utf-8"))
    reviews = [
        json.loads(path.read_text(encoding="utf-8")) for path in args.review_summary
    ]
    output = build_batch_queue(
        queue,
        reviews,
        required_accepted_canary_pairs=args.required_canary_pairs,
        batch_pairs=args.batch_pairs,
    )
    output["source_queue_sha256"] = hashlib.sha256(args.queue.read_bytes()).hexdigest()
    output["review_summary_sha256"] = {
        str(path): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in args.review_summary
    }
    args.output.write_text(
        json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Phase F binary B0 batch queue: "
        f"accepted_canary={len(output['accepted_canary_pair_ids'])}, "
        f"failed_canary={len(output['failed_canary_pair_ids'])}, "
        f"batch={output['batch_pair_count']}, output={args.output}"
    )


if __name__ == "__main__":
    main()
