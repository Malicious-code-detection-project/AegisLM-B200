"""Promote deterministic reserve pairs after a failed B0 preservation canary."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def build_replacement_queue(
    queue: dict[str, Any],
    review: dict[str, Any],
    *,
    excluded_pair_ids: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Select one reserve replacement for every failed reviewed pair."""
    failed = sorted(
        pair_id
        for pair_id, passed in review["pair_decisions"].items()
        if not bool(passed)
    )
    accepted = sorted(
        pair_id for pair_id, passed in review["pair_decisions"].items() if bool(passed)
    )
    reserve = sorted(
        (
            row
            for row in queue["candidates"]
            if row["queue"] == "reserve"
            and str(row["pair_id"]) not in excluded_pair_ids
        ),
        key=lambda row: int(row["queue_rank"]),
    )
    if len(reserve) < len(failed):
        raise ValueError("reserve supply is smaller than failed pair count")
    replacements: list[dict[str, Any]] = []
    for rank, candidate in enumerate(reserve[: len(failed)], start=1):
        replacements.append(
            {
                **candidate,
                "queue": "primary",
                "queue_rank": rank,
                "disposition": "replacement_pending_target_preservation_audit",
                "replaces_failed_pair_id": failed[rank - 1],
            }
        )
    return {
        "schema_version": "aegislm.phase-f-binary-b0-replacement-queue.v1",
        "profile": queue["profile"],
        "seed": queue["seed"],
        "source_queue_sha256": None,
        "review_scope": review["scope"],
        "accepted_pair_ids": accepted,
        "failed_pair_ids": failed,
        "excluded_previous_replacement_pair_ids": sorted(excluded_pair_ids),
        "replacement_count": len(replacements),
        "candidates": replacements,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queue", type=Path, required=True)
    parser.add_argument("--review-summary", type=Path, required=True)
    parser.add_argument(
        "--exclude-queue",
        type=Path,
        action="append",
        default=[],
        help="Previously materialized replacement queue; may be repeated.",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    queue = json.loads(args.queue.read_text(encoding="utf-8"))
    review = json.loads(args.review_summary.read_text(encoding="utf-8"))
    excluded_pair_ids: set[str] = set()
    for path in args.exclude_queue:
        previous = json.loads(path.read_text(encoding="utf-8"))
        excluded_pair_ids.update(str(row["pair_id"]) for row in previous["candidates"])
    output = build_replacement_queue(
        queue,
        review,
        excluded_pair_ids=frozenset(excluded_pair_ids),
    )
    output["source_queue_sha256"] = _sha256_file(args.queue)
    args.output.write_text(
        json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Phase F binary replacement queue: "
        f"accepted={len(output['accepted_pair_ids'])}, "
        f"failed={len(output['failed_pair_ids'])}, "
        f"replacements={output['replacement_count']}, output={args.output}"
    )


def _sha256_file(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    main()
