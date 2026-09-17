"""Select the next bounded relation-recovery batch from the frozen F7 queue."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any


def build_recovery_queue(
    source: Mapping[str, Any],
    exclusions: Sequence[Mapping[str, Any]],
    *,
    batch_pairs: int,
    round_id: str,
) -> dict[str, Any]:
    """Preserve source order and exclude every previously reviewed candidate."""
    if batch_pairs <= 0:
        raise ValueError("batch_pairs must be positive")
    excluded: set[str] = set()
    for manifest in exclusions:
        for key in (
            "accepted_canary_pair_ids",
            "failed_canary_pair_ids",
            "accepted_pair_ids",
            "qualified_pair_ids",
        ):
            values = manifest.get(key, [])
            if isinstance(values, list):
                excluded.update(str(value) for value in values)
        candidates = manifest.get("candidates", [])
        if isinstance(candidates, list):
            excluded.update(str(row["pair_id"]) for row in candidates)
    remaining = [
        row for row in source["candidates"] if str(row["pair_id"]) not in excluded
    ]
    if len(remaining) < batch_pairs:
        raise ValueError(
            f"remaining candidate supply {len(remaining)} is below {batch_pairs}"
        )
    selected = []
    for rank, row in enumerate(remaining[:batch_pairs], start=1):
        selected.append(
            {
                **row,
                "queue": "primary",
                "queue_rank": rank,
                "disposition": f"relation_recovery_{round_id}_pending",
            }
        )
    return {
        "schema_version": "aegislm.phase-f-binary-recovery-queue.v2",
        "profile": source["profile"],
        "seed": source["seed"],
        "source_split": source.get("source_split", "train"),
        "batch_pair_count": len(selected),
        "excluded_pair_count": len(excluded),
        "remaining_pair_count_before_selection": len(remaining),
        "remaining_pair_count_after_selection": len(remaining) - len(selected),
        "round_id": round_id,
        "policy": source["policy"],
        "metrics": source["metrics"],
        "structural_rejections": source.get("structural_rejections", []),
        "candidates": selected,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-queue", type=Path, required=True)
    parser.add_argument(
        "--exclude-manifest",
        type=Path,
        action="append",
        required=True,
    )
    parser.add_argument("--batch-pairs", type=int, required=True)
    parser.add_argument("--round-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = json.loads(args.source_queue.read_text(encoding="utf-8"))
    exclusions = [
        json.loads(path.read_text(encoding="utf-8")) for path in args.exclude_manifest
    ]
    output = build_recovery_queue(
        source,
        exclusions,
        batch_pairs=args.batch_pairs,
        round_id=args.round_id,
    )
    output["source_queue_sha256"] = _sha256(args.source_queue)
    output["exclusion_sha256"] = {
        str(path): _sha256(path) for path in args.exclude_manifest
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Phase F binary relation recovery queue: "
        f"selected={output['batch_pair_count']}, "
        f"excluded={output['excluded_pair_count']}, "
        f"remaining={output['remaining_pair_count_after_selection']}"
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    main()
