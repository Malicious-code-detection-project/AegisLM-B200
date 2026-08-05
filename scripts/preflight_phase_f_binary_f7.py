"""Evaluate F7 verified-pair supply and build a deterministic pilot queue."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
from typing import Any


def build_f7_preflight(
    queue: dict[str, Any],
    reviews: list[dict[str, Any]],
    *,
    required_dataset_pairs: int,
    pilot_pairs: int,
    z_score: float = 1.96,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Calculate conservative supply and select unreviewed pilot pairs."""
    if required_dataset_pairs <= 0 or pilot_pairs <= 0:
        raise ValueError("pair requirements must be positive")

    decisions: dict[str, bool] = {}
    for review in reviews:
        for pair_id, passed_value in review["pair_decisions"].items():
            pair_id = str(pair_id)
            passed = bool(passed_value)
            if pair_id in decisions:
                raise ValueError(f"duplicate reviewed pair: {pair_id}")
            decisions[pair_id] = passed

    candidates = queue["candidates"]
    by_id = {str(row["pair_id"]): row for row in candidates}
    missing = sorted(set(decisions) - set(by_id))
    if missing:
        raise ValueError(
            "reviewed pair missing from supply queue: " + ", ".join(missing)
        )

    reviewed = len(decisions)
    accepted = sum(decisions.values())
    rejected = reviewed - accepted
    structural_supply = len(candidates)
    remaining = structural_supply - reviewed
    additional_needed = max(required_dataset_pairs - accepted, 0)
    observed_rate = accepted / reviewed if reviewed else 0.0
    lower_rate = _wilson_lower(accepted, reviewed, z_score=z_score)
    projected_observed = (
        math.ceil(additional_needed / observed_rate)
        if additional_needed and observed_rate
        else 0
    )
    projected_lower = (
        math.ceil(additional_needed / lower_rate)
        if additional_needed and lower_rate
        else 0
    )
    supply_gate_pass = additional_needed == 0 or (
        lower_rate > 0 and projected_lower <= remaining
    )

    unreviewed = sorted(
        (row for row in candidates if str(row["pair_id"]) not in decisions),
        key=lambda row: int(row["queue_rank"]),
    )
    if len(unreviewed) < pilot_pairs:
        raise ValueError("unreviewed supply is smaller than the requested pilot")
    selected = [
        {
            **row,
            "queue": "pilot",
            "queue_rank": rank,
            "disposition": "f7_pilot_pending_target_preservation_audit",
        }
        for rank, row in enumerate(unreviewed[:pilot_pairs], start=1)
    ]
    preflight = {
        "schema_version": "aegislm.phase-f-binary-f7-preflight.v1",
        "profile": "phase-f-binary-derived-v1",
        "required_dataset_pairs": required_dataset_pairs,
        "structurally_eligible_pair_count": structural_supply,
        "reviewed_pair_count": reviewed,
        "accepted_pair_count": accepted,
        "rejected_pair_count": rejected,
        "remaining_structural_pair_count": remaining,
        "additional_accepted_pair_count_required": additional_needed,
        "observed_acceptance_rate": observed_rate,
        "wilson_z_score": z_score,
        "wilson_acceptance_rate_lower_bound": lower_rate,
        "projected_additional_reviews_at_observed_rate": projected_observed,
        "projected_additional_reviews_at_wilson_lower_bound": projected_lower,
        "supply_margin_at_wilson_lower_bound": remaining - projected_lower,
        "pilot_pair_count": pilot_pairs,
        "supply_gate_pass": supply_gate_pass,
        "decision": "pilot_authorized" if supply_gate_pass else "supply_blocked",
    }
    pilot = {
        "schema_version": "aegislm.phase-f-binary-f7-pilot-queue.v1",
        "profile": "phase-f-binary-derived-v1",
        "seed": queue["seed"],
        "required_dataset_pairs": required_dataset_pairs,
        "historical_reviewed_pair_ids": sorted(decisions),
        "historical_accepted_pair_ids": sorted(
            pair_id for pair_id, passed in decisions.items() if passed
        ),
        "historical_rejected_pair_ids": sorted(
            pair_id for pair_id, passed in decisions.items() if not passed
        ),
        "pilot_pair_count": pilot_pairs,
        "candidates": selected,
    }
    return preflight, pilot


def _wilson_lower(successes: int, total: int, *, z_score: float) -> float:
    if total <= 0:
        return 0.0
    rate = successes / total
    denominator = 1 + z_score**2 / total
    center = (rate + z_score**2 / (2 * total)) / denominator
    half_width = (
        z_score
        * math.sqrt(rate * (1 - rate) / total + z_score**2 / (4 * total**2))
        / denominator
    )
    return center - half_width


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queue", type=Path, required=True)
    parser.add_argument(
        "--review-summary",
        type=Path,
        action="append",
        required=True,
    )
    parser.add_argument("--required-dataset-pairs", type=int, default=2450)
    parser.add_argument("--pilot-pairs", type=int, default=250)
    parser.add_argument("--output-preflight", type=Path, required=True)
    parser.add_argument("--output-pilot", type=Path, required=True)
    args = parser.parse_args()
    queue = json.loads(args.queue.read_text(encoding="utf-8"))
    reviews = [
        json.loads(path.read_text(encoding="utf-8")) for path in args.review_summary
    ]
    preflight, pilot = build_f7_preflight(
        queue,
        reviews,
        required_dataset_pairs=args.required_dataset_pairs,
        pilot_pairs=args.pilot_pairs,
    )
    preflight["source_queue_sha256"] = _sha256_file(args.queue)
    preflight["review_summary_sha256"] = {
        str(path): _sha256_file(path) for path in args.review_summary
    }
    pilot["source_queue_sha256"] = _sha256_file(args.queue)
    args.output_preflight.parent.mkdir(parents=True, exist_ok=True)
    args.output_preflight.write_text(
        json.dumps(preflight, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    args.output_pilot.write_text(
        json.dumps(pilot, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Phase F binary F7 preflight: "
        f"accepted={preflight['accepted_pair_count']}, "
        f"remaining={preflight['remaining_structural_pair_count']}, "
        f"projected_lower={preflight['projected_additional_reviews_at_wilson_lower_bound']}, "
        f"decision={preflight['decision']}"
    )
    print(f"preflight_sha256={_sha256_file(args.output_preflight)}")
    print(f"pilot_sha256={_sha256_file(args.output_pilot)}")
    if not preflight["supply_gate_pass"]:
        raise SystemExit(2)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    main()
