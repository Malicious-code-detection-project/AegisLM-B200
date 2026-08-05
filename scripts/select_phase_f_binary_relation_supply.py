"""Select the exact binary pair supply using observable pseudo-C relations."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.datasets.binary import (  # noqa: E402
    binary_target_relation_visible,
)
from aegislm.datasets.phase_f import load_jsonl  # noqa: E402

VARIANTS = ("gcc-O0", "gcc-O2", "clang-O0", "clang-O2")


def select_relation_supply(
    old_gate: Mapping[str, Any],
    old_records: Sequence[Mapping[str, Any]],
    recovery_queue: Mapping[str, Any],
    recovery_reviews: Sequence[Mapping[str, Any]],
    *,
    required_pairs: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Select exact pairs in frozen queue order without weakening evidence."""
    old_relations = _old_relations(old_gate, old_records)
    recovery_relations = _recovery_relations(recovery_reviews)
    old_order = [str(value) for value in old_gate["accepted_pair_ids"]]
    recovery_order = [str(row["pair_id"]) for row in recovery_queue["candidates"]]
    overlap = set(old_order) & set(recovery_order)
    if overlap:
        raise ValueError("old and recovery pair supplies overlap")
    eligible_order = [
        pair_id
        for pair_id in [*old_order, *recovery_order]
        if old_relations.get(pair_id) or recovery_relations.get(pair_id)
    ]
    if len(eligible_order) < required_pairs:
        raise ValueError(
            f"observable relation supply is {len(eligible_order)}, "
            f"below required {required_pairs}"
        )
    accepted = eligible_order[:required_pairs]
    reserve = eligible_order[required_pairs:]
    qualified_variants = {
        pair_id: list(old_relations.get(pair_id) or recovery_relations[pair_id])
        for pair_id in eligible_order
    }
    accepted_variants = {pair_id: qualified_variants[pair_id] for pair_id in accepted}
    old_ids = [pair_id for pair_id in accepted if pair_id in old_relations]
    recovery_ids = [pair_id for pair_id in accepted if pair_id in recovery_relations]
    cwes = _pair_cwes(old_gate, old_records, recovery_reviews)
    accepted_cwes = Counter(cwes[pair_id] for pair_id in accepted)
    full_variant_pairs = sum(
        set(accepted_variants[pair_id]) == set(VARIANTS) for pair_id in accepted
    )
    final_gate = {
        "schema_version": "aegislm.phase-f-binary-relation-gate.v1",
        "profile": "phase-f-binary-derived-v1",
        "decision": "pass",
        "gate_pass": True,
        "target_relation_policy": "observable-target-relation-v1",
        "required_accepted_pair_count": required_pairs,
        "accepted_pair_count": len(accepted),
        "accepted_pair_ids": accepted,
        "accepted_pair_variants": accepted_variants,
        "existing_pair_ids": old_ids,
        "recovery_pair_ids": recovery_ids,
        "qualified_pair_count": len(eligible_order),
        "qualified_pair_ids": eligible_order,
        "qualified_pair_variants": qualified_variants,
        "qualified_reserve_pair_count": len(reserve),
        "qualified_reserve_pair_ids": reserve,
        "full_four_variant_pair_count": full_variant_pairs,
        "compiler_consistency_supply_pass": full_variant_pairs >= 100,
        "accepted_cwe_pair_counts": dict(sorted(accepted_cwes.items())),
        "raw_object_execution_count": 0,
        "selection_policy": (
            "frozen old accepted order followed by frozen recovery queue order"
        ),
    }
    qualified_recovery_ids = [
        pair_id for pair_id in eligible_order if pair_id in recovery_relations
    ]
    recovery_gate = {
        "schema_version": "aegislm.phase-f-binary-relation-recovery-gate.v1",
        "profile": "phase-f-binary-derived-v1",
        "decision": "pass",
        "gate_pass": True,
        "target_relation_policy": "observable-target-relation-v1",
        "required_accepted_pair_count": len(qualified_recovery_ids),
        "accepted_pair_count": len(qualified_recovery_ids),
        "accepted_pair_ids": qualified_recovery_ids,
        "accepted_pair_variants": {
            pair_id: qualified_variants[pair_id] for pair_id in qualified_recovery_ids
        },
        "raw_object_execution_count": 0,
    }
    return final_gate, recovery_gate


def _old_relations(
    old_gate: Mapping[str, Any],
    records: Sequence[Mapping[str, Any]],
) -> dict[str, tuple[str, ...]]:
    groups: dict[str, dict[str, Mapping[str, Any]]] = defaultdict(dict)
    for record in records:
        group_id = str(record["metadata"]["compiler_group_id"])
        variant = (
            f"{record['artifact']['compiler']}-{record['artifact']['optimization']}"
        )
        groups[group_id][variant] = record
    result: dict[str, tuple[str, ...]] = {}
    for pair_id_value in old_gate["accepted_pair_ids"]:
        pair_id = str(pair_id_value)
        labels = {}
        for label in ("present", "not_observed"):
            opaque = hashlib.sha256(f"{pair_id}:{label}".encode()).hexdigest()[:16]
            labels[label] = groups.get(f"binary-group-{opaque}", {})
        eligible = []
        for variant in VARIANTS:
            present = labels["present"].get(variant)
            fixed = labels["not_observed"].get(variant)
            if present is None or fixed is None:
                continue
            present_pseudo = str(present["analysis"]["functions"][0]["pseudo_c"])
            fixed_pseudo = str(fixed["analysis"]["functions"][0]["pseudo_c"])
            target_cwe = str(present["task"]["target_cwe"])
            if (
                present_pseudo.strip() != fixed_pseudo.strip()
                and binary_target_relation_visible(target_cwe, present_pseudo)
            ):
                eligible.append(variant)
        if eligible:
            result[pair_id] = tuple(eligible)
    return result


def _recovery_relations(
    reviews: Sequence[Mapping[str, Any]],
) -> dict[str, tuple[str, ...]]:
    by_pair: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for review in reviews:
        by_pair[str(review["pair_id"])].append(review)
    result: dict[str, tuple[str, ...]] = {}
    for pair_id, rows in by_pair.items():
        eligible = []
        for row in rows:
            variant = f"{row['compiler']}-{row['optimization']}"
            present = str(row["present_pseudo_c"])
            fixed = str(row["not_observed_pseudo_c"])
            if present.strip() != fixed.strip() and binary_target_relation_visible(
                str(row["target_cwe"]), present
            ):
                eligible.append(variant)
        ordered = tuple(variant for variant in VARIANTS if variant in eligible)
        if ordered:
            result[pair_id] = ordered
    return result


def _pair_cwes(
    old_gate: Mapping[str, Any],
    old_records: Sequence[Mapping[str, Any]],
    recovery_reviews: Sequence[Mapping[str, Any]],
) -> dict[str, str]:
    cwes: dict[str, str] = {}
    group_cwes = {
        str(record["metadata"]["compiler_group_id"]): str(record["task"]["target_cwe"])
        for record in old_records
    }
    for record in old_records:
        group_id = str(record["metadata"]["compiler_group_id"])
        # Group IDs are opaque; pair CWEs are filled by the caller-facing record
        # maps below, so retaining this lookup only validates consistency.
        if group_cwes[group_id] != str(record["task"]["target_cwe"]):
            raise ValueError(f"inconsistent target CWE in {group_id}")
    for review in recovery_reviews:
        pair_id = str(review["pair_id"])
        cwe = str(review["target_cwe"])
        previous = cwes.setdefault(pair_id, cwe)
        if previous != cwe:
            raise ValueError(f"inconsistent recovery CWE: {pair_id}")
    # Old pair IDs cannot be reversed from opaque group IDs. The source gate
    # carries their order, so reconstruct their CWE through both label hashes.
    for pair_id_value in old_gate["accepted_pair_ids"]:
        pair_id = str(pair_id_value)
        opaque = hashlib.sha256(f"{pair_id}:present".encode()).hexdigest()[:16]
        group_id = f"binary-group-{opaque}"
        if group_id not in group_cwes:
            raise ValueError(f"missing old pair CWE: {pair_id}")
        cwes[pair_id] = group_cwes[group_id]
    return cwes


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old-gate", type=Path, required=True)
    parser.add_argument("--old-records", type=Path, required=True)
    parser.add_argument(
        "--recovery-queue",
        type=Path,
        action="append",
        required=True,
    )
    parser.add_argument(
        "--recovery-review",
        type=Path,
        action="append",
        required=True,
    )
    parser.add_argument("--required-pairs", type=int, default=2450)
    parser.add_argument("--output-gate", type=Path, required=True)
    parser.add_argument("--output-recovery-gate", type=Path, required=True)
    args = parser.parse_args()
    old_gate = _load_object(args.old_gate)
    old_records = load_jsonl(args.old_records)
    recovery_queues = [_load_object(path) for path in args.recovery_queue]
    recovery_queue = {
        "candidates": [row for queue in recovery_queues for row in queue["candidates"]]
    }
    recovery_reviews = [
        row for path in args.recovery_review for row in load_jsonl(path)
    ]
    final_gate, recovery_gate = select_relation_supply(
        old_gate,
        old_records,
        recovery_queue,
        recovery_reviews,
        required_pairs=args.required_pairs,
    )
    source_hashes: dict[str, Any] = {
        "old_gate": _sha256(args.old_gate),
        "old_records": _sha256(args.old_records),
        "recovery_queues": {str(path): _sha256(path) for path in args.recovery_queue},
        "recovery_reviews": {str(path): _sha256(path) for path in args.recovery_review},
    }
    final_gate["source_sha256"] = source_hashes
    recovery_gate["source_sha256"] = source_hashes
    _write_json(args.output_gate, final_gate)
    _write_json(args.output_recovery_gate, recovery_gate)
    print(
        "Phase F binary relation supply: "
        f"accepted={final_gate['accepted_pair_count']}, "
        f"existing={len(final_gate['existing_pair_ids'])}, "
        f"recovery={len(final_gate['recovery_pair_ids'])}, "
        f"reserve={final_gate['qualified_reserve_pair_count']}"
    )


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain an object")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
