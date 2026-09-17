"""Select a deterministic, CWE-stratified audit queue for Phase F binary B0."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.datasets.phase_f import read_parquet  # noqa: E402

SCHEMA_VERSION = "aegislm.phase-f-binary-b0-candidate-manifest.v1"
DEFAULT_SEED = 20260728
_UNSUPPORTED_PLATFORM = re.compile(r"(?:w32|windows)", re.IGNORECASE)
_NONPORTABLE_LINUX_WIDE_FILE_API = re.compile(
    (
        r"(?:wchar_t_environment_(?:ifstream|ofstream|open)|"
        r"wchar_t_[^/]*_(?:open|fopen)_)"
    ),
    re.IGNORECASE,
)


def select_candidates(
    rows: Sequence[Mapping[str, Any]],
    *,
    seed: int = DEFAULT_SEED,
    split: str = "train",
    primary_pairs: int = 100,
    reserve_pairs: int = 50,
) -> dict[str, Any]:
    """Build a deterministic audit queue without claiming target preservation."""
    if primary_pairs < 0 or reserve_pairs < 0:
        raise ValueError("pair quotas must be non-negative")

    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        if str(row.get("split")) == split:
            grouped[str(row.get("group_id", ""))].append(row)

    eligible: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    for group_id, group in sorted(grouped.items()):
        candidate, reason = _build_pair(group_id, group, seed=seed)
        if candidate is None:
            rejected.append(
                {
                    "group_id": group_id,
                    "disposition": "reject",
                    "reason": reason,
                }
            )
        else:
            eligible.append(candidate)

    ordered = _stratified_order(eligible, seed=seed)
    required = primary_pairs + reserve_pairs
    selected = ordered[:required]
    for index, candidate in enumerate(selected):
        candidate["queue"] = "primary" if index < primary_pairs else "reserve"
        candidate["queue_rank"] = (
            index + 1 if index < primary_pairs else index - primary_pairs + 1
        )
        candidate["disposition"] = "pending_target_preservation_audit"

    primary = selected[:primary_pairs]
    reserve = selected[primary_pairs:]
    cwe_counts = Counter(str(row["target_cwe"]) for row in primary)
    supply_pass = len(primary) == primary_pairs and len(reserve) == reserve_pairs
    return {
        "schema_version": SCHEMA_VERSION,
        "profile": "phase-f-binary-b0-v1",
        "seed": seed,
        "source_split": split,
        "policy": {
            "selection_unit": "source_group_with_one_present_and_one_not_observed",
            "ordering": "deterministic_cwe_round_robin",
            "target_preservation": (
                "pending; compile/decompile evidence is required before approval"
            ),
            "raw_binary_execution": "forbidden",
            "model_visible_metadata": "none from this manifest",
        },
        "metrics": {
            "input_rows": len(rows),
            "split_group_count": len(grouped),
            "structurally_eligible_pair_count": len(eligible),
            "rejected_pair_count": len(rejected),
            "primary_pair_count": len(primary),
            "reserve_pair_count": len(reserve),
            "primary_cwe_count": len(cwe_counts),
            "primary_cwe_counts": dict(sorted(cwe_counts.items())),
            "maximum_primary_cwe_fraction": (
                max(cwe_counts.values(), default=0) / len(primary) if primary else 0.0
            ),
            "supply_pass": supply_pass,
        },
        "candidates": selected,
        "structural_rejections": rejected,
    }


def _build_pair(
    group_id: str,
    rows: Sequence[Mapping[str, Any]],
    *,
    seed: int,
) -> tuple[dict[str, Any] | None, str]:
    if not group_id:
        return None, "missing_group_id"
    if len(rows) != 2:
        return None, "pair_must_contain_exactly_two_records"
    labels = Counter(str(row.get("label")) for row in rows)
    if labels != Counter({"present": 1, "not_observed": 1}):
        return None, "pair_must_have_one_present_and_one_not_observed"
    if any(str(row.get("disposition")) != "eligible" for row in rows):
        return None, "source_record_not_eligible"
    if any(bool(row.get("contains_executable_payload")) for row in rows):
        return None, "source_manifest_contains_executable_payload"
    cwes = {str(row.get("cwe")) for row in rows}
    paths = {str(row.get("archive_path")) for row in rows}
    source_hashes = {str(row.get("source_sha256")) for row in rows}
    code_hashes = {str(row.get("code_sha256")) for row in rows}
    if len(cwes) != 1 or "" in cwes:
        return None, "pair_cwe_mismatch"
    if len(paths) != 1 or "" in paths:
        return None, "pair_archive_path_mismatch"
    archive_path = next(iter(paths))
    if _UNSUPPORTED_PLATFORM.search(archive_path):
        return None, "windows_specific_source_excluded_from_linux_b0"
    if _NONPORTABLE_LINUX_WIDE_FILE_API.search(archive_path):
        return None, "nonportable_wide_file_api_excluded_from_linux_b0"
    if len(source_hashes) != 1 or "" in source_hashes:
        return None, "pair_source_hash_mismatch"
    if len(code_hashes) != 2 or "" in code_hashes:
        return None, "pair_code_hashes_must_be_distinct"

    by_label = {str(row["label"]): row for row in rows}
    pair_id = hashlib.sha256(f"phase-f-b0:{group_id}".encode()).hexdigest()[:16]
    return (
        {
            "pair_id": pair_id,
            "group_id": group_id,
            "target_cwe": next(iter(cwes)),
            "archive_path": archive_path,
            "source_sha256": next(iter(source_hashes)),
            "present_record_id": str(by_label["present"]["record_id"]),
            "not_observed_record_id": str(by_label["not_observed"]["record_id"]),
            "present_code_sha256": str(by_label["present"]["code_sha256"]),
            "not_observed_code_sha256": str(by_label["not_observed"]["code_sha256"]),
            "selection_hash": hashlib.sha256(f"{seed}:{group_id}".encode()).hexdigest(),
            "target_preservation_audit": {
                "status": "pending",
                "gcc_o0": None,
                "gcc_o2": None,
                "clang_o0": None,
                "clang_o2": None,
                "operator_notes": "",
            },
        },
        "eligible",
    )


def _stratified_order(
    candidates: Sequence[dict[str, Any]],
    *,
    seed: int,
) -> list[dict[str, Any]]:
    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for candidate in candidates:
        buckets[str(candidate["target_cwe"])].append(candidate)
    for values in buckets.values():
        values.sort(key=lambda item: str(item["selection_hash"]))
    cwe_order = sorted(
        buckets,
        key=lambda cwe: hashlib.sha256(f"{seed}:{cwe}".encode()).hexdigest(),
    )
    ordered: list[dict[str, Any]] = []
    while any(buckets.values()):
        for cwe in cwe_order:
            if buckets[cwe]:
                ordered.append(buckets[cwe].pop(0))
    return ordered


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--split", default="train")
    parser.add_argument("--primary-pairs", type=int, default=100)
    parser.add_argument("--reserve-pairs", type=int, default=50)
    args = parser.parse_args()
    result = select_candidates(
        read_parquet(args.input),
        seed=args.seed,
        split=args.split,
        primary_pairs=args.primary_pairs,
        reserve_pairs=args.reserve_pairs,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    metrics = result["metrics"]
    print(
        "Phase F binary B0 candidate queue: "
        f"primary={metrics['primary_pair_count']}, "
        f"reserve={metrics['reserve_pair_count']}, "
        f"cwes={metrics['primary_cwe_count']}, "
        f"supply={'PASS' if metrics['supply_pass'] else 'FAIL'}, "
        f"output={args.output}"
    )
    if not metrics["supply_pass"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
