"""Carry a completed review only when compacting non-semantic target fields."""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

SEMANTIC_OUTPUT_FIELDS = (
    "schema_version",
    "scope",
    "assessment",
    "assessment_basis",
    "findings",
)
REVIEW_FIELDS = (
    "review_status",
    "operator_label_error",
    "operator_evidence_error",
    "checks",
    "reviewer",
    "review_method",
)


def carry_compact_review(
    baseline: Sequence[Mapping[str, Any]],
    candidate: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Return reviewed candidate rows after strict semantic-equivalence checks."""
    baseline_by_id = _unique_by_id(baseline, "baseline")
    candidate_by_id = _unique_by_id(candidate, "candidate")
    if set(baseline_by_id) != set(candidate_by_id):
        raise ValueError("baseline and candidate review ids do not match")

    carried: list[dict[str, Any]] = []
    for row in candidate:
        record_id = str(row["id"])
        previous = baseline_by_id[record_id]
        for field in ("code", "private_label", "target_cwe"):
            if previous.get(field) != row.get(field):
                raise ValueError(f"{record_id}: reviewed {field} changed")
        previous_output = _required_output(previous, record_id, "baseline")
        candidate_output = _required_output(row, record_id, "candidate")
        for field in SEMANTIC_OUTPUT_FIELDS:
            if previous_output.get(field) != candidate_output.get(field):
                raise ValueError(f"{record_id}: semantic output field changed: {field}")
        if (
            previous.get("review_status") != "pass"
            or previous.get("operator_label_error") is not False
            or previous.get("operator_evidence_error") is not False
        ):
            raise ValueError(f"{record_id}: baseline review is not reusable")
        limitations = candidate_output.get("limitations")
        if (
            not isinstance(limitations, list)
            or not limitations
            or any(
                "reviewed boundary includes" in str(item).lower()
                for item in limitations
            )
        ):
            raise ValueError(f"{record_id}: candidate limitations are not compact")

        reviewed = dict(row)
        for field in REVIEW_FIELDS:
            reviewed[field] = previous.get(field)
        reviewed["notes"] = (
            "Carried forward after exact code, label, scope, assessment, "
            "assessment_basis, and findings equality; only non-semantic "
            "limitations/recommendations were compacted."
        )
        carried.append(reviewed)
    return carried


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-review", type=Path, required=True)
    parser.add_argument("--candidate-review", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    carried = carry_compact_review(
        _load_jsonl(args.baseline_review),
        _load_jsonl(args.candidate_review),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    _write_jsonl(carried, args.output)
    print(
        f"Compact target review carried: records={len(carried)}, output={args.output}"
    )


def _required_output(
    row: Mapping[str, Any],
    record_id: str,
    name: str,
) -> Mapping[str, Any]:
    output = row.get("expected_output")
    if not isinstance(output, Mapping):
        raise ValueError(f"{record_id}: {name} expected_output is missing")
    return output


def _unique_by_id(
    rows: Sequence[Mapping[str, Any]],
    name: str,
) -> dict[str, Mapping[str, Any]]:
    indexed: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        record_id = str(row.get("id") or "")
        if not record_id or record_id in indexed:
            raise ValueError(f"{name} review contains a missing or duplicate id")
        indexed[record_id] = row
    return indexed


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _write_jsonl(rows: Sequence[Mapping[str, Any]], path: Path) -> None:
    path.write_text(
        "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
