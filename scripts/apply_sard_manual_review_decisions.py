"""Apply explicit human or agent decisions to a SARD manual-review JSONL."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

CHECK_NAMES = {
    "label_matches_target_cwe",
    "vulnerable_or_fixed_path_is_feasible",
    "code_spans_are_exact",
    "causal_relationship_is_complete",
    "cwe_explanation_is_specific",
    "irrelevant_spans_are_absent",
}
REVIEW_STATUSES = {
    "pass",
    "evidence_error",
    "label_and_evidence_error",
    "uncertain",
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review", type=Path, required=True)
    parser.add_argument("--decisions", type=Path, required=True)
    args = parser.parse_args()

    rows = _load_jsonl(args.review)
    decisions = _load_jsonl(args.decisions)
    updated = _apply_decisions(rows, decisions)
    temporary = args.review.with_suffix(args.review.suffix + ".tmp")
    _write_jsonl(updated, temporary)
    temporary.replace(args.review)
    print(f"Applied {len(decisions)} decisions to {args.review}")


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number}: object required")
            rows.append(value)
    return rows


def _write_jsonl(rows: list[dict[str, Any]], path: Path) -> None:
    path.write_text(
        "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows
        ),
        encoding="utf-8",
    )


def _apply_decisions(
    rows: list[dict[str, Any]],
    decisions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    row_by_id = {str(row.get("id")): row for row in rows}
    if len(row_by_id) != len(rows):
        raise ValueError("review rows contain duplicate or missing ids")
    seen: set[str] = set()
    for decision in decisions:
        record_id = str(decision.get("id") or "")
        if record_id in seen:
            raise ValueError(f"duplicate decision id: {record_id}")
        seen.add(record_id)
        if record_id not in row_by_id:
            raise ValueError(f"unknown decision id: {record_id}")
        _validate_decision(decision)
        row = row_by_id[record_id]
        for field in (
            "review_status",
            "operator_label_error",
            "operator_evidence_error",
            "checks",
            "notes",
        ):
            row[field] = decision[field]
        row["reviewer"] = decision.get("reviewer")
        row["review_method"] = decision.get("review_method")
    return rows


def _validate_decision(decision: dict[str, Any]) -> None:
    status = decision.get("review_status")
    if status not in REVIEW_STATUSES:
        raise ValueError(f"invalid review_status: {status}")
    label_error = decision.get("operator_label_error")
    evidence_error = decision.get("operator_evidence_error")
    if not isinstance(label_error, bool) or not isinstance(evidence_error, bool):
        raise ValueError("operator decisions must be boolean")
    expected = {
        "pass": (False, False),
        "evidence_error": (False, True),
        "label_and_evidence_error": (True, True),
        "uncertain": (True, True),
    }[status]
    if (label_error, evidence_error) != expected:
        raise ValueError(f"{status} is inconsistent with operator decisions")
    checks = decision.get("checks")
    if not isinstance(checks, dict) or set(checks) != CHECK_NAMES:
        raise ValueError("decision checks must contain the complete rubric")
    if not all(isinstance(value, bool) for value in checks.values()):
        raise ValueError("decision checks must be boolean")
    if status == "pass" and not all(checks.values()):
        raise ValueError("pass requires every rubric check")
    if not isinstance(decision.get("notes"), str):
        raise ValueError("notes must be a string")


if __name__ == "__main__":
    main()
