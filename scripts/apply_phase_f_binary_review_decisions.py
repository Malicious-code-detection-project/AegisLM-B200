"""Apply hash-bound operator decisions to the binary manual-review artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.datasets.phase_f import load_jsonl, write_jsonl  # noqa: E402


def apply_decisions(
    rows: list[dict[str, Any]],
    decision_set: dict[str, Any],
    *,
    review_sha256: str,
) -> list[dict[str, Any]]:
    """Apply explicit decisions while preserving unreviewed rows for early stop."""
    if decision_set.get("review_artifact_sha256") != review_sha256:
        raise ValueError("decision set does not match the review artifact SHA-256")
    indexed = {str(row["id"]): dict(row) for row in rows}
    default_decision = decision_set.get("default_decision")
    if default_decision is not None:
        label_error, evidence_error, notes = _validate_decision_fields(
            default_decision,
            record_id="default_decision",
        )
        for row in indexed.values():
            row["operator_label_error"] = label_error
            row["operator_evidence_error"] = evidence_error
            row["notes"] = notes
    decisions = decision_set.get("decisions", [])
    if not isinstance(decisions, list):
        raise ValueError("decisions must be a list")
    if default_decision is None and not decisions:
        raise ValueError("decision set must contain at least one explicit decision")
    seen: set[str] = set()
    for decision in decisions:
        if not isinstance(decision, dict):
            raise ValueError("each decision must be an object")
        record_id = str(decision.get("id", ""))
        if record_id in seen:
            raise ValueError(f"duplicate decision ID: {record_id}")
        seen.add(record_id)
        if record_id not in indexed:
            raise ValueError(f"unknown review ID: {record_id}")
        label_error, evidence_error, notes = _validate_decision_fields(
            decision,
            record_id=record_id,
        )
        indexed[record_id]["operator_label_error"] = label_error
        indexed[record_id]["operator_evidence_error"] = evidence_error
        indexed[record_id]["notes"] = notes
    return [indexed[str(row["id"])] for row in rows]


def _validate_decision_fields(
    decision: dict[str, Any],
    *,
    record_id: str,
) -> tuple[bool, bool, str]:
    label_error = decision.get("operator_label_error")
    evidence_error = decision.get("operator_evidence_error")
    notes = decision.get("notes")
    if not isinstance(label_error, bool) or not isinstance(evidence_error, bool):
        raise ValueError(f"{record_id}: both error decisions must be boolean")
    if not isinstance(notes, str) or not notes.strip():
        raise ValueError(f"{record_id}: notes must record the review basis")
    return label_error, evidence_error, notes.strip()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review-jsonl", type=Path, required=True)
    parser.add_argument("--decisions-json", type=Path, required=True)
    args = parser.parse_args()
    rows = load_jsonl(args.review_jsonl)
    decisions = json.loads(args.decisions_json.read_text(encoding="utf-8"))
    updated = apply_decisions(
        rows,
        decisions,
        review_sha256=_sha256(args.review_jsonl),
    )
    write_jsonl(updated, args.review_jsonl)
    decided = sum(
        isinstance(row.get("operator_label_error"), bool)
        and isinstance(row.get("operator_evidence_error"), bool)
        for row in updated
    )
    errors = sum(
        bool(row.get("operator_label_error"))
        or bool(row.get("operator_evidence_error"))
        for row in updated
        if isinstance(row.get("operator_label_error"), bool)
        and isinstance(row.get("operator_evidence_error"), bool)
    )
    print(
        "Phase F binary review decisions applied: "
        f"decided={decided}/{len(updated)}, errors={errors}"
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    main()
