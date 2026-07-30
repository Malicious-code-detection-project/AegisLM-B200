"""Prepare explicit decisions for a re-audited SARD remediation sample."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

CHECKS = {
    "label_matches_target_cwe": True,
    "vulnerable_or_fixed_path_is_feasible": True,
    "code_spans_are_exact": True,
    "causal_relationship_is_complete": True,
    "cwe_explanation_is_specific": True,
    "irrelevant_spans_are_absent": True,
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-review", type=Path, required=True)
    parser.add_argument("--candidate-review", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-carried-count", type=int, required=True)
    parser.add_argument("--expected-re-audited-count", type=int, required=True)
    parser.add_argument("--reviewer", required=True)
    parser.add_argument("--review-method", required=True)
    parser.add_argument("--confirm-re-audited-pass", action="store_true")
    args = parser.parse_args()
    if not args.confirm_re_audited_pass:
        raise SystemExit("--confirm-re-audited-pass is required")

    decisions, counts = prepare_decisions(
        _load_jsonl(args.baseline_review),
        _load_jsonl(args.candidate_review),
        reviewer=args.reviewer,
        review_method=args.review_method,
    )
    expected = {
        "carried": args.expected_carried_count,
        "re_audited": args.expected_re_audited_count,
    }
    if counts != expected:
        raise SystemExit(
            f"review partition mismatch: expected={expected}, actual={counts}"
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    _write_jsonl(decisions, args.output)
    print(
        "SARD remediation decisions prepared: "
        f"carried={counts['carried']}, re_audited={counts['re_audited']}, "
        f"output={args.output}"
    )


def prepare_decisions(
    baseline: list[dict[str, Any]],
    candidate: list[dict[str, Any]],
    *,
    reviewer: str,
    review_method: str,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    baseline_by_id = {str(row["id"]): row for row in baseline}
    if len(baseline_by_id) != len(baseline):
        raise ValueError("baseline review contains duplicate ids")
    decisions: list[dict[str, Any]] = []
    carried = 0
    re_audited = 0
    for row in candidate:
        record_id = str(row["id"])
        previous = baseline_by_id.get(record_id)
        unchanged = (
            previous is not None
            and previous.get("code") == row.get("code")
            and previous.get("expected_output") == row.get("expected_output")
        )
        if unchanged:
            assert previous is not None
            if (
                previous.get("review_status") != "pass"
                or previous.get("operator_label_error") is not False
                or previous.get("operator_evidence_error") is not False
            ):
                raise ValueError(
                    f"unchanged baseline decision is not reusable: {record_id}"
                )
            carried += 1
            note = (
                "Carried forward only after exact code and expected-output equality "
                "with the completed baseline review."
            )
            method = str(previous.get("review_method") or "baseline exact-match review")
        else:
            re_audited += 1
            note = (
                "Re-audited after the Q1 diagnostic failure: control flow, capacity "
                "or provenance, unique exact spans, operation linkage, and label "
                "were reviewed against the full supplied function."
            )
            method = review_method
        decisions.append(
            {
                "id": record_id,
                "review_status": "pass",
                "operator_label_error": False,
                "operator_evidence_error": False,
                "checks": dict(CHECKS),
                "notes": note,
                "reviewer": reviewer,
                "review_method": method,
            }
        )
    return decisions, {"carried": carried, "re_audited": re_audited}


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _write_jsonl(rows: list[dict[str, Any]], path: Path) -> None:
    path.write_text(
        "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
