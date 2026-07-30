"""Apply explicit operator decisions and finalize a B0 preservation review."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def finalize_review(
    entries: list[dict[str, Any]],
    decisions: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Require an explicit pair policy and produce variant/pair gate metrics."""
    policies = _expand_pair_policies(decisions)
    finalized: list[dict[str, Any]] = []
    seen_pairs: set[str] = set()
    for entry in entries:
        pair_id = str(entry["pair_id"])
        policy = policies.get(pair_id)
        if not isinstance(policy, dict):
            raise ValueError(f"missing review policy: {pair_id}")
        variant = f"{entry['compiler']}-{entry['optimization']}"
        override = policy.get("overrides", {}).get(variant)
        decision = override["decision"] if override is not None else policy["default"]
        if decision not in {"pass", "fail"}:
            raise ValueError(f"invalid decision for {pair_id}/{variant}")
        notes = override["notes"] if override is not None else policy["notes"]
        passed = decision == "pass"
        finalized.append(
            {
                **entry,
                "operator_present_semantics_preserved": passed,
                "operator_not_observed_semantics_preserved": passed,
                "operator_pair_distinction_preserved": passed,
                "operator_evidence_notes": notes,
                "operator_decision": decision,
            }
        )
        seen_pairs.add(pair_id)
    unused = sorted(set(policies) - seen_pairs)
    if unused:
        raise ValueError("unused review policies: " + ", ".join(unused))

    by_pair: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in finalized:
        by_pair[str(entry["pair_id"])].append(entry)
    pair_decisions = {
        pair_id: all(row["operator_decision"] == "pass" for row in rows)
        for pair_id, rows in by_pair.items()
    }
    variant_counts = Counter(row["operator_decision"] for row in finalized)
    pair_passed = sum(pair_decisions.values())
    required_rate = float(decisions["required_target_preservation_rate"])
    variant_rate = variant_counts["pass"] / len(finalized)
    pair_rate = pair_passed / len(pair_decisions)
    summary = {
        "schema_version": "aegislm.phase-f-binary-b0-review-summary.v1",
        "scope": decisions["review_scope"],
        "variant_count": len(finalized),
        "variant_target_preservation": {
            "passed": variant_counts["pass"],
            "failed": variant_counts["fail"],
            "rate": variant_rate,
        },
        "pair_count": len(pair_decisions),
        "pair_target_preservation": {
            "passed": pair_passed,
            "failed": len(pair_decisions) - pair_passed,
            "rate": pair_rate,
        },
        "pair_decisions": dict(sorted(pair_decisions.items())),
        "required_target_preservation_rate": required_rate,
        "target_preservation_gate_pass": pair_rate >= required_rate,
        "ready_for_b0_100_pair": pair_rate >= required_rate,
        "decision": (
            "pass" if pair_rate >= required_rate else "fail_replace_candidates"
        ),
    }
    return finalized, summary


def _expand_pair_policies(decisions: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Support the detailed v1 format and a compact, still-explicit v2 format."""
    if "pairs" in decisions:
        return decisions["pairs"]

    passed = decisions.get("pass_pair_ids")
    failed = decisions.get("failed_pairs")
    if not isinstance(passed, list) or not isinstance(failed, dict):
        raise ValueError(
            "decisions require either pairs or pass_pair_ids plus failed_pairs"
        )
    duplicate_ids = sorted(set(passed) & set(failed))
    if duplicate_ids:
        raise ValueError(
            "pair IDs cannot be both pass and fail: " + ", ".join(duplicate_ids)
        )
    pass_notes = decisions.get(
        "pass_notes",
        "Explicit operator review confirmed target preservation across all variants.",
    )
    policies = {
        str(pair_id): {
            "default": "pass",
            "notes": pass_notes,
        }
        for pair_id in passed
    }
    for pair_id, notes in failed.items():
        if not isinstance(notes, str) or not notes.strip():
            raise ValueError(f"failed pair requires review notes: {pair_id}")
        policies[str(pair_id)] = {
            "default": "fail",
            "notes": notes,
        }
    return policies


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review-jsonl", type=Path, required=True)
    parser.add_argument("--decisions", type=Path, required=True)
    parser.add_argument("--output-jsonl", type=Path, required=True)
    parser.add_argument("--output-summary", type=Path, required=True)
    args = parser.parse_args()
    entries = [
        json.loads(line)
        for line in args.review_jsonl.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    decisions = json.loads(args.decisions.read_text(encoding="utf-8"))
    finalized, summary = finalize_review(entries, decisions)
    args.output_jsonl.write_text(
        "".join(
            json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n"
            for entry in finalized
        ),
        encoding="utf-8",
    )
    args.output_summary.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Phase F binary target-preservation review: "
        f"variants={summary['variant_target_preservation']['passed']}/"
        f"{summary['variant_count']}, "
        f"pairs={summary['pair_target_preservation']['passed']}/"
        f"{summary['pair_count']}, decision={summary['decision']}"
    )
    print(f"summary_sha256={_sha256_file(args.output_summary)}")


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    main()
