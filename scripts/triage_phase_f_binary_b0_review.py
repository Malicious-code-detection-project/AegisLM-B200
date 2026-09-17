"""Triage B0 pseudo-C for mandatory operator review; never auto-approve pairs."""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

_CALL = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_CONTROL = {"if", "for", "while", "switch", "sizeof", "return"}
_SECURITY_OPERATIONS = {
    "accept",
    "alloca",
    "bind",
    "calloc",
    "close",
    "connect",
    "delete",
    "fclose",
    "fopen",
    "free",
    "fscanf",
    "getenv",
    "listen",
    "malloc",
    "memcpy",
    "memmove",
    "memset",
    "new",
    "open",
    "pclose",
    "popen",
    "putenv",
    "read",
    "realloc",
    "recv",
    "socket",
    "strcat",
    "strcpy",
    "strncat",
    "strncpy",
    "system",
    "wcsncat",
    "wcscat",
    "wcscpy",
}


def triage_review(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Flag evidence loss and compiler divergence without deciding labels."""
    baselines: dict[tuple[str, str, str], int] = {}
    for entry in entries:
        for label, field in (
            ("present", "present_pseudo_c"),
            ("not_observed", "not_observed_pseudo_c"),
        ):
            if entry["optimization"] == "O0":
                baselines[(entry["pair_id"], entry["compiler"], label)] = _body_size(
                    entry[field]
                )

    cases: list[dict[str, Any]] = []
    pair_flags: dict[str, set[str]] = defaultdict(set)
    for entry in entries:
        source_ops = _operations(entry["source_annotation_excerpt"])
        present_ops = _operations(entry["present_pseudo_c"])
        negative_ops = _operations(entry["not_observed_pseudo_c"])
        present_size = _body_size(entry["present_pseudo_c"])
        negative_size = _body_size(entry["not_observed_pseudo_c"])
        flags: list[str] = []
        if present_size < 120:
            flags.append("present_body_too_short")
        if negative_size < 120:
            flags.append("not_observed_body_too_short")
        if source_ops and not (source_ops & (present_ops | negative_ops)):
            flags.append("source_operation_not_recovered")
        if entry["optimization"] == "O2":
            present_o0 = baselines.get(
                (entry["pair_id"], entry["compiler"], "present"), 0
            )
            negative_o0 = baselines.get(
                (entry["pair_id"], entry["compiler"], "not_observed"), 0
            )
            if present_o0 and present_size / present_o0 < 0.15:
                flags.append("present_o2_evidence_collapse")
            if negative_o0 and negative_size / negative_o0 < 0.15:
                flags.append("not_observed_o2_evidence_collapse")
        if "Unresolved local var" in entry["present_pseudo_c"] and present_size < 300:
            flags.append("present_unresolved_and_short")
        if (
            "Unresolved local var" in entry["not_observed_pseudo_c"]
            and negative_size < 300
        ):
            flags.append("not_observed_unresolved_and_short")
        pair_flags[str(entry["pair_id"])].update(flags)
        cases.append(
            {
                "pair_id": entry["pair_id"],
                "target_cwe": entry["target_cwe"],
                "compiler": entry["compiler"],
                "optimization": entry["optimization"],
                "present_body_size": present_size,
                "not_observed_body_size": negative_size,
                "source_operations": sorted(source_ops),
                "present_operations": sorted(present_ops),
                "not_observed_operations": sorted(negative_ops),
                "flags": flags,
                "operator_review_required": bool(flags),
            }
        )
    flagged_pairs = sorted(pair for pair, flags in pair_flags.items() if flags)
    return {
        "schema_version": "aegislm.phase-f-binary-b0-review-triage.v1",
        "policy": {
            "automatic_pair_approval": False,
            "flagged_variants": "mandatory operator review",
            "unflagged_variants": "still require explicit pair decision",
        },
        "variant_count": len(cases),
        "flagged_variant_count": sum(
            bool(case["operator_review_required"]) for case in cases
        ),
        "pair_count": len(pair_flags),
        "flagged_pair_count": len(flagged_pairs),
        "flagged_pair_ids": flagged_pairs,
        "pair_flags": {
            pair: sorted(flags) for pair, flags in sorted(pair_flags.items())
        },
        "cases": cases,
    }


def _body_size(text: str) -> int:
    return len(
        "".join(
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("/*")
        )
    )


def _operations(text: str) -> set[str]:
    calls = {name.lower() for name in _CALL.findall(text)}
    return (calls - _CONTROL) & _SECURITY_OPERATIONS


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review-jsonl", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    entries = [
        json.loads(line)
        for line in args.review_jsonl.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    result = triage_review(entries)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Phase F binary B0 review triage: "
        f"flagged_variants={result['flagged_variant_count']}/"
        f"{result['variant_count']}, "
        f"flagged_pairs={result['flagged_pair_count']}/{result['pair_count']}"
    )


if __name__ == "__main__":
    main()
