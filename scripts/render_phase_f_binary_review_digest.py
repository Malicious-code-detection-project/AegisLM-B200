"""Render compact per-pair evidence for explicit binary target review."""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

_RELEVANT = re.compile(
    r"(?:FLAW|FIX|if\s*\(|while\s*\(|for\s*\(|malloc|calloc|realloc|"
    r"free|mem(?:cpy|move|set)|str(?:cpy|ncpy|cat|ncat|len)|wcs|open|"
    r"close|fopen|fclose|popen|system|new|delete|assert|print|return|"
    r"\b(?:data|length|size|count|index)\b)",
    re.IGNORECASE,
)
_NOISE = re.compile(
    r"(?:\[[0-9a-fx]+\]\s*=\s*['\"]?\\0|Unresolved local var)",
    re.IGNORECASE,
)


def build_digest(
    entries: list[dict[str, Any]],
    triage: dict[str, Any],
    *,
    maximum_lines: int = 18,
) -> list[dict[str, Any]]:
    """Compact four compiler variants without making an automatic decision."""
    by_pair: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in entries:
        by_pair[str(entry["pair_id"])].append(entry)
    pair_flags = triage.get("pair_flags", {})
    digest: list[dict[str, Any]] = []
    for pair_id, rows in sorted(by_pair.items()):
        first = rows[0]
        variants = []
        for row in sorted(
            rows,
            key=lambda item: (
                str(item["compiler"]),
                str(item["optimization"]),
            ),
        ):
            variants.append(
                {
                    "variant": f"{row['compiler']}-{row['optimization']}",
                    "present": relevant_lines(
                        str(row["present_pseudo_c"]),
                        maximum_lines=maximum_lines,
                    ),
                    "not_observed": relevant_lines(
                        str(row["not_observed_pseudo_c"]),
                        maximum_lines=maximum_lines,
                    ),
                }
            )
        digest.append(
            {
                "pair_id": pair_id,
                "target_cwe": first["target_cwe"],
                "private_source_path": first["private_source_path"],
                "triage_flags": pair_flags.get(pair_id, []),
                "source_evidence": relevant_lines(
                    str(first["source_annotation_excerpt"]),
                    maximum_lines=maximum_lines,
                ),
                "variants": variants,
                "operator_decision": "pending",
                "operator_notes": "",
            }
        )
    return digest


def relevant_lines(text: str, *, maximum_lines: int) -> list[str]:
    """Keep bounded semantic lines and discard bulk zero initialization."""
    values = [
        line.strip()
        for line in text.splitlines()
        if _RELEVANT.search(line) and not _NOISE.search(line)
    ]
    return values[-maximum_lines:]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review-jsonl", type=Path, required=True)
    parser.add_argument("--triage", type=Path, required=True)
    parser.add_argument("--output-jsonl", type=Path, required=True)
    parser.add_argument("--maximum-lines", type=int, default=18)
    args = parser.parse_args()
    entries = [
        json.loads(line)
        for line in args.review_jsonl.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    triage = json.loads(args.triage.read_text(encoding="utf-8"))
    digest = build_digest(
        entries,
        triage,
        maximum_lines=args.maximum_lines,
    )
    args.output_jsonl.write_text(
        "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in digest
        ),
        encoding="utf-8",
    )
    print(
        f"Phase F binary review digest: pairs={len(digest)}, output={args.output_jsonl}"
    )


if __name__ == "__main__":
    main()
