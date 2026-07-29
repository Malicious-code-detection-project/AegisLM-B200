"""Render a SARD manual-review JSONL as a readable Markdown workbook."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()

    rows = _load_jsonl(args.input)
    if args.limit is not None:
        rows = rows[: args.limit]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(_render(rows), encoding="utf-8")
    print(f"Rendered {len(rows)} review cases to {args.output}")


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


def _render(rows: list[dict[str, Any]]) -> str:
    labels = Counter(str(row.get("private_label")) for row in rows)
    cwes = Counter(str(row.get("target_cwe")) for row in rows)
    statuses = Counter(str(row.get("review_status")) for row in rows)
    lines = [
        "# SARD Source Manual Review",
        "",
        f"- Cases: `{len(rows)}`",
        f"- Labels: `{dict(sorted(labels.items()))}`",
        f"- CWE count: `{len(cwes)}`",
        f"- Review statuses: `{dict(sorted(statuses.items()))}`",
        "- Rubric: `docs/SOURCE_MANUAL_REVIEW_RUBRIC.md`",
        "",
        "## Decision checklist",
        "",
        "1. target CWE와 label이 코드에 맞는가?",
        "2. 위험 또는 방어 경로가 supplied function에서 성립하는가?",
        "3. 모든 code span이 정확하고 의미 있는가?",
        "4. source/setup–guard–sink/effect 관계가 완성됐는가?",
        "5. 설명이 target CWE에 구체적인가?",
        "",
    ]
    for index, row in enumerate(rows, 1):
        output = row.get("expected_output") or {}
        lines.extend(
            [
                f"## {index}. {row.get('id')}",
                "",
                f"- Target: `{row.get('target_cwe')}`",
                f"- Private label: `{row.get('private_label')}`",
                f"- Review status: `{row.get('review_status')}`",
                f"- Label error: `{row.get('operator_label_error')}`",
                f"- Evidence error: `{row.get('operator_evidence_error')}`",
                f"- Reviewer: `{row.get('reviewer')}`",
                f"- Review method: `{row.get('review_method')}`",
                "",
                "### Rubric checks",
                "",
                *_render_checks(row.get("checks")),
                "",
                "### Code",
                "",
                "```cpp",
                str(row.get("code") or ""),
                "```",
                "",
                "### Assessment basis",
                "",
                "```json",
                json.dumps(
                    output.get("assessment_basis"),
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                ),
                "```",
                "",
                "### Findings",
                "",
                "```json",
                json.dumps(
                    output.get("findings"),
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                ),
                "```",
                "",
                f"### Notes\n\n{row.get('notes') or ''}",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def _render_checks(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return ["- `checks`: not recorded"]
    lines: list[str] = []
    for name, decision in value.items():
        marker = "x" if decision is True else " " if decision is False else "-"
        lines.append(f"- [{marker}] `{name}`: `{decision}`")
    return lines


if __name__ == "__main__":
    main()
