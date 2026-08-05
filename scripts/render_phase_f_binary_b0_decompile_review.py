"""Render a private operator workbook for B0 target-preservation review."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.run_phase_f_binary_b0_decompile_canary import (  # noqa: E402
    parse_function_manifest,
)


def annotated_source_excerpt(source: str, *, radius: int = 3) -> str:
    """Return bounded source lines around Juliet FLAW/FIX annotations."""
    lines = source.splitlines()
    selected: set[int] = set()
    for index, line in enumerate(lines):
        if "FLAW" in line or "FIX" in line:
            selected.update(
                range(max(0, index - radius), min(len(lines), index + radius + 1))
            )
    return "\n".join(f"{index + 1:04d}: {lines[index]}" for index in sorted(selected))


def build_review(
    *,
    compile_root: Path,
    decompile_root: Path,
) -> list[dict[str, Any]]:
    """Join private source annotations with decompiled compiler variants."""
    compile_summary = json.loads(
        (compile_root / "compile-summary.json").read_text(encoding="utf-8")
    )
    entries: list[dict[str, Any]] = []
    for item in compile_summary["results"]:
        if not bool(item["compile_success"]):
            continue
        pair_id = str(item["pair_id"])
        variant = f"{item['compiler']}-{item['optimization']}"
        source_path = compile_root / "extracted" / str(item["archive_path"])
        pseudo_dir = decompile_root / "pseudo-c" / pair_id / variant
        functions = parse_function_manifest(pseudo_dir / "functions.tsv")
        by_label: dict[str, list[str]] = {
            "present": [],
            "not_observed": [],
        }
        for function in functions:
            if function["completed"].lower() != "true":
                continue
            pseudo_path = pseudo_dir / function["output_file"]
            by_label[function["label"]].append(
                pseudo_path.read_text(encoding="utf-8", errors="replace").strip()
            )
        entries.append(
            {
                "pair_id": pair_id,
                "target_cwe": item["target_cwe"],
                "compiler": item["compiler"],
                "optimization": item["optimization"],
                "private_source_path": item["archive_path"],
                "source_annotation_excerpt": annotated_source_excerpt(
                    source_path.read_text(encoding="utf-8", errors="replace")
                ),
                "present_pseudo_c": "\n\n".join(by_label["present"]),
                "not_observed_pseudo_c": "\n\n".join(by_label["not_observed"]),
                "operator_present_semantics_preserved": None,
                "operator_not_observed_semantics_preserved": None,
                "operator_pair_distinction_preserved": None,
                "operator_evidence_notes": "",
                "operator_decision": "pending",
            }
        )
    return entries


def render_markdown(entries: list[dict[str, Any]]) -> str:
    """Render review entries without implying that pending fields passed."""
    lines = [
        "# Phase F Binary B0 Target-Preservation Review",
        "",
        "> Private operator artifact. Provenance and labels in this file must not be "
        "sent to the model.",
        "",
    ]
    for index, entry in enumerate(entries, start=1):
        lines.extend(
            [
                f"## {index}. {entry['pair_id']} — {entry['target_cwe']} "
                f"{entry['compiler']}-{entry['optimization']}",
                "",
                f"- Decision: `{entry['operator_decision']}`",
                f"- Source: `{entry['private_source_path']}`",
                "",
                "### Source annotation excerpt",
                "",
                "```c",
                entry["source_annotation_excerpt"],
                "```",
                "",
                "### Decompiled present path",
                "",
                "```c",
                entry["present_pseudo_c"],
                "```",
                "",
                "### Decompiled not_observed path",
                "",
                "```c",
                entry["not_observed_pseudo_c"],
                "```",
                "",
                "### Operator fields",
                "",
                "- present semantics preserved: `null`",
                "- not_observed semantics preserved: `null`",
                "- pair distinction preserved: `null`",
                "- notes:",
                "",
            ]
        )
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compile-root", type=Path, required=True)
    parser.add_argument("--decompile-root", type=Path, required=True)
    parser.add_argument("--output-jsonl", type=Path, required=True)
    parser.add_argument("--output-markdown", type=Path, required=True)
    args = parser.parse_args()
    entries = build_review(
        compile_root=args.compile_root,
        decompile_root=args.decompile_root,
    )
    args.output_jsonl.parent.mkdir(parents=True, exist_ok=True)
    args.output_jsonl.write_text(
        "".join(
            json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n"
            for entry in entries
        ),
        encoding="utf-8",
    )
    args.output_markdown.write_text(
        render_markdown(entries),
        encoding="utf-8",
    )
    print(
        f"Phase F binary review workbook: entries={len(entries)}, "
        f"jsonl={args.output_jsonl}, markdown={args.output_markdown}"
    )


if __name__ == "__main__":
    main()
