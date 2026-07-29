"""Audit Phase F source targets with the real Qwen tokenizer and no truncation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> None:
    """Run the F2 target-quality and tokenizer audit."""
    from transformers import AutoTokenizer

    from aegislm.datasets.phase_f import read_parquet
    from aegislm.datasets.source import (
        derive_patch_findings,
        phase_f_record_to_source_record,
    )
    from aegislm.datasets.source_audit import audit_source_targets
    from aegislm.evaluation.harness import load_jsonl

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-root", type=Path, required=True)
    parser.add_argument("--model-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cutoff-len", type=int, default=2048)
    args = parser.parse_args()

    if not args.model_dir.exists():
        parser.error(f"tokenizer/model path does not exist: {args.model_dir}")
    manifest_path = args.dataset_root / "selected_manifest.parquet"
    if not manifest_path.exists():
        parser.error(f"selected manifest does not exist: {manifest_path}")

    records = []
    for name in ("train.jsonl", "validation.jsonl", "challenge.jsonl"):
        path = args.dataset_root / name
        if not path.exists():
            parser.error(f"materialized split does not exist: {path}")
        records.extend(load_jsonl(path))
    manifest = read_parquet(manifest_path)
    cross_records = []
    for path in sorted((args.dataset_root / "cross_dataset").glob("*/challenge.jsonl")):
        cross_records.extend(load_jsonl(path))
    records.extend(cross_records)
    findings_by_id = _cross_dataset_findings(
        cross_records,
        manifest,
        phase_f_record_to_source_record=phase_f_record_to_source_record,
        derive_patch_findings=derive_patch_findings,
    )
    tokenizer = AutoTokenizer.from_pretrained(
        args.model_dir,
        local_files_only=True,
        trust_remote_code=True,
    )
    summary = audit_source_targets(
        records,
        manifest,
        tokenizer=tokenizer,
        cutoff_len=args.cutoff_len,
        grounded_findings_by_id=findings_by_id,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Phase F source target audit complete: "
        f"status={summary['status']}, "
        f"eligible={summary['metrics']['eligible_count']}, "
        f"excluded={summary['metrics']['excluded_count']}, "
        f"tokenized={summary['metrics']['tokenized_sequence_count']}, "
        f"output={args.output}"
    )


def _cross_dataset_findings(
    records: list[dict],
    manifest: list[dict],
    *,
    phase_f_record_to_source_record: Any,
    derive_patch_findings: Any,
) -> dict[str, list[dict[str, str]]]:
    convert = phase_f_record_to_source_record
    derive = derive_patch_findings
    record_by_id = {str(record["id"]): record for record in records}
    rows_by_group: dict[str, list[dict]] = {}
    for row in manifest:
        if row.get("materialization") == "cross_dataset_test":
            rows_by_group.setdefault(str(row["group_id"]), []).append(row)
    findings: dict[str, list[dict[str, str]]] = {}
    for rows in rows_by_group.values():
        before = next(
            (row for row in rows if row.get("pair_type") == "vulnerable_before"),
            None,
        )
        after = next(
            (row for row in rows if row.get("pair_type") == "fixed_after"),
            None,
        )
        if before is None or after is None:
            continue
        before_record = record_by_id.get(str(before["record_id"]))
        after_record = record_by_id.get(str(after["record_id"]))
        if before_record is None or after_record is None:
            continue
        normalized_before = convert(before_record, before)
        normalized_after = convert(after_record, after)
        findings[str(before["record_id"])] = derive(
            str(normalized_before["code"]["text"]),
            str(normalized_after["code"]["text"]),
        )
    return findings


if __name__ == "__main__":
    main()
