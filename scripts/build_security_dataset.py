"""Build AegisLM canonical records from existing security datasets."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aegislm.datasets.security_builder import (  # noqa: E402
    bigvul_to_aegislm_record,
    cybersecurity_qa_to_aegislm_record,
    diversevul_to_aegislm_record,
    load_ctf_writeup_records,
    load_legacy_alpaca_json,
    load_source_corpus_records,
    load_zip_source_records,
    reached_record_limit,
    SKIPPABLE_RECORD_ERRORS,
    split_records,
    write_jsonl,
    write_split_jsonl,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build safe AegisLM records before LLaMA-Factory export."
    )
    parser.add_argument(
        "--legacy-alpaca", help="Existing instruction/input/output JSON or JSONL."
    )
    parser.add_argument("--local-source-dir", help="Local source corpus directory.")
    parser.add_argument(
        "--include-hf",
        action="store_true",
        help="Load the default HF set: Cybersecurity QA, DiverseVul, and BigVul.",
    )
    parser.add_argument(
        "--include-cybersecurity-qa",
        action="store_true",
        help="Load public Cybersecurity QA from Hugging Face.",
    )
    parser.add_argument(
        "--include-diversevul",
        action="store_true",
        help="Load bstee615/diversevul from Hugging Face.",
    )
    parser.add_argument(
        "--include-bigvul",
        action="store_true",
        help="Load DynaOuchebara/BigVul from Hugging Face.",
    )
    parser.add_argument(
        "--ctf-writeups-dir", help="Local CTF Markdown write-up corpus."
    )
    parser.add_argument("--zip-source-dir", help="Directory containing ZIP archives.")
    parser.add_argument(
        "--zip-extract-dir",
        default="data/extracted/security_archives",
        help="Safe extraction directory for --zip-source-dir archives.",
    )
    parser.add_argument(
        "--max-per-source",
        type=int,
        default=3000,
        help="Maximum converted records per source. Use -1 for all records.",
    )
    parser.add_argument(
        "--split", default="train", choices=["train", "validation", "test", "fixture"]
    )
    parser.add_argument("--output", help="Output AegisLM JSONL path for fixed split.")
    parser.add_argument(
        "--output-dir",
        help="Write train/validation/test files into this directory.",
    )
    parser.add_argument(
        "--split-ratios",
        default="0.8,0.1,0.1",
        help="Comma-separated train,validation,test ratios for --output-dir.",
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--manifest-output",
        help="Dataset manifest path. Defaults to <output-dir>/dataset_manifest.json.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    records = []
    source_stats: dict[str, dict[str, Any]] = {}

    if args.legacy_alpaca:
        records.extend(load_legacy_alpaca_json(args.legacy_alpaca, split=args.split))

    if args.local_source_dir:
        source_records = load_source_corpus_records(
            args.local_source_dir,
            max_records=args.max_per_source,
            split=args.split,
        )
        records.extend(source_records)
        print(f"Loaded {len(source_records)} local source records.")

    if args.ctf_writeups_dir:
        ctf_records = load_ctf_writeup_records(
            args.ctf_writeups_dir,
            max_records=args.max_per_source,
            split=args.split,
        )
        records.extend(ctf_records)
        print(f"Loaded {len(ctf_records)} CTF write-up records.")

    if args.zip_source_dir:
        zip_records = load_zip_source_records(
            args.zip_source_dir,
            zip_extract_dir=args.zip_extract_dir,
            max_records=args.max_per_source,
            split=args.split,
        )
        records.extend(zip_records)
        print(f"Loaded {len(zip_records)} ZIP source records.")

    include_qa, include_diversevul, include_bigvul = _resolve_hf_includes(args)
    if include_qa or include_diversevul or include_bigvul:
        hf_records = _load_hf_dataset_records(
            max_per_source=args.max_per_source,
            split=args.split,
            include_cybersecurity_qa=include_qa,
            include_diversevul=include_diversevul,
            include_bigvul=include_bigvul,
            source_stats=source_stats,
        )
        records.extend(hf_records)

    if args.output_dir:
        train_ratio, validation_ratio, test_ratio = _parse_split_ratios(
            args.split_ratios
        )
        split_map = split_records(
            records,
            train_ratio=train_ratio,
            validation_ratio=validation_ratio,
            test_ratio=test_ratio,
            seed=args.seed,
        )
        paths = write_split_jsonl(split_map, args.output_dir)
        for split_name, path in paths.items():
            print(f"Wrote {len(split_map[split_name])} {split_name} records to {path}")
        manifest_path = (
            Path(args.manifest_output)
            if args.manifest_output
            else Path(args.output_dir) / "dataset_manifest.json"
        )
        _write_dataset_manifest(
            manifest_path,
            paths=paths,
            split_map=split_map,
            source_stats=source_stats,
            seed=args.seed,
            split_ratios=(train_ratio, validation_ratio, test_ratio),
            max_per_source=args.max_per_source,
            local_ctf_available=bool(args.ctf_writeups_dir),
            local_zip_available=bool(args.zip_source_dir),
        )
        print(f"Wrote dataset manifest to {manifest_path}")
        return

    if not args.output:
        raise SystemExit("Either --output or --output-dir is required.")

    write_jsonl(records, args.output)
    print(f"Wrote {len(records)} AegisLM records to {args.output}")


def _load_hf_dataset_records(
    *,
    max_per_source: int,
    split: str,
    include_cybersecurity_qa: bool,
    include_diversevul: bool,
    include_bigvul: bool,
    source_stats: dict[str, dict[str, Any]] | None = None,
) -> list[dict]:
    try:
        from datasets import load_dataset
    except ImportError as exc:
        raise SystemExit("Install datasets to use --include-hf.") from exc

    records = []
    stats = source_stats if source_stats is not None else {}
    revisions = {
        dataset_id: _resolve_dataset_revision(dataset_id)
        for dataset_id, enabled in (
            ("rezaduty/cybersecurity-qa-v2", include_cybersecurity_qa),
            ("Rowden/CybersecurityQAA", include_cybersecurity_qa),
            ("bstee615/diversevul", include_diversevul),
            ("DynaOuchebara/BigVul", include_bigvul),
        )
        if enabled
    }

    if include_cybersecurity_qa:
        qa_records, qa_source, qa_skipped = _load_cybersecurity_qa_records(
            load_dataset,
            max_per_source,
            split,
            revisions=revisions,
        )
        records.extend(qa_records)
        stats[qa_source] = {
            "revision": revisions.get(qa_source),
            "converted": len(qa_records),
            "skipped": qa_skipped,
            "status": "included",
        }
        print(f"Loaded {len(qa_records)} Cybersecurity QA records.")

    if include_diversevul:
        diversevul_records = []
        skipped = 0
        diversevul = load_dataset(
            "bstee615/diversevul",
            split="train",
            revision=revisions.get("bstee615/diversevul"),
        )
        for index, row in enumerate(diversevul):
            if reached_record_limit(diversevul_records, max_per_source):
                break
            try:
                record = diversevul_to_aegislm_record(row, index=index, split=split)
            except SKIPPABLE_RECORD_ERRORS as exc:
                skipped += 1
                _print_skip("DiverseVul", index, exc, skipped)
                continue
            if record:
                diversevul_records.append(record)
        records.extend(diversevul_records)
        stats["bstee615/diversevul"] = {
            "revision": revisions.get("bstee615/diversevul"),
            "converted": len(diversevul_records),
            "skipped": skipped,
            "status": "included",
        }
        print(
            f"Loaded {len(diversevul_records)} DiverseVul records (skipped {skipped})."
        )

    if include_bigvul:
        bigvul_records = []
        skipped = 0
        bigvul = load_dataset(
            "DynaOuchebara/BigVul",
            split="train",
            revision=revisions.get("DynaOuchebara/BigVul"),
        )
        for index, row in enumerate(bigvul):
            if reached_record_limit(bigvul_records, max_per_source):
                break
            try:
                record = bigvul_to_aegislm_record(row, index=index, split=split)
            except SKIPPABLE_RECORD_ERRORS as exc:
                skipped += 1
                _print_skip("BigVul", index, exc, skipped)
                continue
            if record:
                bigvul_records.append(record)
        records.extend(bigvul_records)
        stats["DynaOuchebara/BigVul"] = {
            "revision": revisions.get("DynaOuchebara/BigVul"),
            "converted": len(bigvul_records),
            "skipped": skipped,
            "status": "included",
        }
        print(f"Loaded {len(bigvul_records)} BigVul records (skipped {skipped}).")

    return records


def _load_cybersecurity_qa_records(
    load_dataset,
    max_per_source: int,
    split: str,
    *,
    revisions: dict[str, str | None] | None = None,
) -> tuple[list[dict], str, int]:
    revisions = revisions or {}
    try:
        records, skipped = _load_rezaduty_cybersecurity_qa_jsonl(
            max_per_source,
            split,
            revision=revisions.get("rezaduty/cybersecurity-qa-v2"),
            return_skipped=True,
        )
        if records:
            return records, "rezaduty/cybersecurity-qa-v2", skipped
    except Exception as exc:  # pragma: no cover - network/service dependent
        print(f"Failed to load rezaduty/cybersecurity-qa-v2 JSONL: {exc}")

    dataset_names = ("Rowden/CybersecurityQAA",)
    last_error = None
    for dataset_name in dataset_names:
        try:
            dataset = load_dataset(
                dataset_name,
                split="train",
                revision=revisions.get(dataset_name),
            )
        except Exception as exc:  # pragma: no cover - network/service dependent
            last_error = exc
            print(f"Failed to load {dataset_name}: {exc}")
            continue

        records = []
        skipped = 0
        for index, row in enumerate(dataset):
            if reached_record_limit(records, max_per_source):
                break
            try:
                record = cybersecurity_qa_to_aegislm_record(
                    row,
                    index=index,
                    split=split,
                    dataset_name=dataset_name,
                )
            except SKIPPABLE_RECORD_ERRORS as exc:
                skipped += 1
                _print_skip(dataset_name, index, exc, skipped)
                continue
            if record:
                records.append(record)
        if skipped:
            print(f"Skipped {skipped} {dataset_name} records during conversion.")
        return records, dataset_name, skipped

    raise SystemExit(f"Failed to load Cybersecurity QA datasets: {last_error}")


def _load_rezaduty_cybersecurity_qa_jsonl(
    max_per_source: int,
    split: str,
    *,
    revision: str | None = None,
    return_skipped: bool = False,
) -> list[dict] | tuple[list[dict], int]:
    try:
        from huggingface_hub import hf_hub_download
    except ImportError as exc:
        raise SystemExit("Install huggingface_hub to load rezaduty JSONL.") from exc

    path = hf_hub_download(
        repo_id="rezaduty/cybersecurity-qa-v2",
        repo_type="dataset",
        filename="cybersecurity_interview_qa_complete.jsonl",
        revision=revision,
    )

    records = []
    skipped = 0
    with Path(path).open(encoding="utf-8") as f:
        for index, line in enumerate(f):
            if reached_record_limit(records, max_per_source):
                break
            if not line.strip():
                continue
            try:
                row = json.loads(line)
                record = cybersecurity_qa_to_aegislm_record(
                    row,
                    index=index,
                    split=split,
                    dataset_name="rezaduty/cybersecurity-qa-v2",
                )
            except (json.JSONDecodeError, *SKIPPABLE_RECORD_ERRORS) as exc:
                skipped += 1
                _print_skip("rezaduty/cybersecurity-qa-v2", index, exc, skipped)
                continue
            if record:
                records.append(record)

    print(
        f"Loaded {len(records)} rezaduty/cybersecurity-qa-v2 JSONL records"
        f" (skipped {skipped})."
    )
    if return_skipped:
        return records, skipped
    return records


def _resolve_dataset_revision(dataset_id: str) -> str | None:
    try:
        from huggingface_hub import HfApi

        return (
            HfApi(token=os.environ.get("HF_TOKEN") or None).dataset_info(dataset_id).sha
        )
    except Exception as exc:  # pragma: no cover - network/service dependent
        print(f"WARN: could not resolve revision for {dataset_id}: {exc}")
        return None


def _write_dataset_manifest(
    path: Path,
    *,
    paths: dict[str, Path],
    split_map: dict[str, list[dict]],
    source_stats: dict[str, dict[str, Any]],
    seed: int,
    split_ratios: tuple[float, float, float],
    max_per_source: int,
    local_ctf_available: bool,
    local_zip_available: bool,
) -> None:
    files = {}
    for split_name, file_path in paths.items():
        files[split_name] = {
            "path": str(file_path),
            "records": len(split_map[split_name]),
            "bytes": file_path.stat().st_size,
            "sha256": _sha256(file_path),
        }
    manifest = {
        "profile": "hf-full-v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "seed": seed,
        "split_ratios": list(split_ratios),
        "max_per_source": "all" if max_per_source < 0 else max_per_source,
        "sources": source_stats,
        "local_sources": {
            "ctf_writeups": "available" if local_ctf_available else "not_available",
            "zip_corpus": "available" if local_zip_available else "not_available",
        },
        "files": files,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _resolve_hf_includes(args: argparse.Namespace) -> tuple[bool, bool, bool]:
    return (
        bool(args.include_hf or args.include_cybersecurity_qa),
        bool(args.include_hf or args.include_diversevul),
        bool(args.include_hf or args.include_bigvul),
    )


def _print_skip(source_name: str, index: int, exc: Exception, skipped: int) -> None:
    if skipped <= 5 or skipped % 100 == 0:
        print(f"Skipped {source_name} row {index}: {exc}")


def _parse_split_ratios(raw_value: str) -> tuple[float, float, float]:
    parts = [part.strip() for part in raw_value.split(",")]
    if len(parts) != 3:
        raise SystemExit("--split-ratios must have exactly three numbers.")
    try:
        train_ratio, validation_ratio, test_ratio = (float(part) for part in parts)
    except ValueError as exc:
        raise SystemExit("--split-ratios values must be numbers.") from exc
    return train_ratio, validation_ratio, test_ratio


if __name__ == "__main__":
    main()
