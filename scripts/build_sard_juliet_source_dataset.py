"""Build the grounded Phase F source profile from the SARD Juliet C/C++ ZIP."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

OFFICIAL_ARCHIVE_SHA256 = (
    "ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb"
)


def main() -> None:
    from transformers import AutoTokenizer

    from aegislm.datasets.phase_f import write_jsonl, write_parquet
    from aegislm.datasets.sard_juliet import (
        SARD_JULIET_SEED,
        extract_juliet_functions,
        materialize_juliet_profile,
    )

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--tokenizer", required=True)
    parser.add_argument(
        "--profile",
        default="phase-f-sard-grounded-v2",
        help="Immutable profile identifier written to the dataset manifest.",
    )
    parser.add_argument("--seed", type=int, default=SARD_JULIET_SEED)
    parser.add_argument("--cutoff-len", type=int, default=2048)
    parser.add_argument("--train-pairs", type=int, default=5000)
    parser.add_argument("--validation-pairs", type=int, default=500)
    parser.add_argument("--test-pairs", type=int, default=250)
    parser.add_argument(
        "--exclude-manifest",
        type=Path,
        action="append",
        default=[],
        help=(
            "Parquet manifest whose group_id and code_sha256 values must be "
            "excluded. May be repeated."
        ),
    )
    parser.add_argument(
        "--evaluation-only",
        action="store_true",
        help=(
            "Build a frozen test-only artifact. Requires zero train and "
            "validation pairs and does not emit a manual review answer sheet."
        ),
    )
    parser.add_argument(
        "--expected-archive-sha256",
        default=OFFICIAL_ARCHIVE_SHA256,
        help="Set to an empty string only for a locally curated test archive.",
    )
    args = parser.parse_args()

    archive_hash = _sha256_file(args.archive)
    if args.expected_archive_sha256 and archive_hash != args.expected_archive_sha256:
        raise SystemExit(
            "archive SHA-256 mismatch: "
            f"expected={args.expected_archive_sha256}, actual={archive_hash}"
        )
    tokenizer = AutoTokenizer.from_pretrained(
        args.tokenizer,
        trust_remote_code=True,
    )
    functions, catalog = extract_juliet_functions(args.archive)
    from aegislm.datasets.phase_f import read_parquet

    excluded_group_ids: set[str] = set()
    excluded_code_hashes: set[str] = set()
    exclusion_inputs = []
    for path in args.exclude_manifest:
        resolved = path.resolve()
        rows = read_parquet(resolved)
        group_ids = {
            str(row["group_id"]) for row in rows if isinstance(row.get("group_id"), str)
        }
        code_hashes = {
            str(row["code_sha256"])
            for row in rows
            if isinstance(row.get("code_sha256"), str)
        }
        excluded_group_ids.update(group_ids)
        excluded_code_hashes.update(code_hashes)
        exclusion_inputs.append(
            {
                "path": str(resolved),
                "sha256": _sha256_file(resolved),
                "row_count": len(rows),
                "group_count": len(group_ids),
                "code_hash_count": len(code_hashes),
            }
        )
    profile = materialize_juliet_profile(
        functions,
        tokenizer=tokenizer,
        profile=args.profile,
        seed=args.seed,
        cutoff_len=args.cutoff_len,
        train_pairs=args.train_pairs,
        validation_pairs=args.validation_pairs,
        test_pairs=args.test_pairs,
        excluded_group_ids=frozenset(excluded_group_ids),
        excluded_code_hashes=frozenset(excluded_code_hashes),
        evaluation_only=args.evaluation_only,
    )
    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    write_parquet(catalog, output_dir / "raw_catalog.parquet")
    write_parquet(profile["manifest"], output_dir / "eligible_manifest.parquet")
    quarantined = [row for row in catalog if row["disposition"] != "eligible"]
    if quarantined:
        write_parquet(quarantined, output_dir / "quarantine_manifest.parquet")
    write_jsonl(profile["canonical_records"], output_dir / "private" / "records.jsonl")
    write_jsonl(profile["records"]["train"], output_dir / "train.jsonl")
    write_jsonl(profile["records"]["validation"], output_dir / "validation.jsonl")
    test_rows = profile["records"]["test"]
    challenge = [
        {"id": row["id"], "messages": row["messages"][:2]} for row in test_rows
    ]
    gold = [
        {
            "id": row["id"],
            "expected_output": json.loads(row["messages"][2]["content"]),
        }
        for row in test_rows
    ]
    write_jsonl(challenge, output_dir / "challenge.jsonl")
    write_jsonl(gold, output_dir / "gold.jsonl")
    canonical_by_id = {row["id"]: row for row in profile["canonical_records"]}
    materialized_by_id = {
        row["id"]: row
        for split_rows in profile["records"].values()
        for row in split_rows
    }
    if not args.evaluation_only:
        sampled_manifest = []
        for label in ("present", "not_observed"):
            label_rows = [row for row in profile["manifest"] if row["label"] == label]
            sampled_manifest.extend(
                sorted(
                    label_rows,
                    key=lambda row: hashlib.sha256(
                        f"{args.seed}:manual:{row['record_id']}".encode()
                    ).hexdigest(),
                )[:50]
            )
        manual_rows = []
        for row in sampled_manifest:
            record_id = row["record_id"]
            canonical = canonical_by_id[record_id]
            materialized = materialized_by_id[record_id]
            manual_rows.append(
                {
                    "id": record_id,
                    "target_cwe": canonical["task"]["target_cwe"],
                    "code": canonical["code"]["text"],
                    "private_label": canonical["metadata"]["label"],
                    "expected_output": json.loads(
                        materialized["messages"][2]["content"]
                    ),
                    "operator_label_error": None,
                    "operator_evidence_error": None,
                    "review_status": None,
                    "checks": {
                        "label_matches_target_cwe": None,
                        "vulnerable_or_fixed_path_is_feasible": None,
                        "code_spans_are_exact": None,
                        "causal_relationship_is_complete": None,
                        "cwe_explanation_is_specific": None,
                        "irrelevant_spans_are_absent": None,
                    },
                    "notes": "",
                }
            )
        write_jsonl(manual_rows, output_dir / "manual_review_100.jsonl")

    summary = {
        key: value
        for key, value in profile.items()
        if key not in {"records", "manifest", "canonical_records"}
    }
    summary["archive"] = {
        "external_path": str(args.archive.resolve()),
        "sha256": archive_hash,
        "payload_stored_in_dataset": False,
    }
    summary["exclusion_inputs"] = exclusion_inputs
    summary_path = output_dir / "dataset_manifest.json"
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _write_hashes(output_dir)
    print(
        "SARD Juliet source profile complete: "
        f"status={profile['status']}, "
        f"pairs={profile['eligible_record_count'] // 2}, "
        f"available={profile['available_complete_pairs']}, "
        f"output={output_dir}"
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_hashes(output_dir: Path) -> None:
    files = sorted(
        path
        for path in output_dir.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    )
    lines = [
        f"{_sha256_file(path)}  {path.relative_to(output_dir).as_posix()}"
        for path in files
    ]
    (output_dir / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
