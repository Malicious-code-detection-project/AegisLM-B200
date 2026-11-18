"""Rebuild the approved Phase F dataset artifacts in one deterministic pipeline.

This module is the dataset-build entry point.  It deliberately does not download
data, create symlinks, or bypass the manual source-review gate.  Public/raw input
is supplied by the operator, automatic catalog materialization runs first, and an
approved F2 artifact is then promoted into the remediated source-v4 and decision-v2
artifacts used by training.

Run with::

    python -m aegislm.datasets.rebuild_pipeline \
        --approved-f2-root data/processed/phase-f-sard-grounded-v3 \
        --tokenizer model/base/qwen3-coder-next \
        --output-root data/processed/rebuild-20260728

The tokenizer is loaded with ``local_files_only=True`` so this command never
silently downloads a model or tokenizer.
"""

from __future__ import annotations

import argparse
import json
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aegislm.datasets.phase_f import (
    PHASE_F_BUILD_SEED,
    build_raw_catalog,
    build_source_profile,
    write_jsonl,
    write_parquet,
)
from aegislm.datasets.phase_f_raw import (
    SOURCE_REVISIONS,
    iter_bigvul_raw_records,
    iter_primevul_paired_records,
    load_diversevul_raw_records,
    raw_dataset_inventory,
)
from aegislm.datasets.source_decision import build_source_decision_artifact
from aegislm.datasets.source_v3 import promote_source_v3
from aegislm.datasets.sard_juliet import SARD_JULIET_PROFILE


DEFAULT_PROFILE_CONFIG = Path("configs/phase_f/source_v2.json")


@dataclass(frozen=True)
class DatasetRebuildConfig:
    """Inputs and immutable output policy for one rebuild attempt."""

    approved_f2_root: Path
    tokenizer: Path
    output_root: Path
    raw_root: Path | None = None
    profile_config: Path = DEFAULT_PROFILE_CONFIG
    seed: int = PHASE_F_BUILD_SEED
    cutoff_len: int = 2048
    skip_bigvul_catalog: bool = False


class DatasetRebuildError(ValueError):
    """Raised when the rebuild cannot proceed without guessing or overwriting."""


def rebuild_dataset(
    config: DatasetRebuildConfig,
    *,
    tokenizer: Any | None = None,
) -> dict[str, Any]:
    """Run catalog, source-v4 promotion, and decision-v2 projection sequentially.

    ``approved_f2_root`` is intentionally an input rather than an automatically
    generated approval.  Manual review and source acquisition remain explicit
    gates.  All generated stages are written under a temporary root and become
    visible only after every stage succeeds.
    """

    _validate_config(config)
    if tokenizer is None:
        tokenizer = _load_local_tokenizer(config.tokenizer)

    parent = config.output_root.resolve().parent
    parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{config.output_root.name}-", dir=parent)
    )
    try:
        catalog_report: dict[str, Any] | None = None
        if config.raw_root is not None:
            catalog_report = _build_catalog_stage(config, temporary / "catalog")

        source_v4_root = temporary / "phase-f-source-v4"
        source_v4_manifest = promote_source_v3(
            config.approved_f2_root,
            source_v4_root,
            tokenizer=tokenizer,
            cutoff_len=config.cutoff_len,
            profile="phase-f-source-v4",
            train_dataset_name="phase_f_source_v4_train",
            validation_dataset_name="phase_f_source_v4_validation",
        )

        decision_root = temporary / "phase-f-source-decision-v2"
        decision_manifest = build_source_decision_artifact(
            source_v4_root,
            decision_root,
            tokenizer=tokenizer,
            profile="phase-f-source-decision-v2",
            cutoff_len=config.cutoff_len,
            train_dataset_name="phase_f_source_decision_v2_train",
            validation_dataset_name="phase_f_source_decision_v2_validation",
        )

        report = {
            "schema_version": "aegislm.dataset-rebuild-report.v1",
            "status": "complete",
            "seed": config.seed,
            "cutoff_len": config.cutoff_len,
            "inputs": {
                "raw_root": (
                    config.raw_root.resolve().as_posix()
                    if config.raw_root is not None
                    else "not_applicable"
                ),
                "approved_f2_root": config.approved_f2_root.resolve().as_posix(),
                "tokenizer": config.tokenizer.resolve().as_posix(),
            },
            "stages": {
                "catalog": catalog_report or {"status": "not_applicable"},
                "source_v4": {
                    "status": source_v4_manifest["status"],
                    "counts": source_v4_manifest["counts"],
                    "profile": source_v4_manifest["profile"],
                },
                "source_decision_v2": {
                    "status": decision_manifest["status"],
                    "counts": decision_manifest["counts"],
                    "profile": decision_manifest["profile"],
                },
            },
            "manual_gate": {
                "approved_f2_required": True,
                "gold_passed_to_training": False,
            },
        }
        _write_json(temporary / "dataset_rebuild_report.json", report)
        temporary.replace(config.output_root.resolve())
        return report
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def _build_catalog_stage(
    config: DatasetRebuildConfig,
    output_dir: Path,
) -> dict[str, Any]:
    """Materialize the automatic raw-catalog and pool stage."""

    if config.raw_root is None:
        raise DatasetRebuildError("raw_root is required for the catalog stage")
    profile_config = _load_json(config.profile_config)
    quotas = profile_config["source_profile"]["quotas"]
    records = load_diversevul_raw_records(config.raw_root)
    if not config.skip_bigvul_catalog:
        records.extend(iter_bigvul_raw_records(config.raw_root))
    records.extend(iter_primevul_paired_records(config.raw_root))

    catalog = build_raw_catalog(records, source_revisions=SOURCE_REVISIONS)
    profile = build_source_profile(
        records,
        catalog,
        seed=config.seed,
        train_per_class=quotas["train_per_class"],
        validation_per_class=quotas["validation_per_class"],
        test_per_class=quotas["test_per_class"],
        core_datasets=tuple(
            profile_config["source_profile"]["dataset_roles"]["core_training"]
        ),
        cross_dataset_names=tuple(
            profile_config["source_profile"]["dataset_roles"]["cross_dataset_holdout"]
        ),
        cross_dataset_records=quotas["cross_dataset_records_per_dataset"],
    )

    write_parquet(catalog, output_dir / "raw_catalog.parquet")
    for name in (
        "eligible_manifest",
        "selected_manifest",
        "reserve_manifest",
        "quarantine_manifest",
        "reject_manifest",
    ):
        rows = profile[name]
        if rows:
            write_parquet(rows, output_dir / f"{name}.parquet")
    for pool in ("train", "validation", "test"):
        rows = [row for row in profile["eligible_manifest"] if row["pool"] == pool]
        write_parquet(rows, output_dir / "pools" / f"{pool}.parquet")
    for split in ("train", "validation", "challenge", "gold"):
        write_jsonl(profile[split], output_dir / f"{split}.jsonl")
    for dataset, values in profile["cross_dataset"].items():
        safe_name = "".join(
            character if character.isalnum() or character in "-_" else "-"
            for character in dataset.lower()
        ).strip("-")
        write_jsonl(
            values["challenge"],
            output_dir / "cross_dataset" / safe_name / "challenge.jsonl",
        )
        write_jsonl(
            values["gold"],
            output_dir / "cross_dataset" / safe_name / "gold.jsonl",
        )
    _write_json(output_dir / "dataset_manifest.json", profile["summary"])
    _write_json(
        output_dir / "raw_dataset_inventory.json",
        raw_dataset_inventory(config.raw_root),
    )
    return {
        "status": "complete",
        "counts": {
            "train": len(profile["train"]),
            "validation": len(profile["validation"]),
            "challenge": len(profile["challenge"]),
            "gold": len(profile["gold"]),
            "reserve": len(profile["reserve_manifest"]),
        },
        "output": output_dir.as_posix(),
    }


def _validate_config(config: DatasetRebuildConfig) -> None:
    if config.cutoff_len <= 0:
        raise DatasetRebuildError("cutoff_len must be positive")
    for name, path in (
        ("approved_f2_root", config.approved_f2_root),
        ("tokenizer", config.tokenizer),
        ("profile_config", config.profile_config),
    ):
        if not path.exists():
            raise DatasetRebuildError(f"{name} does not exist: {path}")
    if config.raw_root is not None and not config.raw_root.is_dir():
        raise DatasetRebuildError(f"raw_root is not a directory: {config.raw_root}")
    if config.output_root.exists():
        raise DatasetRebuildError(
            f"refusing to overwrite existing output: {config.output_root}"
        )
    for required in ("dataset_manifest.json", "SHA256SUMS"):
        if not (config.approved_f2_root / required).is_file():
            raise DatasetRebuildError(
                f"approved F2 artifact is missing {required}: {config.approved_f2_root}"
            )
    approved_manifest = _load_json(config.approved_f2_root / "dataset_manifest.json")
    if approved_manifest.get("profile") != SARD_JULIET_PROFILE:
        raise DatasetRebuildError(
            "approved F2 artifact must use the remediated "
            f"{SARD_JULIET_PROFILE} profile"
        )


def _load_local_tokenizer(path: Path) -> Any:
    try:
        from transformers import AutoTokenizer
    except ImportError as exc:
        raise DatasetRebuildError(
            "transformers is required to load the pinned local tokenizer"
        ) from exc
    try:
        return AutoTokenizer.from_pretrained(
            path,
            local_files_only=True,
            trust_remote_code=True,
        )
    except (OSError, ValueError) as exc:
        raise DatasetRebuildError(
            f"local tokenizer is unavailable; no download was attempted: {path}"
        ) from exc


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise DatasetRebuildError(f"JSON config must be an object: {path}")
    return value


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--approved-f2-root", type=Path, required=True)
    parser.add_argument("--tokenizer", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--raw-root", type=Path)
    parser.add_argument("--profile-config", type=Path, default=DEFAULT_PROFILE_CONFIG)
    parser.add_argument("--cutoff-len", type=int, default=2048)
    parser.add_argument("--skip-bigvul-catalog", action="store_true")
    args = parser.parse_args()
    report = rebuild_dataset(
        DatasetRebuildConfig(
            approved_f2_root=args.approved_f2_root,
            tokenizer=args.tokenizer,
            output_root=args.output_root,
            raw_root=args.raw_root,
            profile_config=args.profile_config,
            cutoff_len=args.cutoff_len,
            skip_bigvul_catalog=args.skip_bigvul_catalog,
        )
    )
    print(
        "Dataset rebuild complete: "
        f"source_v4={report['stages']['source_v4']['counts']}, "
        f"decision_v2={report['stages']['source_decision_v2']['counts']}, "
        f"output={args.output_root}"
    )


if __name__ == "__main__":
    main()
