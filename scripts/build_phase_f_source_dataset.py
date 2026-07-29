"""Build the Phase F source catalog, manifest, and materialized datasets."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def main() -> None:
    from aegislm.datasets.phase_f import (
        PHASE_F_BUILD_SEED,
        build_raw_catalog,
        build_source_profile,
        load_jsonl,
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

    parser = argparse.ArgumentParser(description=__doc__)
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--input",
        type=Path,
        action="append",
        help="Canonical AegisLM JSONL. Repeat for multiple splits.",
    )
    input_group.add_argument(
        "--raw-root",
        type=Path,
        help="Immutable raw snapshot root containing diversevul/ and bigvul/.",
    )
    parser.add_argument(
        "--skip-bigvul-catalog",
        action="store_true",
        help="Build only the DiverseVul core catalog and profile.",
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--profile-config",
        type=Path,
        default=REPO_ROOT / "configs" / "phase_f" / "source_v2.json",
    )
    parser.add_argument("--seed", type=int)
    parser.add_argument("--train-per-class", type=int)
    parser.add_argument("--validation-per-class", type=int)
    parser.add_argument("--test-per-class", type=int)
    args = parser.parse_args()

    config = json.loads(args.profile_config.read_text(encoding="utf-8"))
    quotas = config["source_profile"]["quotas"]
    seed = (
        args.seed if args.seed is not None else config.get("seed", PHASE_F_BUILD_SEED)
    )
    train_per_class = (
        args.train_per_class
        if args.train_per_class is not None
        else quotas["train_per_class"]
    )
    validation_per_class = (
        args.validation_per_class
        if args.validation_per_class is not None
        else quotas["validation_per_class"]
    )
    test_per_class = (
        args.test_per_class
        if args.test_per_class is not None
        else quotas["test_per_class"]
    )
    if args.raw_root is not None:
        records = load_diversevul_raw_records(args.raw_root)
        if not args.skip_bigvul_catalog:
            records.extend(iter_bigvul_raw_records(args.raw_root))
        records.extend(iter_primevul_paired_records(args.raw_root))
        source_revisions = SOURCE_REVISIONS
        inventory = raw_dataset_inventory(args.raw_root)
    else:
        records = [record for path in args.input for record in load_jsonl(path)]
        source_revisions = {}
        inventory = None

    catalog = build_raw_catalog(records, source_revisions=source_revisions)
    profile = build_source_profile(
        records,
        catalog,
        seed=seed,
        train_per_class=train_per_class,
        validation_per_class=validation_per_class,
        test_per_class=test_per_class,
        core_datasets=tuple(config["source_profile"]["dataset_roles"]["core_training"]),
        cross_dataset_names=tuple(
            config["source_profile"]["dataset_roles"]["cross_dataset_holdout"]
        ),
        cross_dataset_records=quotas["cross_dataset_records_per_dataset"],
    )

    output_dir = args.output_dir
    write_parquet(catalog, output_dir / "raw_catalog.parquet")
    write_parquet(
        profile["eligible_manifest"], output_dir / "eligible_manifest.parquet"
    )
    write_parquet(
        profile["selected_manifest"], output_dir / "selected_manifest.parquet"
    )
    write_parquet(profile["reserve_manifest"], output_dir / "reserve_manifest.parquet")
    if profile["quarantine_manifest"]:
        write_parquet(
            profile["quarantine_manifest"],
            output_dir / "quarantine_manifest.parquet",
        )
    if profile["reject_manifest"]:
        write_parquet(
            profile["reject_manifest"], output_dir / "reject_manifest.parquet"
        )
    for pool in ("train", "validation", "test"):
        pool_rows = [row for row in profile["eligible_manifest"] if row["pool"] == pool]
        write_parquet(pool_rows, output_dir / "pools" / f"{pool}.parquet")
    write_jsonl(profile["train"], output_dir / "train.jsonl")
    write_jsonl(profile["validation"], output_dir / "validation.jsonl")
    write_jsonl(profile["challenge"], output_dir / "challenge.jsonl")
    write_jsonl(profile["gold"], output_dir / "gold.jsonl")
    for dataset, values in profile["cross_dataset"].items():
        dataset_dir = output_dir / "cross_dataset" / _dataset_slug(dataset)
        write_jsonl(values["challenge"], dataset_dir / "challenge.jsonl")
        write_jsonl(values["gold"], dataset_dir / "gold.jsonl")
    (output_dir / "dataset_manifest.json").write_text(
        json.dumps(profile["summary"], ensure_ascii=False, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    if inventory is not None:
        (output_dir / "raw_dataset_inventory.json").write_text(
            json.dumps(inventory, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    print(
        "Phase F source dataset complete: "
        f"train={len(profile['train'])}, "
        f"validation={len(profile['validation'])}, "
        f"challenge={len(profile['challenge'])}, "
        f"cross_dataset={sum(len(v['challenge']) for v in profile['cross_dataset'].values())}, "
        f"reserve={len(profile['reserve_manifest'])}, "
        f"output={output_dir}"
    )


def _dataset_slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


if __name__ == "__main__":
    main()
