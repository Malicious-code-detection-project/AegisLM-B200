"""Build the Phase F source catalog, manifest, and materialized datasets."""

from __future__ import annotations

import argparse
import json
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

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        action="append",
        required=True,
        help="Canonical AegisLM JSONL. Repeat for multiple splits.",
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
    records = [record for path in args.input for record in load_jsonl(path)]
    catalog = build_raw_catalog(records)
    profile = build_source_profile(
        records,
        catalog,
        seed=seed,
        train_per_class=train_per_class,
        validation_per_class=validation_per_class,
        test_per_class=test_per_class,
    )

    output_dir = args.output_dir
    write_parquet(catalog, output_dir / "raw_catalog.parquet")
    write_parquet(profile["manifest"], output_dir / "eligible_manifest.parquet")
    write_jsonl(profile["train"], output_dir / "train.jsonl")
    write_jsonl(profile["validation"], output_dir / "validation.jsonl")
    write_jsonl(profile["challenge"], output_dir / "challenge.jsonl")
    write_jsonl(profile["gold"], output_dir / "gold.jsonl")
    (output_dir / "dataset_manifest.json").write_text(
        json.dumps(profile["summary"], ensure_ascii=False, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    print(
        "Phase F source dataset complete: "
        f"train={len(profile['train'])}, "
        f"validation={len(profile['validation'])}, "
        f"challenge={len(profile['challenge'])}, "
        f"output={output_dir}"
    )


if __name__ == "__main__":
    main()
