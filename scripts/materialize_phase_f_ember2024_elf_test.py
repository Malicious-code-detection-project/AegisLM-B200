"""Materialize deduplicated, label-blind EMBER2024 ELF benchmark files."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.datasets.ember2024 import (  # noqa: E402
    materialize_ember2024_elf_test,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--audit", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--expected-records", type=int, required=True)
    parser.add_argument(
        "--dataset-role",
        choices=("classifier_train", "classifier_test"),
        required=True,
    )
    args = parser.parse_args()

    result = materialize_ember2024_elf_test(
        args.archive,
        args.inventory,
        args.audit,
        args.output_dir,
        expected_records=args.expected_records,
        dataset_role=args.dataset_role,
    )
    print(
        "EMBER2024 ELF materialization: "
        f"decision={result['decision']}, "
        f"records={result['summary']['record_count']}, "
        f"labels={result['summary']['label_counts']}"
    )
    if result["decision"] != "materialization_pass":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
