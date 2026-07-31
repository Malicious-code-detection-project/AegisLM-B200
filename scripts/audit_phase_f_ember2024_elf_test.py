"""Audit the fixed EMBER2024 ELF test feature archive as an independent benchmark."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.datasets.ember2024 import (  # noqa: E402
    audit_ember2024_elf_test,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--expected-records", type=int, required=True)
    parser.add_argument("--expected-materialized-records", type=int)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    result = audit_ember2024_elf_test(
        args.archive,
        args.inventory,
        expected_records=args.expected_records,
        expected_materialized_records=args.expected_materialized_records,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "EMBER2024 ELF test audit: "
        f"decision={result['decision']}, "
        f"records={result['summary']['record_count']}, "
        f"labels={result['label_counts']}"
    )
    if result["decision"] != "benchmark_metadata_pass":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
