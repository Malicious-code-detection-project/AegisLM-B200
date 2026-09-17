"""Audit Decompile-Bench repository provenance after alignment review."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.datasets.decompile_bench_provenance import (  # noqa: E402
    audit_decompile_bench_provenance,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shard", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--review-result", type=Path, required=True)
    parser.add_argument("--dataset-revision", required=True)
    parser.add_argument("--dataset-license", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    result = audit_decompile_bench_provenance(
        args.shard,
        args.inventory,
        args.review_result,
        dataset_revision=args.dataset_revision,
        dataset_license=args.dataset_license,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Phase F Decompile-Bench provenance audit: "
        f"decision={result['decision']}, "
        f"explicit={result['summary']['explicit_repository_rows']}/"
        f"{result['summary']['total_rows']}, "
        f"repositories={result['summary']['unique_explicit_repositories']}, "
        f"training={result['approved_for_training']}"
    )
    if result["decision"] == "provenance_audit_invalid":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
