"""Build the Phase F Q1R7 source multitask canary artifact."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def main() -> None:
    from aegislm.datasets.source_multitask import build_source_multitask_artifact

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-dir", type=Path, required=True)
    parser.add_argument("--decision-dir", type=Path, required=True)
    parser.add_argument("--canonical-records", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=20260730)
    parser.add_argument("--development-per-class", type=int, default=50)
    args = parser.parse_args()
    manifest = build_source_multitask_artifact(
        args.report_dir,
        args.decision_dir,
        args.canonical_records,
        args.output_dir,
        seed=args.seed,
        development_per_class=args.development_per_class,
    )
    print(
        "Source multitask artifact complete: "
        f"status={manifest['status']}, counts={manifest['counts']}, "
        f"output={args.output_dir}"
    )


if __name__ == "__main__":
    main()
