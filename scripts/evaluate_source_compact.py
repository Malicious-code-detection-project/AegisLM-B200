"""Evaluate compact source evidence predictions on a label-blind challenge."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def main() -> None:
    from aegislm.evaluation.harness import load_jsonl, load_predictions
    from aegislm.evaluation.source_compact import (
        SourceCompactThresholds,
        evaluate_source_compact_predictions,
        write_source_compact_summary,
    )

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--challenge", type=Path, required=True)
    parser.add_argument("--gold", type=Path, required=True)
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--minimum-sample-count", type=int, default=100)
    parser.add_argument("--fail-on-gate", action="store_true")
    args = parser.parse_args()
    result = evaluate_source_compact_predictions(
        load_jsonl(args.challenge),
        load_jsonl(args.gold),
        load_predictions(args.predictions),
        thresholds=SourceCompactThresholds(
            minimum_sample_count=args.minimum_sample_count
        ),
    )
    write_source_compact_summary(result, args.summary)
    metrics = result["metrics"]
    print(
        "AegisLM source compact evaluation: "
        f"{'PASS' if result['overall_pass'] else 'FAIL'}, "
        f"precision={metrics['precision']:.4f}, "
        f"recall={metrics['recall']:.4f}, "
        f"fpr={metrics['false_positive_rate']:.4f}, "
        f"schema={metrics['schema_pass_rate']:.4f}, "
        f"evidence_f1={metrics['evidence_f1']:.4f}, "
        f"summary={args.summary}"
    )
    if args.fail_on_gate and not result["overall_pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
