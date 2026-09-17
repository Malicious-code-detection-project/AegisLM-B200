"""Evaluate predictions from the diagnostic source decision-only contract."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def main() -> None:
    from aegislm.evaluation.harness import load_jsonl, load_predictions
    from aegislm.evaluation.source_decision import (
        SourceDecisionThresholds,
        evaluate_source_decisions,
        write_source_decision_summary,
    )

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gold", type=Path, required=True)
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--minimum-sample-count", type=int, default=20)
    parser.add_argument("--minimum-precision", type=float, default=0.75)
    parser.add_argument("--minimum-recall", type=float, default=0.75)
    parser.add_argument("--maximum-false-positive-rate", type=float, default=0.20)
    parser.add_argument("--maximum-abstention-rate", type=float, default=0.10)
    parser.add_argument("--minimum-parse-success-rate", type=float, default=0.99)
    parser.add_argument("--minimum-schema-pass-rate", type=float, default=0.99)
    parser.add_argument("--blind-test", action="store_true")
    parser.add_argument("--fail-on-gate", action="store_true")
    args = parser.parse_args()
    result = evaluate_source_decisions(
        load_jsonl(args.gold),
        load_predictions(args.predictions),
        thresholds=SourceDecisionThresholds(
            minimum_sample_count=args.minimum_sample_count,
            minimum_precision=args.minimum_precision,
            minimum_recall=args.minimum_recall,
            maximum_false_positive_rate=args.maximum_false_positive_rate,
            maximum_abstention_rate=args.maximum_abstention_rate,
            minimum_parse_success_rate=args.minimum_parse_success_rate,
            minimum_schema_pass_rate=args.minimum_schema_pass_rate,
        ),
        blind_test_used=args.blind_test,
    )
    write_source_decision_summary(result, args.summary)
    metrics = result["metrics"]
    print(
        "AegisLM source decision evaluation: "
        f"{'PASS' if result['overall_pass'] else 'FAIL'}, "
        f"precision={metrics['precision']:.4f}, "
        f"recall={metrics['recall']:.4f}, "
        f"fpr={metrics['false_positive_rate']:.4f}, "
        f"schema={metrics['schema_pass_rate']:.4f}, "
        f"summary={args.summary}"
    )
    if args.fail_on_gate and not result["overall_pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
