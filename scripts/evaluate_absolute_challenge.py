"""Evaluate a blind-code prediction run against absolute pass/fail gates."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def main() -> None:
    from aegislm.evaluation import (
        AbsoluteThresholds,
        evaluate_absolute_challenge,
        load_jsonl,
        load_predictions,
        write_absolute_report,
        write_absolute_summary,
    )

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gold", type=Path, required=True)
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--minimum-sample-count", type=int, default=200)
    parser.add_argument("--minimum-precision", type=float, default=0.90)
    parser.add_argument("--minimum-recall", type=float, default=0.95)
    parser.add_argument("--maximum-false-positive-rate", type=float, default=0.05)
    parser.add_argument("--maximum-abstention-rate", type=float, default=0.05)
    parser.add_argument("--minimum-parse-success-rate", type=float, default=0.99)
    parser.add_argument("--minimum-schema-pass-rate", type=float, default=0.99)
    parser.add_argument("--minimum-safety-pass-rate", type=float, default=1.0)
    parser.add_argument("--minimum-evidence-rate", type=float, default=0.90)
    parser.add_argument(
        "--fail-on-gate",
        action="store_true",
        help="Exit with status 1 when one or more quality gates fail.",
    )
    args = parser.parse_args()

    thresholds = AbsoluteThresholds(
        minimum_sample_count=args.minimum_sample_count,
        minimum_precision=args.minimum_precision,
        minimum_recall=args.minimum_recall,
        maximum_false_positive_rate=args.maximum_false_positive_rate,
        maximum_abstention_rate=args.maximum_abstention_rate,
        minimum_parse_success_rate=args.minimum_parse_success_rate,
        minimum_schema_pass_rate=args.minimum_schema_pass_rate,
        minimum_safety_pass_rate=args.minimum_safety_pass_rate,
        minimum_evidence_rate=args.minimum_evidence_rate,
    )
    result = evaluate_absolute_challenge(
        load_jsonl(args.gold),
        load_predictions(args.predictions),
        thresholds=thresholds,
    )
    write_absolute_summary(result, args.summary)
    write_absolute_report(result, args.report)
    status = "PASS" if result["overall_pass"] else "FAIL"
    metrics = result["metrics"]
    print(
        f"AegisLM absolute evaluation: {status}, "
        f"precision={metrics['precision']:.4f}, "
        f"recall={metrics['recall']:.4f}, "
        f"fpr={metrics['false_positive_rate']:.4f}, "
        f"summary={args.summary}, report={args.report}"
    )
    if args.fail_on_gate and not result["overall_pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
