"""Evaluate source-v2 predictions against the private canonical records."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def main() -> None:
    from aegislm.evaluation import (
        SourceThresholds,
        evaluate_source_predictions,
        load_jsonl,
        load_predictions,
        write_source_report,
        write_source_summary,
    )

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--challenge", type=Path, required=True)
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--minimum-sample-count", type=int, default=200)
    parser.add_argument(
        "--gate-profile",
        choices=("final", "diagnostic"),
        default="final",
        help="Use the final 500-case gate or the Q1/Q2 canary diagnostic gate.",
    )
    parser.add_argument("--fail-on-gate", action="store_true")
    args = parser.parse_args()

    challenge = load_jsonl(args.challenge)
    challenge_ids = [str(row["id"]) for row in challenge]
    if len(challenge_ids) != len(set(challenge_ids)):
        raise SystemExit("challenge ids must be unique")
    canonical_by_id = {str(row["id"]): row for row in load_jsonl(args.records)}
    missing = [
        record_id for record_id in challenge_ids if record_id not in canonical_by_id
    ]
    if missing:
        raise SystemExit(
            "canonical records missing challenge ids: " + ", ".join(missing[:10])
        )
    records = [canonical_by_id[record_id] for record_id in challenge_ids]
    thresholds = (
        SourceThresholds.diagnostic(minimum_sample_count=args.minimum_sample_count)
        if args.gate_profile == "diagnostic"
        else SourceThresholds(minimum_sample_count=args.minimum_sample_count)
    )
    result = evaluate_source_predictions(
        records,
        load_predictions(args.predictions),
        thresholds=thresholds,
    )
    write_source_summary(result, args.summary)
    write_source_report(result, args.report)
    metrics = result["metrics"]
    print(
        "AegisLM source evaluation: "
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
