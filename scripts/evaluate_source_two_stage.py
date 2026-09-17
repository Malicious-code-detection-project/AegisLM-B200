"""Evaluate the source decision-to-evidence pipeline on development records."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def main() -> None:
    from aegislm.evaluation.harness import load_jsonl, load_predictions
    from aegislm.evaluation.source_two_stage import (
        SourceTwoStageThresholds,
        evaluate_source_two_stage_predictions,
        write_source_two_stage_summary,
    )

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--decision-gold", type=Path, required=True)
    parser.add_argument("--decision-predictions", type=Path, required=True)
    parser.add_argument("--evidence-challenge", type=Path, required=True)
    parser.add_argument("--evidence-gold", type=Path, required=True)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--evidence-predictions", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--blind-test", action="store_true")
    parser.add_argument("--fail-on-gate", action="store_true")
    args = parser.parse_args()
    result = evaluate_source_two_stage_predictions(
        load_jsonl(args.decision_gold),
        load_predictions(args.decision_predictions),
        load_jsonl(args.evidence_challenge),
        load_jsonl(args.evidence_gold),
        load_jsonl(args.records),
        load_predictions(args.evidence_predictions),
        thresholds=SourceTwoStageThresholds(),
        blind_test_used=args.blind_test,
    )
    write_source_two_stage_summary(result, args.summary)
    decision = result["decision"]["metrics"]
    evidence = result["evidence"]["metrics"]
    print(
        "AegisLM two-stage source evaluation: "
        f"{'PASS' if result['overall_pass'] else 'FAIL'}, "
        f"precision={decision['precision']:.4f}, "
        f"recall={decision['recall']:.4f}, "
        f"fpr={decision['false_positive_rate']:.4f}, "
        f"evidence_f1={evidence['evidence_f1']:.4f}, "
        f"renderer={evidence['renderer_pass_rate']:.4f}, "
        f"summary={args.summary}"
    )
    if args.fail_on_gate and not result["overall_pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
