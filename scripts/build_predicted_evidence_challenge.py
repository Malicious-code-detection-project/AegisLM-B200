"""Build evidence prompts conditioned on recorded decision predictions."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def main() -> None:
    from aegislm.datasets.source_two_stage import (
        build_predicted_assessment_evidence_challenge,
    )
    from aegislm.evaluation.harness import load_jsonl

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--decision-predictions", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows = build_predicted_assessment_evidence_challenge(
        load_jsonl(args.records),
        load_jsonl(args.decision_predictions),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows
        ),
        encoding="utf-8",
    )
    print(f"Predicted-assessment evidence challenge complete: records={len(rows)}")


if __name__ == "__main__":
    main()
