"""Aggregate explicit review rounds into the final Phase F binary B0 gate."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def finalize_b0_gate(
    summaries: list[dict[str, Any]],
    *,
    required_accepted_pairs: int,
) -> dict[str, Any]:
    """Require conflict-free decisions and exactly the requested accepted supply."""
    if required_accepted_pairs <= 0:
        raise ValueError("required accepted pairs must be positive")

    decisions: dict[str, bool] = {}
    scopes: list[str] = []
    reviewed_variant_count = 0
    for summary in summaries:
        scope = str(summary["scope"])
        scopes.append(scope)
        reviewed_variant_count += int(summary["variant_count"])
        for pair_id, passed_value in summary["pair_decisions"].items():
            passed = bool(passed_value)
            if pair_id in decisions:
                raise ValueError(f"duplicate reviewed pair: {pair_id}")
            decisions[str(pair_id)] = passed

    accepted = sorted(pair_id for pair_id, passed in decisions.items() if passed)
    rejected = sorted(pair_id for pair_id, passed in decisions.items() if not passed)
    gate_pass = len(accepted) == required_accepted_pairs
    return {
        "schema_version": "aegislm.phase-f-binary-b0-gate-summary.v1",
        "review_scopes": scopes,
        "review_round_count": len(summaries),
        "reviewed_pair_count": len(decisions),
        "reviewed_variant_count": reviewed_variant_count,
        "accepted_pair_count": len(accepted),
        "rejected_pair_count": len(rejected),
        "required_accepted_pair_count": required_accepted_pairs,
        "accepted_pair_ids": accepted,
        "rejected_pair_ids": rejected,
        "selected_variant_count": len(accepted) * 4,
        "target_preservation": {
            "passed": len(accepted),
            "total": required_accepted_pairs,
            "rate": len(accepted) / required_accepted_pairs,
        },
        "compile_decompile_contract": (
            "Every accepted pair was explicitly reviewed after successful "
            "GCC/Clang O0/O2 compile, decompile, and source-function linkage."
        ),
        "raw_object_execution_count": 0,
        "gate_pass": gate_pass,
        "decision": "pass" if gate_pass else "insufficient_accepted_supply",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--review-summary",
        type=Path,
        action="append",
        required=True,
    )
    parser.add_argument("--required-accepted-pairs", type=int, default=100)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    summaries = [
        json.loads(path.read_text(encoding="utf-8")) for path in args.review_summary
    ]
    output = finalize_b0_gate(
        summaries,
        required_accepted_pairs=args.required_accepted_pairs,
    )
    output["source_review_summary_sha256"] = {
        str(path): _sha256_file(path) for path in args.review_summary
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Phase F binary B0 final gate: "
        f"accepted={output['accepted_pair_count']}/"
        f"{output['required_accepted_pair_count']}, "
        f"reviewed={output['reviewed_pair_count']}, "
        f"decision={output['decision']}"
    )
    print(f"summary_sha256={_sha256_file(args.output)}")


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    main()
