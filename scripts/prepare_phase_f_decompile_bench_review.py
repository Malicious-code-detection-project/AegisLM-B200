"""Render Decompile-Bench review packets and a code-free decision template."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.datasets.decompile_bench_review_decision import (  # noqa: E402
    build_decompile_bench_review_decision_template,
    render_decompile_bench_review_packets,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queue", type=Path, required=True)
    parser.add_argument("--packet-dir", type=Path, required=True)
    parser.add_argument("--decisions", type=Path, required=True)
    parser.add_argument("--batch-size", type=int, default=10)
    parser.add_argument("--error-budget", type=int, default=5)
    args = parser.parse_args()

    packets = render_decompile_bench_review_packets(
        args.queue,
        args.packet_dir,
        batch_size=args.batch_size,
    )
    decisions = build_decompile_bench_review_decision_template(
        args.queue,
        error_budget=args.error_budget,
    )
    args.decisions.parent.mkdir(parents=True, exist_ok=True)
    args.decisions.write_text(
        json.dumps(decisions, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Phase F Decompile-Bench review prepared: "
        f"records={packets['records']}, packets={packets['packet_count']}, "
        f"queue_sha256={packets['queue_sha256']}"
    )


if __name__ == "__main__":
    main()
