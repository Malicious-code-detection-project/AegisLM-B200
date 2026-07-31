"""Render CVEfixes review packets and create a code-free decision template."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.datasets.cvefixes_review_decision import (  # noqa: E402
    build_cvefixes_review_decision_template,
    render_cvefixes_review_packets,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queue", type=Path, required=True)
    parser.add_argument("--packet-dir", type=Path, required=True)
    parser.add_argument("--decisions", type=Path, required=True)
    parser.add_argument("--batch-size", type=int, default=20)
    parser.add_argument("--error-budget", type=int, default=10)
    args = parser.parse_args()

    packet_result = render_cvefixes_review_packets(
        args.queue,
        args.packet_dir,
        batch_size=args.batch_size,
    )
    if args.decisions.exists():
        raise SystemExit(f"refusing to overwrite existing decisions: {args.decisions}")
    decisions = build_cvefixes_review_decision_template(
        args.queue,
        error_budget=args.error_budget,
    )
    args.decisions.parent.mkdir(parents=True, exist_ok=True)
    args.decisions.write_text(
        json.dumps(decisions, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Phase F CVEfixes manual review prepared: "
        f"packets={packet_result['packet_count']}, "
        f"records={packet_result['records']}, "
        f"decisions={args.decisions}"
    )


if __name__ == "__main__":
    main()
