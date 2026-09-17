"""Run the read-only CVEfixes before/after and CWE supply inventory."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.datasets.cvefixes_supply import audit_cvefixes_supply  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--minimum-binary-pairs", type=int, default=2_000)
    args = parser.parse_args()
    result = audit_cvefixes_supply(
        args.database,
        minimum_binary_pairs=args.minimum_binary_pairs,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Phase F CVEfixes supply inventory: "
        f"decision={result['decision']}, "
        f"pairs={result['pairing']['exact_method_pairs']}, "
        f"binary_candidates={result['pairing']['binary_candidate_pairs']}, "
        f"code_returns={result['safety']['raw_code_return_count']}"
    )
    if result["decision"] != "supply_inventory_pass":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
