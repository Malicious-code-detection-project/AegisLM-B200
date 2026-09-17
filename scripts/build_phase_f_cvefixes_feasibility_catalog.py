"""Build the deterministic CVEfixes metadata-only feasibility catalog."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.datasets.cvefixes_catalog import (  # noqa: E402
    build_cvefixes_feasibility_catalog,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--supply-audit", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    config = json.loads(args.config.read_text(encoding="utf-8"))
    result = build_cvefixes_feasibility_catalog(
        args.database,
        args.supply_audit,
        selection_seed=int(config["selection_seed"]),
        sample_size=int(config["sample_size"]),
        language_quotas={
            str(key): int(value) for key, value in config["language_quotas"].items()
        },
        max_per_cwe=int(config["max_per_cwe"]),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Phase F CVEfixes feasibility catalog: "
        f"decision={result['decision']}, "
        f"pool={result['candidate_pool']['rows']}, "
        f"selected={result['selected_summary']['rows']}, "
        f"cwes={result['selected_summary']['distinct_cwes']}"
    )
    if result["decision"] != "manual_evidence_gate_ready":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
