"""Audit ARVO metadata and select a safe 200-record buffer feasibility set."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.datasets.arvo import (  # noqa: E402
    ARVO_DEFAULT_FAMILY_QUOTA,
    ARVO_DEFAULT_SEED,
    audit_arvo_metadata,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=ARVO_DEFAULT_SEED)
    parser.add_argument(
        "--family-quota",
        type=int,
        default=ARVO_DEFAULT_FAMILY_QUOTA,
    )
    args = parser.parse_args()
    result = audit_arvo_metadata(
        args.database,
        seed=args.seed,
        family_quota=args.family_quota,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Phase F ARVO metadata audit: "
        f"selected={result['selection']['selected_count']}, "
        f"decision={result['decision']}, "
        f"sha256={result['source']['database_sha256']}"
    )


if __name__ == "__main__":
    main()
