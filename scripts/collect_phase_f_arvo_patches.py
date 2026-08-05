"""Collect public developer patches for the Phase F ARVO manual review gate."""

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
)
from aegislm.datasets.arvo_patch import (  # noqa: E402
    ARVO_PATCH_MAX_BYTES,
    collect_arvo_patch_review,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--patch-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=ARVO_DEFAULT_SEED)
    parser.add_argument(
        "--family-quota",
        type=int,
        default=ARVO_DEFAULT_FAMILY_QUOTA,
    )
    parser.add_argument("--max-bytes", type=int, default=ARVO_PATCH_MAX_BYTES)
    args = parser.parse_args()
    result = collect_arvo_patch_review(
        args.database,
        args.patch_dir,
        seed=args.seed,
        family_quota=args.family_quota,
        max_bytes=args.max_bytes,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Phase F ARVO patch collection: "
        f"selected={result['selection']['selected_count']}, "
        f"supply_pass={result['gate']['supply_pass']}, "
        f"raw_payload_read={result['safety']['raw_payload_read_count']}"
    )


if __name__ == "__main__":
    main()
