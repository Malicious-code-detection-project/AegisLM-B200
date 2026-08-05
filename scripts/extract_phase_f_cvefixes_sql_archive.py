"""Extract only the inventoried CVEfixes SQL gzip member for schema auditing."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.datasets.archive_inventory import (  # noqa: E402
    extract_verified_zip_member,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument(
        "--member",
        default="CVEfixes_v1.0.8/Data/CVEfixes_v1.0.8.sql.gz",
    )
    parser.add_argument("--max-output-bytes", type=int, default=13_000_000_000)
    args = parser.parse_args()
    inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
    result = extract_verified_zip_member(
        args.archive,
        inventory,
        args.member,
        args.output,
        max_output_bytes=args.max_output_bytes,
    )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Phase F CVEfixes selective extraction: "
        f"decision={result['decision']}, "
        f"bytes={result['member']['observed_output_bytes']}, "
        f"sha256={result['member']['output_sha256']}"
    )


if __name__ == "__main__":
    main()
