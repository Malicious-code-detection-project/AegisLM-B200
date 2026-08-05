"""Verify and inventory the CVEfixes archive without extracting member payloads."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.datasets.archive_inventory import inventory_zip_archive  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_text(encoding="utf-8"))
    result = inventory_zip_archive(
        args.archive,
        expected_bytes=int(config["expected_bytes"]),
        expected_md5=str(config["expected_md5"]),
        max_uncompressed_bytes=int(config["max_uncompressed_bytes"]),
        max_compression_ratio=float(config["max_compression_ratio"]),
    )
    result["profile"] = str(config["profile"])
    result["source_id"] = str(config["source_id"])
    result["source_record"] = str(config["source_record"])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Phase F CVEfixes archive inventory: "
        f"decision={result['decision']}, "
        f"members={result['inventory']['member_count']}, "
        f"extractions={result['safety']['member_extraction_count']}"
    )
    if result["decision"] != "inventory_pass":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
