"""Verify a fixed Assemblage compressed metadata artifact without extracting it."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.datasets.assemblage_metadata import (  # noqa: E402
    verify_compressed_metadata_artifact,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--expected-bytes", type=int, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    result = verify_compressed_metadata_artifact(
        args.artifact,
        expected_bytes=args.expected_bytes,
        expected_sha256=args.expected_sha256,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Assemblage compressed metadata verification: "
        f"decision={result['decision']}, "
        f"bytes={result['artifact']['observed_bytes']}"
    )
    if result["decision"] != "compressed_artifact_verified":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
