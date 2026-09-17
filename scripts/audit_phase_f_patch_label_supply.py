"""Audit patch-localized CWE dataset metadata before raw acquisition."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.datasets.patch_supply import audit_patch_label_supply  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--available-bytes", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    registry = json.loads(args.config.read_text(encoding="utf-8"))
    result = audit_patch_label_supply(
        registry,
        available_bytes=args.available_bytes,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Phase F patch-label supply preflight: "
        f"decision={result['decision']}, "
        f"ready={','.join(result['ready_source_ids']) or 'none'}, "
        f"archive_downloads={result['safety']['archive_download_count']}"
    )


if __name__ == "__main__":
    main()
