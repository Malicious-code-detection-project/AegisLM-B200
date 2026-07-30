"""Refresh ARVO review excerpts from the hash-bound cached source patches."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.datasets.arvo_patch import refresh_arvo_patch_review  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review-json", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.review_json.read_text(encoding="utf-8"))
    refreshed = refresh_arvo_patch_review(manifest)
    args.review_json.write_text(
        json.dumps(refreshed, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Phase F ARVO patch summaries refreshed: "
        f"records={len(refreshed['review_records'])}"
    )


if __name__ == "__main__":
    main()
