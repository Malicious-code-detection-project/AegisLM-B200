"""Render the Phase F ARVO patch review queue as readable Markdown."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.datasets.arvo_patch import (  # noqa: E402
    render_arvo_patch_manual_review,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review-json", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.review_json.read_text(encoding="utf-8"))
    markdown = render_arvo_patch_manual_review(manifest["review_records"])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(markdown + "\n", encoding="utf-8")
    print(
        "Phase F ARVO manual review rendered: "
        f"records={len(manifest['review_records'])}, output={args.output}"
    )


if __name__ == "__main__":
    main()
