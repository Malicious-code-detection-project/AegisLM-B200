"""Run the metadata-only Phase F binary-alignment supply preflight."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.datasets.alignment_supply import audit_alignment_supply  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--storage-path", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    registry = json.loads(args.config.read_text(encoding="utf-8"))
    available_bytes = shutil.disk_usage(args.storage_path).free
    result = audit_alignment_supply(
        registry,
        available_bytes=available_bytes,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Phase F binary alignment supply preflight: "
        f"decision={result['decision']}, "
        f"ready={result['acquisition_ready_source_ids']}, "
        f"available_bytes={available_bytes}"
    )
    if result["decision"] != "single_alignment_candidate_ready":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
