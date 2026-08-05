"""Build the Phase F F2R1 compact source evidence artifact."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def main() -> None:
    from transformers import AutoTokenizer

    from aegislm.datasets.source_compact import build_source_compact_artifact

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--tokenizer", required=True)
    args = parser.parse_args()
    tokenizer = AutoTokenizer.from_pretrained(
        args.tokenizer,
        trust_remote_code=True,
    )
    manifest = build_source_compact_artifact(
        args.source_dir,
        args.output_dir,
        tokenizer=tokenizer,
    )
    print(
        "Source compact artifact complete: "
        f"status={manifest['status']}, counts={manifest['counts']}, "
        f"maximum_tokens={manifest['maximum_tokens']}, "
        f"output={args.output_dir}"
    )


if __name__ == "__main__":
    main()
