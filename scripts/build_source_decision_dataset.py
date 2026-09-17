"""Build the diagnostic Phase F source decision-only dataset."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def main() -> None:
    from transformers import AutoTokenizer

    from aegislm.datasets.source_decision import build_source_decision_artifact

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--tokenizer", required=True)
    args = parser.parse_args()
    tokenizer = AutoTokenizer.from_pretrained(
        args.tokenizer,
        trust_remote_code=True,
    )
    manifest = build_source_decision_artifact(
        args.source_dir,
        args.output_dir,
        tokenizer=tokenizer,
    )
    print(
        "Source decision dataset complete: "
        f"status={manifest['status']}, "
        f"train={manifest['counts']['train']}, "
        f"validation={manifest['counts']['validation']}, "
        f"maximum_tokens={manifest['maximum_tokens']}, "
        f"output={args.output_dir}"
    )


if __name__ == "__main__":
    main()
