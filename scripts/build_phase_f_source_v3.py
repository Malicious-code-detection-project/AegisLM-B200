"""Build and freeze the approved Phase F source-v3 training artifact."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def main() -> None:
    from transformers import AutoTokenizer

    from aegislm.datasets.source_v3 import promote_source_v3

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--tokenizer", required=True)
    parser.add_argument("--cutoff-len", type=int, default=2048)
    parser.add_argument("--profile", default="phase-f-source-v3")
    parser.add_argument("--train-dataset-name", default="phase_f_source_v3_train")
    parser.add_argument(
        "--validation-dataset-name",
        default="phase_f_source_v3_validation",
    )
    args = parser.parse_args()

    tokenizer = AutoTokenizer.from_pretrained(
        args.tokenizer,
        trust_remote_code=True,
    )
    manifest = promote_source_v3(
        args.source_dir,
        args.output_dir,
        tokenizer=tokenizer,
        cutoff_len=args.cutoff_len,
        profile=args.profile,
        train_dataset_name=args.train_dataset_name,
        validation_dataset_name=args.validation_dataset_name,
    )
    print(
        "Phase F source-v3 frozen: "
        f"status={manifest['status']}, "
        f"train={manifest['counts']['train']}, "
        f"validation={manifest['counts']['validation']}, "
        f"challenge={manifest['counts']['challenge']}, "
        f"output={args.output_dir}"
    )


if __name__ == "__main__":
    main()
