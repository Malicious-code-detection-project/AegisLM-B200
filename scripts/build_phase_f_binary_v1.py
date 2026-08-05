"""Build and freeze the Phase F binary-derived v1 dataset."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from transformers import AutoTokenizer

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.datasets.binary_v1 import (  # noqa: E402
    BINARY_V1_CONSISTENCY_PAIRS,
    BINARY_V1_CUTOFF_LEN,
    BINARY_V1_SEED,
    BINARY_V1_TEST_PAIRS,
    BINARY_V1_TRAIN_PAIRS,
    BINARY_V1_VALIDATION_PAIRS,
    freeze_binary_v1,
    prepare_binary_v1,
)
from aegislm.datasets.phase_f import load_jsonl  # noqa: E402


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--final-gate", type=Path, required=True)
    parser.add_argument("--model-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=BINARY_V1_SEED)
    parser.add_argument("--cutoff-len", type=int, default=BINARY_V1_CUTOFF_LEN)
    parser.add_argument("--train-pairs", type=int, default=BINARY_V1_TRAIN_PAIRS)
    parser.add_argument(
        "--validation-pairs",
        type=int,
        default=BINARY_V1_VALIDATION_PAIRS,
    )
    parser.add_argument("--test-pairs", type=int, default=BINARY_V1_TEST_PAIRS)
    parser.add_argument(
        "--consistency-pairs",
        type=int,
        default=BINARY_V1_CONSISTENCY_PAIRS,
    )
    return parser.parse_args()


def main() -> None:
    args = _arguments()
    gate = _load_object(args.final_gate)
    records = load_jsonl(args.records)
    tokenizer = AutoTokenizer.from_pretrained(
        args.model_dir,
        trust_remote_code=True,
        local_files_only=True,
    )
    prepared = prepare_binary_v1(
        records,
        gate,
        tokenizer=tokenizer,
        seed=args.seed,
        cutoff_len=args.cutoff_len,
        train_pairs=args.train_pairs,
        validation_pairs=args.validation_pairs,
        test_pairs=args.test_pairs,
        consistency_pairs=args.consistency_pairs,
    )
    manifest = freeze_binary_v1(
        prepared,
        args.output_dir,
        source_gate_path=str(args.final_gate.resolve()),
        source_records_path=str(args.records.resolve()),
    )
    print(
        "Phase F binary v1 frozen: "
        f"pairs={manifest['counts']['accepted_pairs']} "
        f"train={manifest['counts']['train_records']} "
        f"validation={manifest['counts']['validation_records']} "
        f"challenge={manifest['counts']['challenge_records']} "
        f"max_tokens={manifest['metrics']['maximum_token_count']}"
    )


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


if __name__ == "__main__":
    main()
