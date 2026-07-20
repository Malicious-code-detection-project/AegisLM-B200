#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

PYTHON="${PYTHON:-.venv/bin/python}"
PROCESSED_DIR="${DATASET_OUTPUT_DIR:-data/processed/hf-full-v1}"
LLAMAFACTORY_DATA="data/llamafactory"

"$PYTHON" scripts/build_security_dataset.py \
  --include-hf \
  --max-per-source -1 \
  --output-dir "$PROCESSED_DIR" \
  --split-ratios 0.8,0.1,0.1 \
  --seed 42

"$PYTHON" scripts/export_llamafactory_dataset.py \
  --input "$PROCESSED_DIR/aegislm_security_train.jsonl" \
  --output "$LLAMAFACTORY_DATA/aegislm_security_sft_train_full.json" \
  --dataset-name aegislm_security_sft_train_full

"$PYTHON" scripts/export_llamafactory_dataset.py \
  --input "$PROCESSED_DIR/aegislm_security_validation.jsonl" \
  --output "$LLAMAFACTORY_DATA/aegislm_security_sft_validation_full.json" \
  --dataset-name aegislm_security_sft_validation_full

"$PYTHON" scripts/prepare_llamafactory_data.py \
  --dataset-dir "$LLAMAFACTORY_DATA"
