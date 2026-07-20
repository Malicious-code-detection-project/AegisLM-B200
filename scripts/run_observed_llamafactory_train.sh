#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

PROFILE="stable"
RESUME_MODE="auto"
CONFIG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE="$2"; shift 2 ;;
    --resume) RESUME_MODE="$2"; shift 2 ;;
    --config) CONFIG="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

if [[ "$PROFILE" == "fast" ]]; then
  VENV=".venv-fast"
  RUN_SUFFIX="fast"
  CONFIG="${CONFIG:-configs/llamafactory/b200/qwen3_coder_next_lora_full_fast.yaml}"
else
  VENV=".venv"
  RUN_SUFFIX="stable"
  CONFIG="${CONFIG:-configs/llamafactory/b200/qwen3_coder_next_lora_full.yaml}"
fi

PYTHON="$PWD/$VENV/bin/python"
export PATH="$PWD/$VENV/bin:$PATH"
export PYTHONPATH="$PWD/vendor/LlamaFactory/src${PYTHONPATH:+:$PYTHONPATH}"
export CUDA_VISIBLE_DEVICES="${CUDA_VISIBLE_DEVICES:-0,1}"
export WANDB_PROJECT="${WANDB_PROJECT:-malware-analysis-llm}"
export WANDB_LOG_MODEL="${WANDB_LOG_MODEL:-false}"
export WANDB_WATCH="${WANDB_WATCH:-false}"
export TOKENIZERS_PARALLELISM="${TOKENIZERS_PARALLELISM:-false}"

PERSISTENT_ROOT="${PERSISTENT_ROOT:-/NHNHOME/WORKSPACE/26moel002_ex07/LLM}"
LOCAL_CHECKPOINT_ROOT="training_artifacts/qwen3-coder-next/lora/full"
MIRROR_ROOT="$PERSISTENT_ROOT/TrainingArtifacts/checkpoints/qwen3-coder-next/lora/full"
RUN_ROOT="$PERSISTENT_ROOT/TrainingArtifacts/runs/qwen3-coder-next/lora/full"
RUNTIME_CONFIG="$RUN_ROOT/runtime-${PROFILE}-$(date -u +%Y%m%dT%H%M%SZ).yaml"

"$PYTHON" scripts/check_environment.py \
  --profile "$PROFILE" \
  --require-model \
  --require-data \
  --require-secrets
"$PYTHON" scripts/patch_deepspeed_zero3_dtype.py --check

RESUME_PATH=$("$PYTHON" scripts/checkpoint_mirror.py \
  --local-root "$LOCAL_CHECKPOINT_ROOT" \
  --mirror-root "$MIRROR_ROOT" \
  --resolve "$RESUME_MODE")

RENDER_ARGS=(
  --input "$CONFIG"
  --output "$RUNTIME_CONFIG"
  --run-name-suffix "$RUN_SUFFIX"
)
if [[ -n "$RESUME_PATH" ]]; then
  RENDER_ARGS+=(--resume-from-checkpoint "$RESUME_PATH")
  echo "Resume checkpoint: $RESUME_PATH"
else
  echo "Starting without a checkpoint."
fi
"$PYTHON" scripts/render_training_config.py "${RENDER_ARGS[@]}"

mkdir -p "$RUN_ROOT" "$MIRROR_ROOT"
"$PYTHON" scripts/check_memory_budget.py \
  --model-dir model/base/qwen3-coder-next \
  --nproc 2 \
  --watch \
  --interval-seconds 5 \
  --output-dir "$RUN_ROOT/memory" &
MEMORY_WATCHER_PID=$!

"$PYTHON" scripts/checkpoint_mirror.py \
  --local-root "$LOCAL_CHECKPOINT_ROOT" \
  --mirror-root "$MIRROR_ROOT" \
  --watch \
  --interval-seconds "${CHECKPOINT_MIRROR_INTERVAL_SECONDS:-30}" \
  --log-path "$RUN_ROOT/checkpoint_mirror.jsonl" &
CHECKPOINT_WATCHER_PID=$!

cleanup() {
  kill "$MEMORY_WATCHER_PID" "$CHECKPOINT_WATCHER_PID" 2>/dev/null || true
  wait "$MEMORY_WATCHER_PID" "$CHECKPOINT_WATCHER_PID" 2>/dev/null || true
  "$PYTHON" scripts/checkpoint_mirror.py \
    --local-root "$LOCAL_CHECKPOINT_ROOT" \
    --mirror-root "$MIRROR_ROOT" \
    --once \
    --log-path "$RUN_ROOT/checkpoint_mirror.jsonl" || true
}
trap cleanup EXIT INT TERM

set +e
llamafactory-cli train "$RUNTIME_CONFIG" 2>&1 | tee "$RUN_ROOT/training-${PROFILE}.log"
TRAIN_STATUS=${PIPESTATUS[0]}
set -e
exit "$TRAIN_STATUS"
