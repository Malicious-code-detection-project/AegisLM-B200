#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

VENV="${PHASE_F_TRAINING_VENV:-.venv}"
PYTHON="$PWD/$VENV/bin/python"
export PATH="$PWD/$VENV/bin:$PATH"
export PYTHONPATH="$PWD/vendor/LlamaFactory/src${PYTHONPATH:+:$PYTHONPATH}"
export CUDA_VISIBLE_DEVICES="${CUDA_VISIBLE_DEVICES:-0,1}"
export WANDB_PROJECT="${WANDB_PROJECT:-malware-analysis-llm}"
export WANDB_LOG_MODEL="${WANDB_LOG_MODEL:-false}"
export WANDB_WATCH="${WANDB_WATCH:-false}"
export TOKENIZERS_PARALLELISM="${TOKENIZERS_PARALLELISM:-false}"

PERSISTENT_ROOT="${PERSISTENT_ROOT:-/NHNHOME/WORKSPACE/26moel002_ex07/LLM}"
PROFILE="${PHASE_F_PROFILE:-phase-f-source-v3}"
RUN_ID="${PHASE_F_RUN_ID:-q1-100}"
CONFIG="${PHASE_F_CONFIG:-configs/llamafactory/b200/qwen3_coder_next_phase_f_q1_100.yaml}"
DATASET_ROOT="${PHASE_F_DATASET_ROOT:-data/processed/$PROFILE}"
LOCAL_ROOT="${PHASE_F_LOCAL_ROOT:-training_artifacts/qwen3-coder-next/lora/$PROFILE/$RUN_ID}"
MIRROR_ROOT="${PHASE_F_MIRROR_ROOT:-$PERSISTENT_ROOT/TrainingArtifacts/checkpoints/qwen3-coder-next/lora/$PROFILE/$RUN_ID}"
RUN_ROOT="${PHASE_F_RUN_ROOT:-$PERSISTENT_ROOT/TrainingArtifacts/runs/qwen3-coder-next/lora/$PROFILE/$RUN_ID}"
EXPECTED_MANIFEST_SHA256="${PHASE_F_EXPECTED_MANIFEST_SHA256:-5b63098478c261e3031ce91848627dc06c6bee3e165724ee3f8ee8c60887cb8b}"
EXPECTED_SHA256SUMS_SHA256="${PHASE_F_EXPECTED_SHA256SUMS_SHA256:-38f62f2d10c456d84439fc3e618430b0f53bb057d66d45419be64a34b93d8b00}"
EXPECTED_TRAIN_DATASET="${PHASE_F_EXPECTED_TRAIN_DATASET:-phase_f_source_v3_train}"
EXPECTED_VALIDATION_DATASET="${PHASE_F_EXPECTED_VALIDATION_DATASET:-phase_f_source_v3_validation}"
EXPECTED_TRAIN_COUNT="${PHASE_F_EXPECTED_TRAIN_COUNT:-10000}"
EXPECTED_VALIDATION_COUNT="${PHASE_F_EXPECTED_VALIDATION_COUNT:-1000}"
EXPECTED_MAX_STEPS="${PHASE_F_EXPECTED_MAX_STEPS:-100}"
EXPECTED_SAVE_STEPS="${PHASE_F_EXPECTED_SAVE_STEPS:-100}"
EXPECTED_INITIAL_ADAPTER="${PHASE_F_EXPECTED_INITIAL_ADAPTER:-}"
EXPECTED_INITIAL_ADAPTER_SHA256="${PHASE_F_EXPECTED_INITIAL_ADAPTER_SHA256:-}"
EXPECTED_MIX_STRATEGY="${PHASE_F_EXPECTED_MIX_STRATEGY:-}"
EXPECTED_INTERLEAVE_PROBS="${PHASE_F_EXPECTED_INTERLEAVE_PROBS:-}"
SKIP_TRAINER_EVAL="${PHASE_F_SKIP_TRAINER_EVAL:-false}"
DIRTY_REASON="${GIT_DIRTY_REASON:-}"

mkdir -p "$RUN_ROOT" "$MIRROR_ROOT"

if pgrep -af "vllm serve|llamafactory-cli train" > "$RUN_ROOT/preflight-processes.txt"; then
  echo "Refusing Q1 start while serving or training processes are running." >&2
  cat "$RUN_ROOT/preflight-processes.txt" >&2
  exit 1
fi

GPU_USED=$(
  nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits |
    awk '{sum += $1} END {print sum + 0}'
)
if (( GPU_USED > 2048 )); then
  echo "Refusing Q1 start: aggregate GPU memory in use is ${GPU_USED} MiB." >&2
  exit 1
fi

PREFLIGHT_INITIAL_ADAPTER_ARGS=()
if [[ -n "$EXPECTED_INITIAL_ADAPTER" ]]; then
  PREFLIGHT_INITIAL_ADAPTER_ARGS=(
    --expected-initial-adapter "$EXPECTED_INITIAL_ADAPTER"
    --expected-initial-adapter-sha256 "$EXPECTED_INITIAL_ADAPTER_SHA256"
  )
fi
PREFLIGHT_MIX_ARGS=()
if [[ -n "$EXPECTED_MIX_STRATEGY" ]]; then
  PREFLIGHT_MIX_ARGS=(
    --expected-mix-strategy "$EXPECTED_MIX_STRATEGY"
    --expected-interleave-probs "$EXPECTED_INTERLEAVE_PROBS"
  )
fi
PREFLIGHT_EVAL_ARGS=()
if [[ "$SKIP_TRAINER_EVAL" == "true" ]]; then
  PREFLIGHT_EVAL_ARGS=(--skip-trainer-eval)
fi

"$PYTHON" scripts/preflight_phase_f_q1.py \
  --config "$CONFIG" \
  --dataset-dir "$DATASET_ROOT" \
  --report "$RUN_ROOT/preflight.json" \
  --nproc 2 \
  --dirty-reason "$DIRTY_REASON" \
  --expected-profile "$PROFILE" \
  --expected-manifest-sha256 "$EXPECTED_MANIFEST_SHA256" \
  --expected-sha256s-sha256 "$EXPECTED_SHA256SUMS_SHA256" \
  --expected-train-dataset "$EXPECTED_TRAIN_DATASET" \
  --expected-validation-dataset "$EXPECTED_VALIDATION_DATASET" \
  --expected-train-count "$EXPECTED_TRAIN_COUNT" \
  --expected-validation-count "$EXPECTED_VALIDATION_COUNT" \
  --expected-output-dir "$LOCAL_ROOT" \
  --run-profile "phase-f-$RUN_ID" \
  --expected-max-steps "$EXPECTED_MAX_STEPS" \
  --expected-save-steps "$EXPECTED_SAVE_STEPS" \
  "${PREFLIGHT_INITIAL_ADAPTER_ARGS[@]}" \
  "${PREFLIGHT_MIX_ARGS[@]}" \
  "${PREFLIGHT_EVAL_ARGS[@]}"

cp "$CONFIG" "$RUN_ROOT/training-config.yaml"
git rev-parse HEAD > "$RUN_ROOT/git-head.txt"
git status --porcelain=v1 > "$RUN_ROOT/git-status.txt"
git submodule status vendor/LlamaFactory > "$RUN_ROOT/llamafactory-revision.txt"
"$PYTHON" - <<'PY' > "$RUN_ROOT/python-freeze.txt"
from importlib.metadata import distributions

rows = sorted(
    f"{distribution.metadata['Name']}=={distribution.version}"
    for distribution in distributions()
    if distribution.metadata["Name"]
)
print("\n".join(rows))
PY
sha256sum \
  "$CONFIG" \
  configs/deepspeed/ds_z3_b200.json \
  aegislm/datasets/sard_juliet.py \
  aegislm/datasets/source.py \
  aegislm/datasets/source_compact.py \
  aegislm/datasets/source_decision.py \
  aegislm/datasets/source_evidence_artifact.py \
  aegislm/datasets/source_evidence_lines.py \
  aegislm/datasets/source_multitask.py \
  aegislm/datasets/source_v3.py \
  scripts/build_sard_juliet_source_dataset.py \
  scripts/build_source_compact_dataset.py \
  scripts/build_source_evidence_dataset.py \
  scripts/build_source_multitask_dataset.py \
  scripts/preflight_phase_f_q1.py \
  scripts/run_phase_f_q1_100.sh \
  "$DATASET_ROOT/dataset_manifest.json" \
  "$DATASET_ROOT/SHA256SUMS" \
  > "$RUN_ROOT/input-SHA256SUMS"
nvidia-smi --query-gpu=index,name,memory.used,memory.total,utilization.gpu \
  --format=csv,noheader > "$RUN_ROOT/gpu-before.csv"

"$PYTHON" scripts/check_memory_budget.py \
  --model-dir model/base/qwen3-coder-next \
  --nproc 2 \
  --watch \
  --interval-seconds 5 \
  --output-dir "$RUN_ROOT/memory" &
MEMORY_WATCHER_PID=$!

"$PYTHON" scripts/checkpoint_mirror.py \
  --local-root "$LOCAL_ROOT" \
  --mirror-root "$MIRROR_ROOT" \
  --watch \
  --interval-seconds "${CHECKPOINT_MIRROR_INTERVAL_SECONDS:-30}" \
  --log-path "$RUN_ROOT/checkpoint-mirror.jsonl" &
CHECKPOINT_WATCHER_PID=$!

cleanup() {
  kill "$MEMORY_WATCHER_PID" "$CHECKPOINT_WATCHER_PID" 2>/dev/null || true
  wait "$MEMORY_WATCHER_PID" "$CHECKPOINT_WATCHER_PID" 2>/dev/null || true
  "$PYTHON" scripts/checkpoint_mirror.py \
    --local-root "$LOCAL_ROOT" \
    --mirror-root "$MIRROR_ROOT" \
    --once \
    --log-path "$RUN_ROOT/checkpoint-mirror.jsonl" || true
}
trap cleanup EXIT INT TERM

set +e
llamafactory-cli train "$CONFIG" 2>&1 | tee "$RUN_ROOT/training.log"
TRAIN_STATUS=${PIPESTATUS[0]}
set -e
exit "$TRAIN_STATUS"
