# B200 2-GPU Setup

## Target

- Project: `${AEGISLM_PROJECT_ROOT}`
- GPUs: two NVIDIA B200 devices
- Effective container memory: 400 GiB
- Model: `Qwen/Qwen3-Coder-Next` BF16
- Method: LlamaFactory v0.9.5, LoRA, DeepSpeed ZeRO-3

The 400 GiB value is a cgroup limit, not host RAM. `free -h` describes the
host, while `memory.max` in the effective cgroup ancestor controls the
container.

## Persistent Layout

| Kind | Path |
| --- | --- |
| Model | `${AEGISLM_ARTIFACT_ROOT}/model` |
| Dataset | `${AEGISLM_DATA_ROOT}` |
| Checkpoints and logs | `${AEGISLM_ARTIFACT_ROOT}` |
| HF cache | `${AEGISLM_ARTIFACT_ROOT}/cache/huggingface` |

`model` and `data` in the repository are symlinks to the first two paths.
The active checkpoint under `training_artifacts/` remains on the container
filesystem and is mirrored to persistent storage.

## Install

```bash
export AEGISLM_PROJECT_ROOT="/path/to/AegisLM-B200"
export AEGISLM_DATA_ROOT="/path/to/LLM/Data"
export AEGISLM_ARTIFACT_ROOT="/path/to/LLM/TrainingArtifacts"

cd "${AEGISLM_PROJECT_ROOT}"
python scripts/setup_b200_workspace.py
bash scripts/setup_server_env.sh
uv sync --frozen --group training
.venv/bin/python scripts/patch_deepspeed_zero3_dtype.py --apply
.venv/bin/python scripts/patch_deepspeed_zero3_dtype.py --check
```

Set these variables to the approved server locations before running commands.
They keep server-specific absolute paths out of the repository while preserving
the project, data, and artifact-root roles.

Set `HF_TOKEN` and `WANDB_API_KEY` only in `.env`. Never commit the file.

## Preflight

```bash
set -a
. ./.env
set +a
.venv/bin/python scripts/check_environment.py --profile stable
```

Before training, add `--require-model --require-data --require-secrets`.
The check verifies the two GPUs, 400 GiB cgroup, symlinks, writable persistent
paths, free disk, tokens, model shards, dataset files, and LlamaFactory import.

## Data and Model

```bash
bash scripts/prepare_hf_full_v1.sh

.venv/bin/python scripts/download_hf_model.py \
  --variant qwen3-coder-next \
  --max-download-gib 170
```

The dataset build writes `dataset_manifest.json` with HF revisions, converted
and skipped counts, split seed, and SHA256 values. The model download writes
`aegislm_model_manifest.json` with the resolved model revision and shard state.
Local CTF and ZIP sources are `not_available` in the first profile.

## Boundary

Setup and preflight do not load the 80B model and do not start training. The
operator starts the foreground runner after reviewing the handoff checklist.
