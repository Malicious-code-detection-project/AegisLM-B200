# B200 2-GPU Setup

## Target

- Project: `/home/daegu/workspace/AegisLM-B200`
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
| Model | `/NHNHOME/WORKSPACE/26moel002_ex07/LLM/Model` |
| Dataset | `/NHNHOME/WORKSPACE/26moel002_ex07/LLM/Data` |
| Checkpoints and logs | `/NHNHOME/WORKSPACE/26moel002_ex07/LLM/TrainingArtifacts` |
| HF cache | `/NHNHOME/WORKSPACE/26moel002_ex07/LLM/Cache/huggingface` |

`model` and `data` in the repository are symlinks to the first two paths.
The active checkpoint under `training_artifacts/` remains on the container
filesystem and is mirrored to persistent storage.

## Install

```bash
cd /home/daegu/workspace/AegisLM-B200
python scripts/setup_b200_workspace.py
cp .env.example .env
chmod 600 .env
uv sync --frozen --group training
.venv/bin/python scripts/patch_deepspeed_zero3_dtype.py --apply
.venv/bin/python scripts/patch_deepspeed_zero3_dtype.py --check
```

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
