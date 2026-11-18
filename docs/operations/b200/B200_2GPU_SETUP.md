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

## Mistral F5-X unified experiment

The Qwen layout remains unchanged. `model` and `data` continue to link their
complete persistent roots, while `training_artifacts` remains a local directory.
Only `training_artifacts/mistral-small-4-119b` links to the matching directory
under the persistent `TrainingArtifacts` root. Creating these links remains an
operator-approved action; running the setup script is not part of CPU validation.

`configs/experiment.yaml` is the only human-edited Mistral experiment input.
Do not override its model, revision, profile, step count, run ID, or output path
on the command line.

The Mistral runtime is isolated in `.venv-axolotl`; never add Axolotl packages
to the Qwen `.venv`. Validate the repository-owned runtime contract before the
approved install.

The first compatibility-matrix run is retained as historical evidence. It
stopped before dependency resolution because the system `uv 0.9.3` did not
recognize the `cu130` backend selector. Do not reuse or delete its probe root.
The operator path now installs one stable stack directly into the isolated
`.venv-axolotl`; the existing Qwen `.venv` remains untouched.

```bash
python scripts/setup_mistral_f5x_env.py --action validate
export AEGISLM_APPROVED_RUNTIME_SHA256="$(sha256sum configs/runtime/mistral_f5x_environment.json | cut -d' ' -f1)"
python scripts/setup_mistral_f5x_env.py --action install
# If SSH was interrupted after .venv-axolotl was created, use the same hash:
python scripts/setup_mistral_f5x_env.py --action resume
export AXOLOTL_DO_NOT_TRACK=1
.venv-axolotl/bin/python scripts/check_mistral_f5x_runtime.py --require-gpus
```

The installer creates the environment exclusively, installs and checks PyTorch
2.12.1 first, then installs the stable `axolotl[flash-attn]==0.17.0` and
`transformers==5.9.0` pair. `UV_TORCH_BACKEND` is deliberately unset; the
post-install gate proves CUDA 13.0 and both B200 identities from the installed
PyTorch runtime. Any resolver, `uv pip check`, import, or GPU check failure
stops the run.

FlashAttention is built only for the installed B200 compute capability
(`FLASH_ATTN_CUDA_ARCHS=100`) with four Ninja jobs and one NVCC thread. This
avoids compiling unrelated GPU architectures and prevents host-memory
exhaustion during the source build. These settings affect installation only;
they do not limit training parallelism or GPU participation.

```bash
.venv-axolotl/bin/python scripts/run_experiment.py --config configs/experiment.yaml --action validate
export AEGISLM_APPROVED_CONFIG_SHA256="$(sha256sum configs/experiment.yaml | cut -d' ' -f1)"
.venv-axolotl/bin/python scripts/run_experiment.py --config configs/experiment.yaml --action render
# GPU approval, pinned environment, model/data snapshots, and full preflight are required first.
.venv-axolotl/bin/python scripts/run_experiment.py --config configs/experiment.yaml --action run
```

`render` creates a new immutable run directory. `run` rechecks the approved raw
YAML hash and all rendered files, validates every 10,000 train and 1,000
validation record with the local pinned tokenizer, and then uses the selected
two-GPU profile. The profiles must be attempted in order: `g1-qlora-ddp`, then a
newly approved config and run ID for `g1-bf16-lora-fsdp2`.
