# B200 Server Readiness Report

## Status

Verified on 2026-07-20 KST. The stable profile is ready for an operator-started
full training run. No model load or training process was started during setup.

| Check | Result |
| --- | --- |
| Project commit | `65112ae8e3467d052776636d5415826b419c517f` |
| LlamaFactory | v0.9.5 submodule |
| Stable environment | Ready |
| Fast environment | Blocked: `nvcc` is unavailable |
| GPUs | NVIDIA B200 x 2, 183,359 MiB each |
| Effective cgroup memory | 400.0 GiB |
| Persistent free space | approximately 8.6 TiB |
| HF/W&B variables | Present in mode-600 `.env`; values not recorded |
| DeepSpeed patch | Applied and verified |
| Linux tests | 100 passed |
| Ruff/mypy | Passed |

## Model

- ID: `Qwen/Qwen3-Coder-Next`
- Revision: `a7fbcb5c0e12d62a448eaa0e260346bf5dcc0feb`
- Safetensors: 159,358,031,480 bytes, 40 shards
- Missing shards: none
- Index SHA256: `e54c170589a729006db825100b4c69cf1c485ee89d3e8dd30aec9dccbf9cea1b`

## Dataset

Profile: `hf-full-v1`, split seed 42, ratios 0.8/0.1/0.1.

| Source | Revision | Converted | Skipped |
| --- | --- | ---: | ---: |
| `rezaduty/cybersecurity-qa-v2` | `4b6f278056b35bb28ddd685d28e1a030196fed47` | 709 | 0 |
| `bstee615/diversevul` | `3ed5dae8fdf3f6026f1e260f789656c4bb6d98e6` | 264,392 | 0 |
| `DynaOuchebara/BigVul` | `801dfa4f48205cb70976bea1e77d357178e68212` | 150,908 | 0 |

| Split | Records | SHA256 |
| --- | ---: | --- |
| Train | 332,807 | `f8e1abacf67896ed8249bb778d3a651d17c9739ff67f744a8321839ba99ad06f` |
| Validation | 41,600 | `0d5d6a4f1273901e50f8d382e2f7bcec2e3bbbc3361789985457e43a5126a8c4` |
| Test | 41,602 | `47e7379654af712fee9264682b0d3e8a5887cbcc60cac1ad483ff3b5a7532525` |

Local CTF and ZIP corpora are recorded as `not_available` for this profile.
The canonical files and LlamaFactory exports occupy approximately 2.6 GiB.

## Checkpoint Recovery

A dummy `checkpoint-500` was mirrored from the local artifact root to the
persistent artifact root. Both roots retained one physical checkpoint and
`--resolve auto` selected the matching step. Test artifacts were removed after
verification.

## Remaining Administrative Item

The organization disables repository deploy keys, and the local `gh` token did
not have `admin:public_key` scope for registering a server user key. Initial
deployment therefore used a verified Git bundle. Before the server needs to
pull future private-repository changes, register the existing server public key
or authenticate Git on the server. This does not block the prepared training
run at the current commit.

## Operator Command

Follow [B200_TRAINING_HANDOFF.md](B200_TRAINING_HANDOFF.md). The first run is:

```bash
cd /home/daegu/workspace/AegisLM-B200
bash scripts/run_train_qwen3_coder_next_full.sh \
  --profile stable \
  --resume fresh
```
