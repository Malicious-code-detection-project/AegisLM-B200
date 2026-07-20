# B200 Qwen3-Coder-Next Training Handoff

## Fixed Configuration

| Setting | Value |
| --- | --- |
| Model | `Qwen/Qwen3-Coder-Next` BF16 |
| GPUs | B200 x 2 |
| Container memory | 400 GiB |
| Dataset | `hf-full-v1` |
| Epochs | 1.0 |
| Cutoff | 2048 |
| LoRA | rank 8, alpha 16, all targets |
| Per-device batch | 1 |
| Gradient accumulation | 16 |
| Global batch | `1 x 2 x 16 = 32` |
| Checkpoint | every 500 steps, latest one retained per storage tier |

## Operator Checklist

```bash
cd /home/daegu/workspace/AegisLM-B200
set -a
. ./.env
set +a

.venv/bin/python scripts/check_environment.py \
  --profile stable \
  --require-model \
  --require-data \
  --require-secrets
```

Review that every required line is `OK`. Then start the first run in the
foreground:

```bash
bash scripts/run_train_qwen3_coder_next_full.sh \
  --profile stable \
  --resume fresh
```

For a resumed run:

```bash
bash scripts/run_train_qwen3_coder_next_full.sh \
  --profile stable \
  --resume auto
```

## Observe

- W&B: loss, learning rate, epoch, step, throughput
- Training log: `TrainingArtifacts/runs/qwen3-coder-next/lora/full/`
- Memory telemetry: the `memory/` directory below the same run root
- Persistent checkpoint: `TrainingArtifacts/checkpoints/qwen3-coder-next/lora/full/`
- Local checkpoint: `training_artifacts/qwen3-coder-next/lora/full/`

The memory and checkpoint watchers are observe-only. They do not send signals
to the trainer. Stopping and restarting training remains the operator's
decision.

## First Failure Triage

1. Record the foreground traceback and timestamp.
2. Compare `memory.events` before and after the failure.
3. Check the latest memory JSONL for cgroup and per-process RSS.
4. Verify whether a complete `checkpoint-N` exists locally and persistently.
5. Do not delete either checkpoint until `checkpoint_mirror.py --resolve auto`
   has reported whether they agree.

Actual model loading and training are intentionally outside setup automation.
