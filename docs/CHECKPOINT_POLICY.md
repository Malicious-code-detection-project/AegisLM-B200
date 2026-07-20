# Checkpoint Policy

## Policy

- LlamaFactory saves every 500 optimizer steps.
- `save_total_limit: 1` retains one complete local checkpoint.
- `save_only_model: false` preserves optimizer and trainer state for resume.
- The observer mirrors the newest completed checkpoint to persistent storage.
- Persistent storage also retains one complete checkpoint.
- The observer logs copy failures but never signals the training process.

The two physical copies serve different failure domains: the local copy is
fast to resume, and the persistent copy survives container replacement.

## Atomic Mirror

`scripts/checkpoint_mirror.py` waits until a checkpoint fingerprint stops
changing, copies it into a staging directory, verifies file count and bytes,
and atomically renames the staging directory. Older valid mirrors are removed
only after the new mirror is complete.

## Resume Modes

| Mode | Behavior |
| --- | --- |
| `fresh` | Refuse to start when any valid checkpoint exists. |
| `auto` | Use matching latest copies, or restore the persistent copy locally. |
| path | Validate and use the exact checkpoint path. |

If local and persistent steps disagree, `auto` refuses to guess. Inspect both
copies and pass an explicit trusted path.

```bash
bash scripts/run_train_qwen3_coder_next_full.sh --resume auto
```

This policy avoids the previous failure mode where a long run had no resumable
checkpoint while also preventing unbounded checkpoint growth.
