# Environment Profiles

## Stable

The stable profile uses the locked PyTorch and Transformers implementation.
Missing FLA or causal-conv kernels may produce a fallback warning. That warning
is not a crash and does not block training.

```bash
uv sync --frozen --group training
.venv/bin/python scripts/check_environment.py --profile stable
```

## Fast

The fast profile is isolated in `.venv-fast` and adds
`flash-linear-attention` and `causal-conv1d`. It must pass package imports and
a BF16 causal-conv forward/backward test before use.

```bash
bash scripts/setup_fast_profile.sh
.venv-fast/bin/python scripts/check_environment.py \
  --profile fast \
  --require-fast
```

The current B200 container has no `nvcc`, so the fast profile is **blocked**
until a CUDA 13-compatible build toolchain or compatible wheels are available.
This does not affect stable profile readiness.
