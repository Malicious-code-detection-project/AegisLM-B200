#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v nvcc >/dev/null 2>&1; then
  echo "BLOCKED: nvcc is not installed. Stable profile remains usable." >&2
  exit 2
fi

UV_PROJECT_ENVIRONMENT=.venv-fast uv sync --frozen --group training
.venv-fast/bin/python -m pip install \
  "flash-linear-attention==0.3.2" \
  "causal-conv1d==1.6.2.post1"
.venv-fast/bin/python scripts/check_fast_kernels.py
