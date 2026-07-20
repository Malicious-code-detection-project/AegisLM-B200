"""Check optional fast-kernel imports and one BF16 causal-conv backward pass."""

from __future__ import annotations

import argparse
import importlib.util
import shutil


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quiet", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    missing = [
        name
        for name in ("fla", "causal_conv1d")
        if importlib.util.find_spec(name) is None
    ]
    if missing:
        raise SystemExit(f"missing optional package(s): {', '.join(missing)}")
    if shutil.which("nvcc") is None:
        raise SystemExit("nvcc is not available for the fast profile")

    import torch
    from causal_conv1d import causal_conv1d_fn

    if not torch.cuda.is_available():
        raise SystemExit("CUDA is not available")
    x = torch.randn(2, 8, 32, device="cuda", dtype=torch.bfloat16, requires_grad=True)
    weight = torch.randn(8, 4, device="cuda", dtype=torch.bfloat16, requires_grad=True)
    output = causal_conv1d_fn(x, weight)
    output.float().sum().backward()
    if x.grad is None or weight.grad is None:
        raise SystemExit("BF16 causal-conv backward did not produce gradients")
    if not args.quiet:
        print("Fast profile imports and BF16 causal-conv forward/backward passed.")


if __name__ == "__main__":
    main()
