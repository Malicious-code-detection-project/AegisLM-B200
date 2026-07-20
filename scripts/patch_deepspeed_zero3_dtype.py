"""Apply, check, or restore the DeepSpeed 0.19.2 ZeRO-3 dtype fix."""

from __future__ import annotations

import argparse
import importlib.util
import shutil
from pathlib import Path


OLD_LOOP = "for psize in partition_sizes:"
NEW_LOOP = "for param_idx, psize in enumerate(partition_sizes):"
OLD_DTYPE = "dtype=param_list[0].ds_tensor.dtype"
NEW_DTYPE = "dtype=param_list[param_idx].ds_tensor.dtype"
OLD_SCALE_LOOP = "for psize in quantize_scale_sizes:"
NEW_SCALE_LOOP = "for param_idx, psize in enumerate(quantize_scale_sizes):"
OLD_SCALE_DTYPE = "dtype=param_list[0].ds_tensor.ds_quant_scale.dtype"
NEW_SCALE_DTYPE = "dtype=param_list[param_idx].ds_tensor.ds_quant_scale.dtype"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--apply", action="store_true")
    action.add_argument("--check", action="store_true")
    action.add_argument("--restore", action="store_true")
    return parser.parse_args()


def locate_partition_parameters() -> Path:
    spec = importlib.util.find_spec("deepspeed")
    if spec is None or spec.origin is None:
        raise RuntimeError("DeepSpeed is not installed in this Python environment.")
    package_root = Path(spec.origin).resolve().parent
    path = package_root / "runtime" / "zero" / "partition_parameters.py"
    if not path.is_file():
        raise RuntimeError(f"DeepSpeed partition_parameters.py not found: {path}")
    return path


def is_patched(text: str) -> bool:
    return all(
        marker in text
        for marker in (NEW_LOOP, NEW_DTYPE, NEW_SCALE_LOOP, NEW_SCALE_DTYPE)
    )


def apply_patch(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    if is_patched(text):
        print(f"DeepSpeed ZeRO-3 dtype patch already applied: {path}")
        return
    required = (OLD_LOOP, OLD_DTYPE, OLD_SCALE_LOOP, OLD_SCALE_DTYPE)
    if not all(marker in text for marker in required):
        raise RuntimeError("DeepSpeed source does not match the expected 0.19.2 code.")
    backup = path.with_suffix(path.suffix + ".aegislm-original")
    if not backup.exists():
        shutil.copy2(path, backup)
    patched = (
        text.replace(OLD_LOOP, NEW_LOOP, 1)
        .replace(OLD_DTYPE, NEW_DTYPE, 1)
        .replace(OLD_SCALE_LOOP, NEW_SCALE_LOOP, 1)
        .replace(OLD_SCALE_DTYPE, NEW_SCALE_DTYPE, 1)
    )
    path.write_text(patched, encoding="utf-8")
    if not is_patched(path.read_text(encoding="utf-8")):
        raise RuntimeError("DeepSpeed patch verification failed after write.")
    print(f"Applied DeepSpeed ZeRO-3 dtype patch: {path}")


def restore(path: Path) -> None:
    backup = path.with_suffix(path.suffix + ".aegislm-original")
    if not backup.is_file():
        raise RuntimeError(f"DeepSpeed patch backup not found: {backup}")
    shutil.copy2(backup, path)
    print(f"Restored DeepSpeed source: {path}")


def main() -> None:
    args = parse_args()
    path = locate_partition_parameters()
    if args.apply:
        apply_patch(path)
    elif args.restore:
        restore(path)
    else:
        if not is_patched(path.read_text(encoding="utf-8")):
            raise SystemExit("DeepSpeed ZeRO-3 dtype patch is not applied.")
        print(f"DeepSpeed ZeRO-3 dtype patch is applied: {path}")


if __name__ == "__main__":
    main()
