"""Preflight checks for the two-GPU B200 training workspace."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from aegislm.runtime.memory_budget import (  # noqa: E402
    bytes_to_gib,
    effective_memory_limit,
    inspect_model_dir,
    read_cgroup_chain,
)


DEFAULT_PERSISTENT_ROOT = Path("/NHNHOME/WORKSPACE/26moel002_ex07/LLM")


@dataclass(frozen=True)
class CheckResult:
    status: str
    message: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", choices=("stable", "fast"), default="stable")
    parser.add_argument(
        "--persistent-root",
        type=Path,
        default=Path(os.environ.get("PERSISTENT_ROOT", DEFAULT_PERSISTENT_ROOT)),
    )
    parser.add_argument(
        "--expected-cuda-devices",
        type=int,
        default=int(os.environ.get("EXPECTED_CUDA_DEVICES", "2")),
    )
    parser.add_argument(
        "--expected-cgroup-memory-gib",
        type=float,
        default=float(os.environ.get("EXPECTED_CGROUP_MEMORY_GIB", "400")),
    )
    parser.add_argument("--require-model", action="store_true")
    parser.add_argument("--require-data", action="store_true")
    parser.add_argument("--require-secrets", action="store_true")
    parser.add_argument("--require-fast", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    project_root = args.project_root.resolve()
    persistent_root = args.persistent_root.resolve()
    venv = project_root / (".venv-fast" if args.profile == "fast" else ".venv")
    fast_blocked = args.profile == "fast" and not venv.exists()
    python = (
        project_root / ".venv" / "bin" / "python"
        if fast_blocked
        else venv / "bin" / "python"
    )

    checks = [
        _profile_venv_check(
            venv,
            profile=args.profile,
            require_fast=args.require_fast,
        ),
        _path_check(
            project_root / "vendor" / "LlamaFactory",
            "pinned LlamaFactory checkout",
            required=True,
        ),
        _symlink_check(project_root / "model", persistent_root / "Model"),
        _symlink_check(project_root / "data", persistent_root / "Data"),
        _writable_check(persistent_root / "TrainingArtifacts"),
        _disk_check(persistent_root, minimum_gib=200.0),
        _git_ignore_check(project_root, "model"),
        _git_ignore_check(project_root, "data"),
        _git_ignore_check(project_root, "training_artifacts"),
        _env_check("HF_TOKEN", required=args.require_secrets, secret=True),
        _env_check("WANDB_API_KEY", required=args.require_secrets, secret=True),
        _env_check("WANDB_PROJECT", required=False, secret=False),
        _cuda_check(python, args.expected_cuda_devices),
        _cgroup_check(args.expected_cgroup_memory_gib),
        _llamafactory_check(python, project_root),
        _model_check(
            project_root / "model" / "base" / "qwen3-coder-next", args.require_model
        ),
        _data_check(project_root / "data" / "llamafactory", args.require_data),
    ]
    if args.profile == "fast":
        if fast_blocked:
            checks.append(
                CheckResult(
                    "FAIL" if args.require_fast else "BLOCKED",
                    "fast profile is not installed; nvcc/toolchain setup is required",
                )
            )
        else:
            checks.append(_fast_profile_check(python, required=args.require_fast))

    for check in checks:
        print(f"[{check.status}] {check.message}")
    if any(check.status == "FAIL" for check in checks):
        raise SystemExit(1)


def _path_check(path: Path, label: str, *, required: bool) -> CheckResult:
    if path.exists():
        return CheckResult("OK", f"{label}: {path}")
    return CheckResult("FAIL" if required else "WARN", f"missing {label}: {path}")


def _profile_venv_check(
    path: Path,
    *,
    profile: str,
    require_fast: bool,
) -> CheckResult:
    if path.exists():
        return CheckResult("OK", f"{profile} virtualenv: {path}")
    if profile == "fast" and not require_fast:
        return CheckResult("BLOCKED", f"fast virtualenv is not installed: {path}")
    return CheckResult("FAIL", f"missing {profile} virtualenv: {path}")


def _symlink_check(link: Path, target: Path) -> CheckResult:
    if not link.is_symlink():
        return CheckResult("FAIL", f"expected symlink is missing: {link}")
    if link.resolve() != target.resolve():
        return CheckResult(
            "FAIL", f"symlink target mismatch: {link} -> {link.resolve()}"
        )
    return CheckResult("OK", f"symlink: {link} -> {target.resolve()}")


def _writable_check(path: Path) -> CheckResult:
    if path.is_dir() and os.access(path, os.W_OK):
        return CheckResult("OK", f"writable persistent path: {path}")
    return CheckResult("FAIL", f"persistent path is not writable: {path}")


def _disk_check(path: Path, *, minimum_gib: float) -> CheckResult:
    try:
        free = shutil.disk_usage(path).free
    except OSError as exc:
        return CheckResult("FAIL", f"disk check failed for {path}: {exc}")
    free_gib = bytes_to_gib(free) or 0.0
    status = "OK" if free_gib >= minimum_gib else "FAIL"
    return CheckResult(status, f"persistent free space: {free_gib:.1f} GiB")


def _git_ignore_check(project_root: Path, relative: str) -> CheckResult:
    result = subprocess.run(
        ["git", "check-ignore", "-q", relative],
        cwd=project_root,
        check=False,
    )
    status = "OK" if result.returncode == 0 else "FAIL"
    return CheckResult(status, f"Git ignore policy for {relative}")


def _env_check(name: str, *, required: bool, secret: bool) -> CheckResult:
    value = os.environ.get(name)
    if value:
        return CheckResult("OK", f"{name}: {'<set>' if secret else value}")
    return CheckResult("FAIL" if required else "WARN", f"{name} is not set")


def _cuda_check(python: Path, expected: int) -> CheckResult:
    if not python.is_file():
        return CheckResult("FAIL", f"Python executable is missing: {python}")
    result = subprocess.run(
        [
            str(python),
            "-c",
            "import torch; print(int(torch.cuda.is_available()), torch.cuda.device_count())",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        return CheckResult("FAIL", f"CUDA check failed: {result.stderr.strip()}")
    available, _, raw_count = result.stdout.strip().partition(" ")
    try:
        count = int(raw_count)
    except ValueError:
        return CheckResult(
            "FAIL", f"unexpected CUDA check output: {result.stdout.strip()}"
        )
    if available != "1" or count != expected:
        return CheckResult(
            "FAIL",
            f"CUDA devices: available={available}, count={count}, expected={expected}",
        )
    return CheckResult("OK", f"CUDA device count: {count}")


def _cgroup_check(expected_gib: float) -> CheckResult:
    snapshots = read_cgroup_chain()
    limit, path = effective_memory_limit(snapshots)
    actual = bytes_to_gib(limit)
    if actual is None:
        return CheckResult("FAIL", "no finite cgroup memory.max was detected")
    if abs(actual - expected_gib) > 1.0:
        return CheckResult(
            "FAIL",
            f"effective cgroup memory.max is {actual:.1f} GiB at {path}; expected {expected_gib:.1f} GiB",
        )
    return CheckResult("OK", f"effective cgroup memory.max: {actual:.1f} GiB at {path}")


def _llamafactory_check(python: Path, project_root: Path) -> CheckResult:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(project_root / "vendor" / "LlamaFactory" / "src")
    result = subprocess.run(
        [str(python), "-c", "import llamafactory; print(llamafactory.__version__)"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
        env=env,
    )
    if result.returncode:
        return CheckResult(
            "FAIL", f"LlamaFactory import failed: {result.stderr.strip()}"
        )
    return CheckResult("OK", f"LlamaFactory version: {result.stdout.strip()}")


def _model_check(model_dir: Path, required: bool) -> CheckResult:
    total, shard_count, missing = inspect_model_dir(model_dir)
    if missing:
        return CheckResult(
            "FAIL", f"Qwen3-Coder-Next missing shards: {', '.join(missing)}"
        )
    if not model_dir.is_dir() or shard_count == 0:
        return CheckResult(
            "FAIL" if required else "WARN",
            f"Qwen3-Coder-Next is not ready: {model_dir}",
        )
    return CheckResult(
        "OK", f"Qwen3-Coder-Next: {bytes_to_gib(total):.1f} GiB, {shard_count} shards"
    )


def _data_check(dataset_dir: Path, required: bool) -> CheckResult:
    required_names = (
        "dataset_info.json",
        "aegislm_security_sft_train_full.json",
        "aegislm_security_sft_validation_full.json",
    )
    missing = [name for name in required_names if not (dataset_dir / name).is_file()]
    if missing:
        return CheckResult(
            "FAIL" if required else "WARN",
            f"dataset files not ready: {', '.join(missing)}",
        )
    return CheckResult("OK", f"full dataset registration: {dataset_dir}")


def _fast_profile_check(python: Path, *, required: bool) -> CheckResult:
    nvcc = shutil.which("nvcc")
    result = subprocess.run(
        [str(python), "scripts/check_fast_kernels.py", "--quiet"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 0:
        return CheckResult("OK", "fast kernels import and BF16 test passed")
    reason = result.stderr.strip() or result.stdout.strip() or "kernel check failed"
    if nvcc is None:
        reason = f"blocked: nvcc is missing; {reason}"
    return CheckResult("FAIL" if required else "BLOCKED", reason)


if __name__ == "__main__":
    main()
