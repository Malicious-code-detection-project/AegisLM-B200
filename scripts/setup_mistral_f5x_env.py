"""Validate or install the isolated pinned Mistral F5-X Axolotl environment."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.experiments.config import load_experiment_config  # noqa: E402
from aegislm.experiments.runtime import (  # noqa: E402
    RUNTIME_MANIFEST,
    load_runtime_manifest,
)


APPROVAL_ENV = "AEGISLM_APPROVED_RUNTIME_SHA256"
CONFIG_PATH = REPO_ROOT / "configs/experiment.yaml"
BLACKWELL_BUILD_ENV = {
    # Build only for the B200 compute capability and serialize compilation so
    # FlashAttention's nvcc/cicc workers cannot exhaust host memory.
    "FLASH_ATTN_CUDA_ARCHS": "100",
    "MAX_JOBS": "4",
    "NVCC_THREADS": "1",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--action", choices=("validate", "install", "resume"), required=True
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = load_experiment_config(CONFIG_PATH, repo_root=REPO_ROOT)
    manifest, digest = load_runtime_manifest(config)
    _validate_host_tools(
        manifest,
        require_linux=args.action in {"install", "resume"},
        require_empty=args.action == "install",
        require_existing=args.action == "resume",
    )
    if args.action == "validate":
        print(f"Mistral runtime contract PASS: sha256={digest}")
        print(json.dumps(_install_plan(manifest), indent=2, sort_keys=True))
        return
    _require_approval(digest)
    _install(manifest, create_environment=args.action == "install")


def _validate_host_tools(
    manifest: dict[str, Any],
    *,
    require_linux: bool,
    require_empty: bool,
    require_existing: bool,
) -> None:
    if require_linux and platform.system() != "Linux":
        raise RuntimeError("Mistral runtime installation is allowed only on Linux B200")
    if shutil.which("uv") is None:
        raise RuntimeError("uv is required and must already be installed")
    environment = REPO_ROOT / manifest["environment_directory"]
    if require_empty and environment.exists():
        raise FileExistsError(
            f"exclusive Mistral runtime path already exists: {environment}"
        )
    if require_existing and not (environment / "bin/python").is_file():
        raise FileNotFoundError(f"resumable Mistral runtime is missing: {environment}")


def _require_approval(expected: str) -> None:
    approved = os.environ.get(APPROVAL_ENV, "")
    if not approved:
        raise RuntimeError(f"{APPROVAL_ENV} is required for installation")
    if approved != expected:
        raise RuntimeError(f"{APPROVAL_ENV} does not match {RUNTIME_MANIFEST}")


def _install_plan(manifest: dict[str, Any]) -> dict[str, Any]:
    packages = manifest["packages"]
    return {
        "environment_directory": manifest["environment_directory"],
        "python_version": manifest["python_version"],
        "torch_backend": manifest["torch_backend"],
        "requirements": [
            f"torch=={packages['torch']['version']}",
            f"axolotl[flash-attn]=={packages['axolotl']['version']}",
            f"transformers=={packages['transformers']['version']}",
            _vcs_requirement("cut-cross-entropy", packages["cut_cross_entropy"]),
        ],
        "build_environment": BLACKWELL_BUILD_ENV,
        "post_install_check": "uv pip check",
        "compatibility_gate": "pip-check, imports, CUDA 13.0, and two B200 GPUs",
    }


def _install(manifest: dict[str, Any], *, create_environment: bool) -> None:
    environment = REPO_ROOT / manifest["environment_directory"]
    python_path = environment / "bin/python"
    packages = manifest["packages"]
    process_env = os.environ.copy()
    process_env.pop("UV_TORCH_BACKEND", None)
    process_env.update(manifest["telemetry_environment"])
    process_env.update(BLACKWELL_BUILD_ENV)
    process_env["PATH"] = os.pathsep.join(
        (str(environment / "bin"), process_env.get("PATH", ""))
    )
    if create_environment:
        _run(
            [
                "uv",
                "venv",
                "--python",
                manifest["python_version"],
                str(environment),
            ],
            process_env,
        )
    _run(
        [
            "uv",
            "pip",
            "install",
            "--python",
            str(python_path),
            "packaging==26.0",
            "setuptools>=64",
            "setuptools-scm>=8",
            "wheel",
            "ninja",
            f"torch=={packages['torch']['version']}",
        ],
        process_env,
    )
    requirements = [
        f"axolotl[flash-attn]=={packages['axolotl']['version']}",
        f"transformers=={packages['transformers']['version']}",
        _vcs_requirement("cut-cross-entropy", packages["cut_cross_entropy"]),
    ]
    _run(
        [
            "uv",
            "pip",
            "install",
            "--python",
            str(python_path),
            "--no-build-isolation",
            *requirements,
        ],
        process_env,
    )
    _run(
        ["uv", "pip", "check", "--python", str(python_path)],
        process_env,
    )
    _run(
        [
            str(python_path),
            str(REPO_ROOT / "scripts/check_mistral_f5x_runtime.py"),
            "--require-gpus",
        ],
        process_env,
    )


def _vcs_requirement(name: str, package: dict[str, Any]) -> str:
    repository = package["repository"]
    revision = package["revision"]
    return f"{name} @ git+{repository}@{revision}"


def _run(command: list[str], process_env: dict[str, str]) -> None:
    subprocess.run(
        command,
        cwd=REPO_ROOT,
        env=process_env,
        check=True,
    )


def runtime_manifest_sha256() -> str:
    """Return the raw-byte identity used by operators and tests."""
    return hashlib.sha256((REPO_ROOT / RUNTIME_MANIFEST).read_bytes()).hexdigest()


if __name__ == "__main__":
    main()
