"""Pinned runtime verification for the Mistral F5-X experiment."""

from __future__ import annotations

import hashlib
import importlib
import importlib.metadata
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

from aegislm.experiments.config import ExperimentConfig


RUNTIME_MANIFEST = Path("configs/runtime/mistral_f5x_environment.json")
PACKAGE_KEYS = (
    "torch",
    "axolotl",
    "transformers",
    "cut_cross_entropy",
    "flash_attn",
    "bitsandbytes",
    "torchao",
)


def load_runtime_manifest(
    config: ExperimentConfig,
) -> tuple[dict[str, Any], str]:
    """Load the repository-owned runtime contract and bind it to the config pins."""
    path = config.repo_root / RUNTIME_MANIFEST
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid runtime manifest: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise ValueError("runtime manifest must be an object")
    expected_keys = {
        "schema_version",
        "python_version",
        "torch_backend",
        "cuda_version",
        "gpu_count",
        "gpu_name_contains",
        "environment_directory",
        "telemetry_environment",
        "packages",
    }
    if set(value) != expected_keys:
        raise ValueError("runtime manifest top-level schema drift")
    if value["schema_version"] != "aegislm.mistral-f5x-runtime.v1":
        raise ValueError("runtime manifest schema version drift")
    if value["environment_directory"] != ".venv-axolotl":
        raise ValueError("runtime environment directory drift")
    frozen_values = {
        "python_version": "3.12",
        "torch_backend": "cu130",
        "cuda_version": "13.0",
        "gpu_count": 2,
        "gpu_name_contains": "B200",
    }
    for key, expected in frozen_values.items():
        if value[key] != expected:
            raise ValueError(f"runtime immutable value drift: {key}")
    if value["telemetry_environment"] != {"AXOLOTL_DO_NOT_TRACK": "1"}:
        raise ValueError("runtime telemetry policy drift")
    packages = value.get("packages")
    if not isinstance(packages, dict) or tuple(packages) != PACKAGE_KEYS:
        raise ValueError("runtime package set or order drift")
    for key, package in packages.items():
        if not isinstance(package, dict):
            raise ValueError(f"runtime package contract is invalid: {key}")
        expected_package_keys = (
            {"distribution", "repository", "revision", "import"}
            if key == "cut_cross_entropy"
            else {"distribution", "version", "import"}
        )
        if set(package) != expected_package_keys:
            raise ValueError(f"runtime package schema drift: {key}")
    _validate_source_pins(config, packages)
    return value, hashlib.sha256(raw).hexdigest()


def verify_runtime_environment(
    config: ExperimentConfig, *, require_gpus: bool = True
) -> dict[str, Any]:
    """Prove that the active interpreter and CLI match the approved runtime."""
    manifest, manifest_sha256 = load_runtime_manifest(config)
    if (
        f"{sys.version_info.major}.{sys.version_info.minor}"
        != manifest["python_version"]
    ):
        raise RuntimeError("active Python does not match the runtime manifest")
    for key, expected in manifest["telemetry_environment"].items():
        if os.environ.get(key) != expected:
            raise RuntimeError(
                f"required runtime environment variable is missing: {key}"
            )

    observed: dict[str, Any] = {}
    imported: dict[str, Any] = {}
    for key in PACKAGE_KEYS:
        package = manifest["packages"][key]
        distribution_name = package["distribution"]
        try:
            distribution = importlib.metadata.distribution(distribution_name)
        except importlib.metadata.PackageNotFoundError as exc:
            raise RuntimeError(
                f"required runtime distribution is missing: {distribution_name}"
            ) from exc
        version = distribution.version
        expected_version = package.get("version")
        if (
            expected_version is not None
            and version.split("+", 1)[0] != expected_version
        ):
            raise RuntimeError(
                f"{distribution_name} version drift: {version}!={expected_version}"
            )
        revision = package.get("revision")
        if revision is not None:
            _verify_direct_url(distribution, package["repository"], revision)
        try:
            imported[key] = importlib.import_module(package["import"])
        except ImportError as exc:
            raise RuntimeError(
                f"required runtime import failed: {package['import']}"
            ) from exc
        observed[key] = {
            "distribution": distribution_name,
            "version": version,
            **({"revision": revision} if revision is not None else {}),
        }

    torch = imported["torch"]
    if torch.version.cuda != manifest["cuda_version"]:
        raise RuntimeError(
            f"PyTorch CUDA drift: {torch.version.cuda}!={manifest['cuda_version']}"
        )
    gpu_names: list[str] = []
    if require_gpus:
        count = int(torch.cuda.device_count())
        if count != manifest["gpu_count"]:
            raise RuntimeError(f"runtime requires exactly {manifest['gpu_count']} GPUs")
        gpu_names = [str(torch.cuda.get_device_name(index)) for index in range(count)]
        if any(manifest["gpu_name_contains"] not in name for name in gpu_names):
            raise RuntimeError("runtime GPU identity does not match the B200 contract")

    executable = shutil.which(
        "axolotl",
        path=str(Path(sys.prefix) / ("Scripts" if os.name == "nt" else "bin")),
    )
    if executable is None:
        raise RuntimeError("axolotl CLI is missing from the active Python environment")
    executable_path = Path(executable).resolve()
    try:
        executable_path.relative_to(Path(sys.prefix).resolve())
    except ValueError as exc:
        raise RuntimeError(
            "axolotl CLI is outside the active Python environment"
        ) from exc

    return {
        "schema_version": "aegislm.mistral-f5x-runtime-evidence.v1",
        "manifest_path": RUNTIME_MANIFEST.as_posix(),
        "manifest_sha256": manifest_sha256,
        "python": sys.version.split()[0],
        "python_prefix": str(Path(sys.prefix).resolve()),
        "cuda": torch.version.cuda,
        "gpu_names": gpu_names,
        "axolotl_cli": str(executable_path),
        "packages": observed,
    }


def _validate_source_pins(config: ExperimentConfig, packages: dict[str, Any]) -> None:
    framework = config.data["framework"]
    version_pins = {
        "axolotl": framework["version"],
        "transformers": framework["transformers_version"],
    }
    for name, expected_version in version_pins.items():
        package = packages.get(name)
        if not isinstance(package, dict):
            raise ValueError(f"runtime package contract is invalid: {name}")
        if package.get("version") != expected_version:
            raise ValueError(f"runtime version pin drift: {name}")

    package = packages.get("cut_cross_entropy")
    if not isinstance(package, dict):
        raise ValueError("runtime package contract is invalid: cut_cross_entropy")
    if not _same_repository(
        package.get("repository"), framework["cut_cross_entropy_repository"]
    ):
        raise ValueError("runtime repository pin drift: cut_cross_entropy")
    if package.get("revision") != framework["cut_cross_entropy_revision"]:
        raise ValueError("runtime revision pin drift: cut_cross_entropy")


def _verify_direct_url(
    distribution: importlib.metadata.Distribution,
    expected_repository: str,
    expected_revision: str,
) -> None:
    raw = distribution.read_text("direct_url.json")
    if raw is None:
        raise RuntimeError(f"{distribution.metadata['Name']} lacks direct_url evidence")
    try:
        direct_url = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("installed direct_url evidence is invalid") from exc
    vcs = direct_url.get("vcs_info") if isinstance(direct_url, dict) else None
    if (
        not isinstance(vcs, dict)
        or vcs.get("vcs") != "git"
        or vcs.get("commit_id") != expected_revision
        or not _same_repository(direct_url.get("url"), expected_repository)
    ):
        raise RuntimeError(
            f"{distribution.metadata['Name']} source revision evidence mismatch"
        )


def _same_repository(left: Any, right: Any) -> bool:
    def normalize(value: Any) -> str:
        if not isinstance(value, str):
            return ""
        normalized = value.lower().rstrip("/")
        if normalized.endswith(".git"):
            normalized = normalized[:-4]
        for prefix in ("git+https://github.com/", "https://github.com/"):
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix) :]
        return normalized

    return normalize(left) == normalize(right)
