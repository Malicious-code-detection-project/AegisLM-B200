from __future__ import annotations

import json
import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from aegislm.experiments import runtime
from aegislm.experiments.config import load_experiment_config


REPO_ROOT = Path(__file__).resolve().parents[1]


def _workspace(tmp_path: Path):
    config_path = tmp_path / "configs/experiment.yaml"
    manifest_path = tmp_path / runtime.RUNTIME_MANIFEST
    config_path.parent.mkdir(parents=True)
    manifest_path.parent.mkdir(parents=True)
    shutil.copyfile(REPO_ROOT / "configs/experiment.yaml", config_path)
    shutil.copyfile(REPO_ROOT / runtime.RUNTIME_MANIFEST, manifest_path)
    return load_experiment_config(config_path, repo_root=tmp_path)


def test_runtime_manifest_is_bound_to_experiment_pins(tmp_path: Path) -> None:
    config = _workspace(tmp_path)

    manifest, digest = runtime.load_runtime_manifest(config)

    assert manifest["environment_directory"] == ".venv-axolotl"
    assert (
        manifest["packages"]["axolotl"]["version"]
        == (config.data["framework"]["version"])
    )
    assert len(digest) == 64


def test_runtime_manifest_rejects_version_drift(tmp_path: Path) -> None:
    config = _workspace(tmp_path)
    path = tmp_path / runtime.RUNTIME_MANIFEST
    value = json.loads(path.read_text(encoding="utf-8"))
    value["packages"]["transformers"]["version"] = "0.0.0"
    path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(ValueError, match="version pin drift"):
        runtime.load_runtime_manifest(config)


class _Distribution:
    def __init__(self, package: dict[str, Any]) -> None:
        self.version = str(package.get("version", "0.0.dev0"))
        self.metadata = {"Name": package["distribution"]}
        self._package = package

    def read_text(self, name: str) -> str | None:
        if name != "direct_url.json" or "revision" not in self._package:
            return None
        return json.dumps(
            {
                "url": self._package["repository"],
                "vcs_info": {
                    "vcs": "git",
                    "commit_id": self._package["revision"],
                },
            }
        )


def test_runtime_verifies_same_environment_cli_and_two_b200s(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _workspace(tmp_path)
    manifest, _ = runtime.load_runtime_manifest(config)
    venv = tmp_path / ".venv-axolotl"
    executable = venv / "bin/axolotl"
    executable.parent.mkdir(parents=True)
    executable.write_text("", encoding="utf-8")
    packages = manifest["packages"]
    by_distribution = {
        package["distribution"]: _Distribution(package) for package in packages.values()
    }
    fake_torch = SimpleNamespace(
        version=SimpleNamespace(cuda="13.0"),
        cuda=SimpleNamespace(
            device_count=lambda: 2,
            get_device_name=lambda index: f"NVIDIA B200 GPU {index}",
        ),
    )
    monkeypatch.setattr(
        runtime.importlib.metadata,
        "distribution",
        lambda name: by_distribution[name],
    )
    monkeypatch.setattr(
        runtime.importlib,
        "import_module",
        lambda name: fake_torch if name == "torch" else SimpleNamespace(),
    )
    monkeypatch.setattr(
        runtime.shutil, "which", lambda name, path=None: str(executable)
    )
    monkeypatch.setattr(runtime.sys, "prefix", str(venv))
    monkeypatch.setattr(runtime.sys, "version_info", SimpleNamespace(major=3, minor=12))
    monkeypatch.setenv("AXOLOTL_DO_NOT_TRACK", "1")

    evidence = runtime.verify_runtime_environment(config)

    assert evidence["gpu_names"] == ["NVIDIA B200 GPU 0", "NVIDIA B200 GPU 1"]
    assert evidence["axolotl_cli"] == str(executable.resolve())


def test_runtime_rejects_axolotl_cli_outside_active_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _workspace(tmp_path)
    outside = tmp_path / "other/bin/axolotl"
    outside.parent.mkdir(parents=True)
    outside.write_text("", encoding="utf-8")
    monkeypatch.setattr(runtime.shutil, "which", lambda name, path=None: str(outside))
    monkeypatch.setattr(runtime.sys, "prefix", str(tmp_path / ".venv-axolotl"))
    monkeypatch.setattr(runtime.sys, "version_info", SimpleNamespace(major=3, minor=12))
    monkeypatch.setenv("AXOLOTL_DO_NOT_TRACK", "1")
    manifest, _ = runtime.load_runtime_manifest(config)
    packages = manifest["packages"]
    by_distribution = {
        package["distribution"]: _Distribution(package) for package in packages.values()
    }
    fake_torch = SimpleNamespace(
        version=SimpleNamespace(cuda="13.0"),
        cuda=SimpleNamespace(device_count=lambda: 0),
    )
    monkeypatch.setattr(
        runtime.importlib.metadata,
        "distribution",
        lambda name: by_distribution[name],
    )
    monkeypatch.setattr(
        runtime.importlib,
        "import_module",
        lambda name: fake_torch if name == "torch" else SimpleNamespace(),
    )

    with pytest.raises(RuntimeError, match="outside the active Python environment"):
        runtime.verify_runtime_environment(config, require_gpus=False)
