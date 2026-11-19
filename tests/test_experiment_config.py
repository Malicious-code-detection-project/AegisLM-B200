from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from aegislm.experiments.config import load_experiment_config


REPO_ROOT = Path(__file__).resolve().parents[1]
REAL_CONFIG = REPO_ROOT / "configs/experiment.yaml"


def _workspace(tmp_path: Path) -> Path:
    path = tmp_path / "configs/experiment.yaml"
    path.parent.mkdir(parents=True)
    shutil.copyfile(REAL_CONFIG, path)
    return path


def _read(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _write(path: Path, value: dict[str, Any]) -> None:
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")


def test_frozen_config_loads_and_validate_is_read_only(tmp_path: Path) -> None:
    path = _workspace(tmp_path)
    before = {item.relative_to(tmp_path) for item in tmp_path.rglob("*")}

    config = load_experiment_config(path, repo_root=tmp_path)

    after = {item.relative_to(tmp_path) for item in tmp_path.rglob("*")}
    assert config.active_profile == "g1-qlora-ddp"
    assert config.data["training"]["common"]["lora_dropout"] == 0.0
    assert before == after


def test_validate_cli_direct_script_passes_without_workspace_changes(
    tmp_path: Path,
) -> None:
    path = _workspace(tmp_path)
    before_bytes = path.read_bytes()
    before_paths = {item.relative_to(tmp_path) for item in tmp_path.rglob("*")}

    completed = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts/run_experiment.py"),
            "--config",
            str(path),
            "--action",
            "validate",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    after_paths = {item.relative_to(tmp_path) for item in tmp_path.rglob("*")}
    assert completed.returncode == 0, completed.stderr
    assert "Experiment config PASS" in completed.stdout
    assert path.read_bytes() == before_bytes
    assert after_paths == before_paths


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda value: value.pop("model"), "config.model is required"),
        (
            lambda value: value["model"].update({"unexpected": True}),
            "config.model.unexpected is not allowed",
        ),
        (
            lambda value: value["training"]["common"].update({"seed": "20260728"}),
            "config.training.common.seed must be 20260728",
        ),
    ],
)
def test_exact_schema_rejects_missing_extra_and_wrong_type(
    tmp_path: Path, mutate: Any, message: str
) -> None:
    path = _workspace(tmp_path)
    value = _read(path)
    mutate(value)
    _write(path, value)

    with pytest.raises(ValueError, match=message):
        load_experiment_config(path, repo_root=tmp_path)


@pytest.mark.parametrize(
    ("section", "key", "replacement"),
    [
        ("model", "training_revision", "main"),
        ("dataset", "train_sha256", "0" * 64),
        ("training.common", "lora_dropout", 0.05),
        ("gates", "g2", True),
    ],
)
def test_immutable_pin_and_future_gate_drift_is_rejected(
    tmp_path: Path, section: str, key: str, replacement: Any
) -> None:
    path = _workspace(tmp_path)
    value = _read(path)
    owner: dict[str, Any] = value
    for part in section.split("."):
        owner = owner[part]
    owner[key] = replacement
    _write(path, value)

    with pytest.raises(ValueError):
        load_experiment_config(path, repo_root=tmp_path)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("run_id", "../escape"),
        ("run_id", "Unsafe Run"),
    ],
)
def test_unsafe_run_id_is_rejected(
    tmp_path: Path, field: str, replacement: str
) -> None:
    path = _workspace(tmp_path)
    value = _read(path)
    value["experiment"][field] = replacement
    value["artifacts"]["run_directory"] = (
        f"training_artifacts/mistral-small-4-119b/{replacement}"
    )
    _write(path, value)

    with pytest.raises(ValueError, match="run_id is unsafe"):
        load_experiment_config(path, repo_root=tmp_path)


@pytest.mark.parametrize(
    "replacement",
    ["/private/model", "C:/private/model", "model/../private", "CHANGEME"],
)
def test_unsafe_or_placeholder_path_is_rejected(
    tmp_path: Path, replacement: str
) -> None:
    path = _workspace(tmp_path)
    value = _read(path)
    value["model"]["local_path"] = replacement
    _write(path, value)

    with pytest.raises(ValueError):
        load_experiment_config(path, repo_root=tmp_path)


def test_secret_like_field_is_rejected(tmp_path: Path) -> None:
    path = _workspace(tmp_path)
    value = _read(path)
    value["framework"]["api_key"] = "not-a-real-key"
    _write(path, value)

    with pytest.raises(ValueError, match="secret-like"):
        load_experiment_config(path, repo_root=tmp_path)
