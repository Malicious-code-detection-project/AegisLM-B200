from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

from aegislm.experiments.axolotl import render_axolotl_config
from aegislm.experiments.config import load_experiment_config
from scripts.download_hf_model import _write_model_manifest
from scripts import run_experiment


REPO_ROOT = Path(__file__).resolve().parents[1]
REAL_CONFIG = REPO_ROOT / "configs/experiment.yaml"


def _workspace(tmp_path: Path, profile: str = "g1-qlora-ddp") -> Path:
    path = tmp_path / "configs/experiment.yaml"
    path.parent.mkdir(parents=True)
    shutil.copyfile(REAL_CONFIG, path)
    if profile != "g1-qlora-ddp":
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
        value["experiment"]["active_profile"] = profile
        value["experiment"]["run_id"] = "g1-bf16-lora-fsdp2-20260806-001"
        value["artifacts"]["run_directory"] = (
            "training_artifacts/mistral-small-4-119b/g1-bf16-lora-fsdp2-20260806-001"
        )
        path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
    return path


def _approve(monkeypatch: pytest.MonkeyPatch, path: Path) -> str:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setenv("AEGISLM_APPROVED_CONFIG_SHA256", digest)
    return digest


def test_qlora_renderer_uses_ddp_default_without_fsdp_or_deepspeed(
    tmp_path: Path,
) -> None:
    config = load_experiment_config(_workspace(tmp_path), repo_root=tmp_path)

    rendered = render_axolotl_config(config)

    assert rendered["adapter"] == "qlora"
    assert rendered["load_in_4bit"] is True
    assert rendered["quantize_moe_experts"] is True
    assert rendered["lora_dropout"] == 0.0
    assert not {"fsdp", "fsdp_config", "fsdp_version", "deepspeed"} & rendered.keys()


def test_lora_renderer_uses_only_modern_fsdp2_keys(tmp_path: Path) -> None:
    config = load_experiment_config(
        _workspace(tmp_path, "g1-bf16-lora-fsdp2"), repo_root=tmp_path
    )

    rendered = render_axolotl_config(config)
    round_trip = yaml.safe_load(yaml.safe_dump(rendered, sort_keys=False))

    assert rendered["adapter"] == "lora"
    assert rendered["bf16"] is True
    assert rendered["fsdp_version"] == 2
    assert rendered["fsdp_config"]["reshard_after_forward"] is True
    assert (
        rendered["fsdp_config"]["transformer_layer_cls_to_wrap"]
        == "Mistral4DecoderLayer"
    )
    assert not {"fsdp", "deepspeed", "load_in_4bit", "quantize_moe_experts"} & (
        rendered.keys()
    )
    assert round_trip == rendered


def test_render_requires_approval_hash_and_is_exclusive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _workspace(tmp_path)
    config = load_experiment_config(path, repo_root=tmp_path)
    with pytest.raises(ValueError, match="is required"):
        run_experiment.render_run_directory(config)
    monkeypatch.setenv("AEGISLM_APPROVED_CONFIG_SHA256", "0" * 64)
    with pytest.raises(ValueError, match="does not match"):
        run_experiment.render_run_directory(config)
    approved = _approve(monkeypatch, path)

    run_directory = run_experiment.render_run_directory(config)

    assert (run_directory / "approved-config.yaml").read_bytes() == path.read_bytes()
    assert (run_directory / "approved-config.sha256").read_text().strip() == approved
    assert (run_directory / "logs").is_dir()
    assert json.loads((run_directory / "inventory.json").read_text())["status"] == (
        "static-preflight-pass"
    )
    with pytest.raises(FileExistsError):
        run_experiment.render_run_directory(config)


def test_run_rejects_tampering_and_already_started_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _workspace(tmp_path)
    _approve(monkeypatch, path)
    config = load_experiment_config(path, repo_root=tmp_path)
    run_directory = run_experiment.render_run_directory(config)
    approved_path = run_directory / "approved-config.yaml"
    approved_path.write_bytes(approved_path.read_bytes() + b"\n")

    with pytest.raises(ValueError, match="approved config bytes"):
        run_experiment.run_approved_experiment(config)

    approved_path.write_bytes(config.raw_bytes)
    (run_directory / "run.started.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(FileExistsError, match="execution evidence"):
        run_experiment.run_approved_experiment(config)


def test_run_uses_exact_two_gpu_command_and_adds_logs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _workspace(tmp_path)
    _approve(monkeypatch, path)
    config = load_experiment_config(path, repo_root=tmp_path)
    run_directory = run_experiment.render_run_directory(config)
    approved_cli = str((tmp_path / ".venv-axolotl/bin/axolotl").resolve())
    monkeypatch.setattr(
        run_experiment,
        "runtime_preflight",
        lambda _config: {
            "schema_version": "unit",
            "status": "pass",
            "runtime": {"axolotl_cli": approved_cli},
        },
    )
    calls: list[dict[str, Any]] = []

    def fake_run(command: list[str], **kwargs: Any) -> SimpleNamespace:
        calls.append({"command": command, **kwargs})
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(run_experiment.subprocess, "run", fake_run)

    assert run_experiment.run_approved_experiment(config) == 0
    assert calls[0]["command"] == [
        approved_cli,
        "train",
        "axolotl.generated.yaml",
        "--launcher",
        "torchrun",
        "--",
        "--nproc_per_node=2",
        "--nnodes=1",
    ]
    assert calls[0]["cwd"] == run_directory
    assert (run_directory / "run.started.json").is_file()
    assert (run_directory / "logs/preflight.runtime.json").is_file()
    assert (run_directory / "logs/train.stdout.log").is_file()
    assert (run_directory / "logs/train.stderr.log").is_file()


def test_renderer_rejects_paths_outside_run_namespace(tmp_path: Path) -> None:
    path = _workspace(tmp_path)
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    value["artifacts"]["run_directory"] = "training_artifacts/qwen/escape"
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")

    with pytest.raises(ValueError, match="frozen namespace"):
        load_experiment_config(path, repo_root=tmp_path)


def test_model_snapshot_verifier_checks_every_frozen_file(tmp_path: Path) -> None:
    config = load_experiment_config(_workspace(tmp_path), repo_root=tmp_path)
    model_path = tmp_path / config.data["model"]["local_path"]
    model_path.mkdir(parents=True)
    (model_path / "config.json").write_text("{}", encoding="utf-8")
    (model_path / "tokenizer_config.json").write_text("{}", encoding="utf-8")
    (model_path / "tokenizer.json").write_text("{}", encoding="utf-8")
    (model_path / "model-00001-of-00001.safetensors").write_bytes(b"weights")
    (model_path / "model.safetensors.index.json").write_text(
        json.dumps({"weight_map": {"weight": "model-00001-of-00001.safetensors"}}),
        encoding="utf-8",
    )
    _write_model_manifest(
        model_path,
        model_id=config.data["model"]["training_repo"],
        revision=config.data["model"]["training_revision"],
    )

    evidence = run_experiment._verify_model_snapshot(model_path, config)

    assert evidence["files_verified"] is True
    assert evidence["file_count"] == 5


def test_model_snapshot_verifier_rejects_weight_tampering(tmp_path: Path) -> None:
    config = load_experiment_config(_workspace(tmp_path), repo_root=tmp_path)
    model_path = tmp_path / config.data["model"]["local_path"]
    model_path.mkdir(parents=True)
    for name in ("config.json", "tokenizer_config.json", "tokenizer.json"):
        (model_path / name).write_text("{}", encoding="utf-8")
    weight = model_path / "model-00001-of-00001.safetensors"
    weight.write_bytes(b"weights")
    (model_path / "model.safetensors.index.json").write_text(
        json.dumps({"weight_map": {"weight": weight.name}}), encoding="utf-8"
    )
    _write_model_manifest(
        model_path,
        model_id=config.data["model"]["training_repo"],
        revision=config.data["model"]["training_revision"],
    )
    weight.write_bytes(b"tampered")

    with pytest.raises(ValueError, match="size mismatch|SHA-256 mismatch"):
        run_experiment._verify_model_snapshot(model_path, config)
