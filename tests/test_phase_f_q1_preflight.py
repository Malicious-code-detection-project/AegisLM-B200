from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from scripts import preflight_phase_f_q1 as preflight


@pytest.fixture(autouse=True)
def _isolate_preflight_test_cwd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        preflight,
        "_git",
        lambda args: "test-commit" if args == ["rev-parse", "HEAD"] else "",
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _dataset(tmp_path: Path) -> Path:
    root = tmp_path / "phase-f-source-v3"
    (root / "llamafactory").mkdir(parents=True)
    manifest = {
        "profile": "phase-f-source-v3",
        "approved_for_training": True,
    }
    (root / "dataset_manifest.json").write_text(
        json.dumps(manifest, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (root / "dataset_info.json").write_text(
        json.dumps(
            {
                "phase_f_source_v3_train": {"file_name": "llamafactory/train.jsonl"},
                "phase_f_source_v3_validation": {
                    "file_name": "llamafactory/validation.jsonl"
                },
            }
        ),
        encoding="utf-8",
    )
    (root / "llamafactory" / "train.jsonl").write_text(
        "{}\n" * 10000,
        encoding="utf-8",
    )
    (root / "llamafactory" / "validation.jsonl").write_text(
        "{}\n" * 1000,
        encoding="utf-8",
    )
    files = sorted(path for path in root.rglob("*") if path.is_file())
    (root / "SHA256SUMS").write_text(
        "".join(
            f"{_sha256(path)}  {path.relative_to(root).as_posix()}\n" for path in files
        ),
        encoding="utf-8",
    )
    return root


def _config(dataset_dir: Path) -> dict[str, Any]:
    return {
        "model_name_or_path": "model/base/qwen3-coder-next",
        "dataset": "phase_f_source_v3_train",
        "eval_dataset": "phase_f_source_v3_validation",
        "dataset_dir": str(dataset_dir),
        "template": "qwen3_nothink",
        "cutoff_len": 2048,
        "max_steps": 100,
        "resume_from_checkpoint": None,
        "output_dir": (
            "training_artifacts/qwen3-coder-next/lora/phase-f-source-v3/q1-100"
        ),
        "per_device_train_batch_size": 1,
        "gradient_accumulation_steps": 16,
        "save_steps": 100,
        "eval_steps": 25,
    }


def test_q1_preflight_accepts_only_the_frozen_no_resume_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dataset = _dataset(tmp_path)
    config_path = tmp_path / "q1.yaml"
    config_path.write_text(yaml.safe_dump(_config(dataset)), encoding="utf-8")
    monkeypatch.setattr(
        preflight,
        "EXPECTED_DATASET_MANIFEST_SHA256",
        _sha256(dataset / "dataset_manifest.json"),
    )
    monkeypatch.setattr(
        preflight,
        "EXPECTED_SHA256SUMS_SHA256",
        _sha256(dataset / "SHA256SUMS"),
    )

    report = preflight.validate_q1_preflight(
        config_path=config_path,
        dataset_dir=dataset,
        nproc=2,
        dirty_reason="test worktree",
    )

    assert report["status"] == "pass"
    assert report["global_batch_size"] == 32
    assert report["max_steps"] == 100
    assert report["resume_from_checkpoint"] is None


def test_q1_preflight_rejects_phase_e_resume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dataset = _dataset(tmp_path)
    config = _config(dataset)
    config["resume_from_checkpoint"] = (
        "training_artifacts/qwen3-coder-next/lora/full/checkpoint-10401"
    )
    config_path = tmp_path / "q1.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    monkeypatch.setattr(
        preflight,
        "EXPECTED_DATASET_MANIFEST_SHA256",
        _sha256(dataset / "dataset_manifest.json"),
    )
    monkeypatch.setattr(
        preflight,
        "EXPECTED_SHA256SUMS_SHA256",
        _sha256(dataset / "SHA256SUMS"),
    )

    with pytest.raises(ValueError, match="resume_from_checkpoint"):
        preflight.validate_q1_preflight(
            config_path=config_path,
            dataset_dir=dataset,
            nproc=2,
            dirty_reason="test worktree",
        )


def test_q1_preflight_accepts_an_isolated_remediation_revision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dataset = _dataset(tmp_path)
    manifest_path = dataset / "dataset_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["profile"] = "phase-f-source-v4"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n")
    files = sorted(
        path
        for path in dataset.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    )
    (dataset / "SHA256SUMS").write_text(
        "".join(
            f"{_sha256(path)}  {path.relative_to(dataset).as_posix()}\n"
            for path in files
        )
    )
    config = _config(dataset)
    config.update(
        {
            "dataset": "phase_f_source_v4_train",
            "eval_dataset": "phase_f_source_v4_validation",
            "output_dir": (
                "training_artifacts/qwen3-coder-next/lora/phase-f-source-v4/q1r1-100"
            ),
        }
    )
    dataset_info = json.loads((dataset / "dataset_info.json").read_text())
    dataset_info["phase_f_source_v4_train"] = dataset_info.pop(
        "phase_f_source_v3_train"
    )
    dataset_info["phase_f_source_v4_validation"] = dataset_info.pop(
        "phase_f_source_v3_validation"
    )
    (dataset / "dataset_info.json").write_text(json.dumps(dataset_info))
    files = sorted(
        path
        for path in dataset.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    )
    (dataset / "SHA256SUMS").write_text(
        "".join(
            f"{_sha256(path)}  {path.relative_to(dataset).as_posix()}\n"
            for path in files
        )
    )
    config_path = tmp_path / "q1r1.yaml"
    config_path.write_text(yaml.safe_dump(config))

    report = preflight.validate_q1_preflight(
        config_path=config_path,
        dataset_dir=dataset,
        nproc=2,
        dirty_reason="test remediation worktree",
        expected_profile="phase-f-source-v4",
        expected_manifest_sha256=_sha256(manifest_path),
        expected_sha256s_sha256=_sha256(dataset / "SHA256SUMS"),
        expected_train_dataset="phase_f_source_v4_train",
        expected_validation_dataset="phase_f_source_v4_validation",
        expected_output_dir=(
            "training_artifacts/qwen3-coder-next/lora/phase-f-source-v4/q1r1-100"
        ),
        run_profile="phase-f-q1r1-100",
    )

    assert report["profile"] == "phase-f-q1r1-100"
    assert report["output_dir"].endswith("phase-f-source-v4/q1r1-100")


def test_q1_preflight_accepts_a_short_semantic_preservation_canary(
    tmp_path: Path,
) -> None:
    dataset = _dataset(tmp_path)
    manifest_path = dataset / "dataset_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["profile"] = "phase-f-source-v4"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n")
    dataset_info_path = dataset / "dataset_info.json"
    dataset_info = json.loads(dataset_info_path.read_text())
    dataset_info["phase_f_source_v4_train"] = dataset_info.pop(
        "phase_f_source_v3_train"
    )
    dataset_info["phase_f_source_v4_validation"] = dataset_info.pop(
        "phase_f_source_v3_validation"
    )
    dataset_info_path.write_text(json.dumps(dataset_info))
    files = sorted(
        path
        for path in dataset.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    )
    (dataset / "SHA256SUMS").write_text(
        "".join(
            f"{_sha256(path)}  {path.relative_to(dataset).as_posix()}\n"
            for path in files
        )
    )
    config = _config(dataset)
    config.update(
        {
            "dataset": "phase_f_source_v4_train",
            "eval_dataset": "phase_f_source_v4_validation",
            "max_steps": 25,
            "save_steps": 25,
            "output_dir": (
                "training_artifacts/qwen3-coder-next/lora/phase-f-source-v4/q1r2-25"
            ),
        }
    )
    config_path = tmp_path / "q1r2.yaml"
    config_path.write_text(yaml.safe_dump(config))

    report = preflight.validate_q1_preflight(
        config_path=config_path,
        dataset_dir=dataset,
        nproc=2,
        dirty_reason="test short canary worktree",
        expected_profile="phase-f-source-v4",
        expected_manifest_sha256=_sha256(manifest_path),
        expected_sha256s_sha256=_sha256(dataset / "SHA256SUMS"),
        expected_train_dataset="phase_f_source_v4_train",
        expected_validation_dataset="phase_f_source_v4_validation",
        expected_output_dir=(
            "training_artifacts/qwen3-coder-next/lora/phase-f-source-v4/q1r2-25"
        ),
        run_profile="phase-f-q1r2-25",
        expected_max_steps=25,
        expected_save_steps=25,
    )

    assert report["max_steps"] == 25
    assert report["save_steps"] == 25


def test_q1_preflight_verifies_initial_adapter(tmp_path: Path) -> None:
    dataset = _dataset(tmp_path)
    adapter_dir = tmp_path / "decision-adapter"
    adapter_dir.mkdir()
    adapter_model = adapter_dir / "adapter_model.safetensors"
    adapter_model.write_bytes(b"approved adapter")
    config = _config(dataset)
    config["adapter_name_or_path"] = adapter_dir.as_posix()
    config_path = tmp_path / "q1-two-stage.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")

    report = preflight.validate_q1_preflight(
        config_path=config_path,
        dataset_dir=dataset,
        nproc=2,
        dirty_reason="test two-stage worktree",
        expected_manifest_sha256=_sha256(dataset / "dataset_manifest.json"),
        expected_sha256s_sha256=_sha256(dataset / "SHA256SUMS"),
        expected_initial_adapter=adapter_dir,
        expected_initial_adapter_sha256=_sha256(adapter_model),
    )

    assert report["initial_adapter"] == adapter_dir.as_posix()
    assert report["initial_adapter_sha256"] == _sha256(adapter_model)


def test_q1_preflight_splits_multitask_dataset_names() -> None:
    assert preflight._split_names("report_train, decision_train") == [
        "report_train",
        "decision_train",
    ]


def test_q1_preflight_accepts_explicit_quarantined_shard_counts(
    tmp_path: Path,
) -> None:
    dataset = _dataset(tmp_path)
    train_path = dataset / "llamafactory" / "train.jsonl"
    validation_path = dataset / "llamafactory" / "validation.jsonl"
    train_path.write_text("{}\n" * 9975, encoding="utf-8")
    validation_path.write_text("{}\n" * 996, encoding="utf-8")
    files = sorted(
        path
        for path in dataset.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    )
    (dataset / "SHA256SUMS").write_text(
        "".join(
            f"{_sha256(path)}  {path.relative_to(dataset).as_posix()}\n"
            for path in files
        ),
        encoding="utf-8",
    )
    config_path = tmp_path / "q1-evidence.yaml"
    config_path.write_text(yaml.safe_dump(_config(dataset)), encoding="utf-8")

    report = preflight.validate_q1_preflight(
        config_path=config_path,
        dataset_dir=dataset,
        nproc=2,
        dirty_reason="test evidence quarantine",
        expected_manifest_sha256=_sha256(dataset / "dataset_manifest.json"),
        expected_sha256s_sha256=_sha256(dataset / "SHA256SUMS"),
        expected_train_count=9975,
        expected_validation_count=996,
    )

    assert report["expected_train_count"] == 9975
    assert report["expected_validation_count"] == 996
