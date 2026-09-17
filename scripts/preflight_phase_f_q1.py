"""Validate the immutable Phase F Q1 dataset and no-resume training contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

import yaml

EXPECTED_PROFILE = "phase-f-source-v3"
EXPECTED_DATASET_MANIFEST_SHA256 = (
    "5b63098478c261e3031ce91848627dc06c6bee3e165724ee3f8ee8c60887cb8b"
)
EXPECTED_SHA256SUMS_SHA256 = (
    "38f62f2d10c456d84439fc3e618430b0f53bb057d66d45419be64a34b93d8b00"
)
EXPECTED_OUTPUT_DIR = (
    "training_artifacts/qwen3-coder-next/lora/phase-f-source-v3/q1-100"
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--dataset-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--nproc", type=int, default=2)
    parser.add_argument("--dirty-reason", default="")
    parser.add_argument("--expected-profile", default=EXPECTED_PROFILE)
    parser.add_argument(
        "--expected-manifest-sha256",
        default=EXPECTED_DATASET_MANIFEST_SHA256,
    )
    parser.add_argument(
        "--expected-sha256s-sha256",
        default=EXPECTED_SHA256SUMS_SHA256,
    )
    parser.add_argument("--expected-train-dataset", default="phase_f_source_v3_train")
    parser.add_argument(
        "--expected-validation-dataset",
        default="phase_f_source_v3_validation",
    )
    parser.add_argument("--expected-train-count", type=int, default=10000)
    parser.add_argument("--expected-validation-count", type=int, default=1000)
    parser.add_argument("--expected-output-dir", default=EXPECTED_OUTPUT_DIR)
    parser.add_argument("--run-profile", default="phase-f-q1-100")
    parser.add_argument("--expected-max-steps", type=int, default=100)
    parser.add_argument("--expected-save-steps", type=int, default=100)
    parser.add_argument("--expected-initial-adapter", type=Path)
    parser.add_argument("--expected-initial-adapter-sha256")
    parser.add_argument("--expected-mix-strategy")
    parser.add_argument("--expected-interleave-probs")
    parser.add_argument("--skip-trainer-eval", action="store_true")
    args = parser.parse_args()

    report = validate_q1_preflight(
        config_path=args.config,
        dataset_dir=args.dataset_dir,
        nproc=args.nproc,
        dirty_reason=args.dirty_reason,
        expected_profile=args.expected_profile,
        expected_manifest_sha256=args.expected_manifest_sha256,
        expected_sha256s_sha256=args.expected_sha256s_sha256,
        expected_train_dataset=args.expected_train_dataset,
        expected_validation_dataset=args.expected_validation_dataset,
        expected_train_count=args.expected_train_count,
        expected_validation_count=args.expected_validation_count,
        expected_output_dir=args.expected_output_dir,
        run_profile=args.run_profile,
        expected_max_steps=args.expected_max_steps,
        expected_save_steps=args.expected_save_steps,
        expected_initial_adapter=args.expected_initial_adapter,
        expected_initial_adapter_sha256=args.expected_initial_adapter_sha256,
        expected_mix_strategy=args.expected_mix_strategy,
        expected_interleave_probs=args.expected_interleave_probs,
        skip_trainer_eval=args.skip_trainer_eval,
    )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Phase F Q1 preflight PASS: "
        f"global_batch={report['global_batch_size']}, "
        f"max_steps={report['max_steps']}, report={args.report}"
    )


def validate_q1_preflight(
    *,
    config_path: Path,
    dataset_dir: Path,
    nproc: int,
    dirty_reason: str,
    expected_profile: str | None = None,
    expected_manifest_sha256: str | None = None,
    expected_sha256s_sha256: str | None = None,
    expected_train_dataset: str = "phase_f_source_v3_train",
    expected_validation_dataset: str = "phase_f_source_v3_validation",
    expected_train_count: int = 10000,
    expected_validation_count: int = 1000,
    expected_output_dir: str | None = None,
    run_profile: str = "phase-f-q1-100",
    expected_max_steps: int = 100,
    expected_save_steps: int = 100,
    expected_initial_adapter: Path | None = None,
    expected_initial_adapter_sha256: str | None = None,
    expected_mix_strategy: str | None = None,
    expected_interleave_probs: str | None = None,
    skip_trainer_eval: bool = False,
) -> dict[str, Any]:
    expected_profile = expected_profile or EXPECTED_PROFILE
    expected_manifest_sha256 = (
        expected_manifest_sha256 or EXPECTED_DATASET_MANIFEST_SHA256
    )
    expected_sha256s_sha256 = expected_sha256s_sha256 or EXPECTED_SHA256SUMS_SHA256
    expected_output_dir = expected_output_dir or EXPECTED_OUTPUT_DIR
    dataset_dir = dataset_dir.resolve()
    config = _load_mapping(config_path)
    manifest_path = dataset_dir / "dataset_manifest.json"
    sums_path = dataset_dir / "SHA256SUMS"
    manifest = _load_mapping(manifest_path)
    errors: list[str] = []

    if _sha256_file(manifest_path) != expected_manifest_sha256:
        errors.append("dataset manifest SHA-256 does not match the F3 freeze")
    if _sha256_file(sums_path) != expected_sha256s_sha256:
        errors.append("SHA256SUMS SHA-256 does not match the F3 freeze")
    errors.extend(_verify_sha256s(dataset_dir))
    if manifest.get("profile") != expected_profile:
        errors.append(f"dataset profile is not {expected_profile}")
    if manifest.get("approved_for_training") is not True:
        errors.append("dataset is not approved for training")

    expected: dict[str, Any] = {
        "model_name_or_path": "model/base/qwen3-coder-next",
        "dataset": expected_train_dataset,
        "template": "qwen3_nothink",
        "cutoff_len": 2048,
        "max_steps": expected_max_steps,
        "resume_from_checkpoint": None,
    }
    if skip_trainer_eval:
        expected["eval_dataset"] = None
        expected["eval_strategy"] = "no"
        expected["do_eval"] = False
    else:
        expected["eval_dataset"] = expected_validation_dataset
    for key, value in expected.items():
        if config.get(key) != value:
            errors.append(f"config {key} must be {value!r}")
    configured_dataset_dir = Path(str(config.get("dataset_dir") or "")).resolve()
    if configured_dataset_dir != dataset_dir:
        errors.append("config dataset_dir does not resolve to the approved F3 artifact")
    output_dir = Path(str(config.get("output_dir") or ""))
    normalized_output = output_dir.as_posix()
    if normalized_output != expected_output_dir:
        errors.append("Q1 output_dir is outside the isolated Phase F namespace")
    if output_dir.exists():
        errors.append(f"Q1 output_dir already exists: {output_dir}")
    if "checkpoint-10401" in json.dumps(config) or "/lora/full" in normalized_output:
        errors.append("Phase E checkpoint/output namespace is forbidden")
    initial_adapter_sha256 = None
    if expected_initial_adapter is not None:
        configured_adapter = Path(str(config.get("adapter_name_or_path") or ""))
        if configured_adapter.resolve() != expected_initial_adapter.resolve():
            errors.append(
                "config adapter_name_or_path does not match the approved input"
            )
        adapter_model = expected_initial_adapter / "adapter_model.safetensors"
        if not adapter_model.is_file():
            errors.append(f"initial adapter model is missing: {adapter_model}")
        else:
            initial_adapter_sha256 = _sha256_file(adapter_model)
            if (
                not expected_initial_adapter_sha256
                or initial_adapter_sha256 != expected_initial_adapter_sha256
            ):
                errors.append("initial adapter SHA-256 does not match")
    elif config.get("adapter_name_or_path") is not None:
        errors.append("unexpected initial adapter in config")

    dataset_info = _load_mapping(dataset_dir / "dataset_info.json")
    dataset_counts = [
        *[
            (name, expected_train_count)
            for name in _split_names(expected_train_dataset)
        ],
        *[
            (name, expected_validation_count)
            for name in _split_names(expected_validation_dataset)
        ],
    ]
    for name, count in dataset_counts:
        entry = dataset_info.get(name)
        if not isinstance(entry, dict):
            errors.append(f"dataset_info entry missing: {name}")
            continue
        file_path = dataset_dir / str(entry.get("file_name") or "")
        if not file_path.is_file():
            errors.append(f"dataset shard missing: {file_path}")
        elif _jsonl_count(file_path) != count:
            errors.append(f"dataset shard count mismatch: {file_path}")

    per_device = int(config.get("per_device_train_batch_size") or 0)
    accumulation = int(config.get("gradient_accumulation_steps") or 0)
    global_batch = per_device * accumulation * nproc
    if global_batch != 32:
        errors.append(f"global batch must be 32, got {global_batch}")
    if int(config.get("save_steps") or 0) != expected_save_steps:
        errors.append(f"Q1 must save at step {expected_save_steps}")
    if not skip_trainer_eval and int(config.get("eval_steps") or 0) > 25:
        errors.append("Q1 must evaluate at least every 25 steps")
    if expected_mix_strategy is not None:
        if config.get("mix_strategy") != expected_mix_strategy:
            errors.append(f"config mix_strategy must be {expected_mix_strategy!r}")
        if config.get("interleave_probs") != expected_interleave_probs:
            errors.append(
                f"config interleave_probs must be {expected_interleave_probs!r}"
            )
    elif (
        config.get("mix_strategy") is not None
        or config.get("interleave_probs") is not None
    ):
        errors.append("unexpected dataset mixing configuration")

    git_commit = _git(["rev-parse", "HEAD"])
    git_status = _git(["status", "--porcelain"])
    if git_status and not dirty_reason.strip():
        errors.append("dirty worktree requires an explicit dirty reason")
    if errors:
        raise ValueError("; ".join(errors))
    return {
        "status": "pass",
        "profile": run_profile,
        "config_path": config_path.as_posix(),
        "config_sha256": _sha256_file(config_path),
        "dataset_dir": dataset_dir.as_posix(),
        "dataset_manifest_sha256": _sha256_file(manifest_path),
        "sha256s_sha256": _sha256_file(sums_path),
        "git_commit": git_commit,
        "git_dirty": bool(git_status),
        "git_dirty_reason": dirty_reason.strip() or None,
        "nproc": nproc,
        "global_batch_size": global_batch,
        "max_steps": int(config["max_steps"]),
        "save_steps": int(config["save_steps"]),
        "resume_from_checkpoint": None,
        "initial_adapter": (
            expected_initial_adapter.as_posix()
            if expected_initial_adapter is not None
            else None
        ),
        "initial_adapter_sha256": initial_adapter_sha256,
        "mix_strategy": expected_mix_strategy,
        "interleave_probs": expected_interleave_probs,
        "trainer_eval_skipped": skip_trainer_eval,
        "expected_train_count": expected_train_count,
        "expected_validation_count": expected_validation_count,
        "output_dir": normalized_output,
    }


def _split_names(value: str) -> list[str]:
    names = [item.strip() for item in value.split(",") if item.strip()]
    if not names:
        raise ValueError("dataset name list must not be empty")
    return names


def _load_mapping(path: Path) -> dict[str, Any]:
    if path.suffix in {".yaml", ".yml"}:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    else:
        value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a mapping")
    return value


def _verify_sha256s(root: Path) -> list[str]:
    errors: list[str] = []
    for line in (root / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, relative = line.split("  ", 1)
        path = root / relative
        if not path.is_file() or _sha256_file(path) != expected:
            errors.append(f"dataset hash mismatch: {relative}")
    return errors


def _jsonl_count(path: Path) -> int:
    return sum(
        bool(line.strip()) for line in path.read_text(encoding="utf-8").splitlines()
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _git(args: list[str]) -> str:
    result = subprocess.run(
        ["git", *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


if __name__ == "__main__":
    main()
