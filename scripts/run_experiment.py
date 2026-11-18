"""Validate, render, or run the approved Mistral F5-X experiment."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.experiments.axolotl import render_axolotl_config  # noqa: E402
from aegislm.experiments.config import (  # noqa: E402
    ExperimentConfig,
    load_experiment_config,
)
from aegislm.experiments.runtime import verify_runtime_environment  # noqa: E402


APPROVAL_ENV = "AEGISLM_APPROVED_CONFIG_SHA256"
GENERATED_NAME = "axolotl.generated.yaml"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument(
        "--action", choices=("validate", "render", "run"), required=True
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = load_experiment_config(args.config)
    if args.action == "validate":
        print(f"Experiment config PASS: sha256={config.sha256}")
        return
    if args.action == "render":
        run_directory = render_run_directory(config)
        print(f"Rendered approved run directory: {run_directory}")
        return
    exit_code = run_approved_experiment(config)
    if exit_code != 0:
        raise SystemExit(exit_code)


def require_approval_hash(config: ExperimentConfig) -> None:
    approved = os.environ.get(APPROVAL_ENV, "")
    if not approved:
        raise ValueError(f"{APPROVAL_ENV} is required for render and run")
    if approved != config.sha256:
        raise ValueError(f"{APPROVAL_ENV} does not match the config raw-byte SHA-256")


def render_run_directory(config: ExperimentConfig) -> Path:
    """Create one immutable run directory; existing paths are never reused."""
    require_approval_hash(config)
    run_directory = config.run_directory
    _assert_within_namespace(config, run_directory)
    run_directory.mkdir(parents=True, exist_ok=False)
    logs = run_directory / "logs"
    logs.mkdir()
    approved_path = run_directory / "approved-config.yaml"
    approved_path.write_bytes(config.raw_bytes)
    hash_path = run_directory / "approved-config.sha256"
    hash_path.write_text(config.sha256 + "\n", encoding="ascii")
    generated_path = run_directory / GENERATED_NAME
    generated_bytes = _serialized_axolotl(config)
    generated_path.write_bytes(generated_bytes)
    inventory = _inventory_payload(config, run_directory)
    (run_directory / "inventory.json").write_text(
        json.dumps(inventory, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return run_directory


def _inventory_payload(config: ExperimentConfig, run_directory: Path) -> dict[str, Any]:
    approved_path = run_directory / "approved-config.yaml"
    hash_path = run_directory / "approved-config.sha256"
    generated_path = run_directory / GENERATED_NAME
    return {
        "schema_version": "aegislm.experiment-inventory.v1",
        "status": "static-preflight-pass",
        "experiment_id": config.data["experiment"]["id"],
        "active_profile": config.active_profile,
        "run_id": config.run_id,
        "approved_config_sha256": config.sha256,
        "files": {
            "approved-config.yaml": _sha256_file(approved_path),
            "approved-config.sha256": _sha256_file(hash_path),
            GENERATED_NAME: _sha256_file(generated_path),
        },
        "runtime_preflight_required": True,
        "gpu_execution_approved": False,
        "future_gates_approved": False,
    }


def run_approved_experiment(config: ExperimentConfig) -> int:
    """Verify immutable artifacts, run full preflight, then launch two GPUs."""
    require_approval_hash(config)
    run_directory = config.run_directory
    _verify_rendered_directory(config)
    logs = run_directory / "logs"
    if any(logs.iterdir()) or (run_directory / "run.started.json").exists():
        raise FileExistsError("run directory already contains execution evidence")

    preflight = runtime_preflight(config)
    _write_new_json(logs / "preflight.runtime.json", preflight)
    _write_new_json(
        run_directory / "run.started.json",
        {
            "schema_version": "aegislm.experiment-run-start.v1",
            "approved_config_sha256": config.sha256,
            "active_profile": config.active_profile,
            "gpu_count": 2,
        },
    )
    command = [
        _runtime_axolotl_cli(preflight),
        "train",
        GENERATED_NAME,
        "--launcher",
        "torchrun",
        "--",
        "--nproc_per_node=2",
        "--nnodes=1",
    ]
    stdout_path = logs / "train.stdout.log"
    stderr_path = logs / "train.stderr.log"
    with (
        stdout_path.open("x", encoding="utf-8") as stdout,
        stderr_path.open("x", encoding="utf-8") as stderr,
    ):
        completed = subprocess.run(
            command,
            cwd=run_directory,
            stdout=stdout,
            stderr=stderr,
            check=False,
        )
    return completed.returncode


def runtime_preflight(config: ExperimentConfig) -> dict[str, Any]:
    """Validate every frozen dataset row with the actual pinned local tokenizer."""
    runtime = verify_runtime_environment(config, require_gpus=True)
    data = config.data
    dataset = data["dataset"]
    dataset_root = config.repo_root / dataset["root"]
    manifest_path = dataset_root / dataset["manifest_file"]
    _require_hash(manifest_path, dataset["manifest_sha256"], "dataset manifest")
    try:
        from transformers import AutoTokenizer
    except ImportError as exc:
        raise RuntimeError(
            "runtime preflight requires the pinned tokenizer runtime"
        ) from exc
    model_path = config.repo_root / data["model"]["local_path"]
    if not model_path.is_dir():
        raise FileNotFoundError(f"pinned local model snapshot is missing: {model_path}")
    tokenizer_inventory = _verify_model_snapshot(model_path, config)
    try:
        tokenizer = AutoTokenizer.from_pretrained(
            model_path, local_files_only=True, trust_remote_code=False
        )
    except (OSError, ValueError, TypeError) as exc:
        raise RuntimeError(f"unable to load the pinned local tokenizer: {exc}") from exc

    reports: dict[str, Any] = {}
    for split, file_key, count_key, hash_key in (
        ("train", "train_file", "train_count", "train_sha256"),
        ("validation", "validation_file", "validation_count", "validation_sha256"),
    ):
        path = dataset_root / dataset[file_key]
        _require_hash(path, dataset[hash_key], f"{split} dataset")
        reports[split] = _validate_dataset_rows(
            path=path,
            split=split,
            expected_count=dataset[count_key],
            tokenizer=tokenizer,
            config=config,
        )
    return {
        "schema_version": "aegislm.experiment-runtime-preflight.v1",
        "status": "pass",
        "approved_config_sha256": config.sha256,
        "runtime": runtime,
        "tokenizer_local_path": data["model"]["local_path"],
        "tokenizer_files_sha256": tokenizer_inventory,
        "splits": reports,
        "forbidden_marker_count": 0,
        "over_sequence_limit_count": 0,
    }


def _runtime_axolotl_cli(preflight: dict[str, Any]) -> str:
    runtime = preflight.get("runtime")
    if not isinstance(runtime, dict):
        raise RuntimeError("runtime preflight did not return environment evidence")
    executable = runtime.get("axolotl_cli")
    if not isinstance(executable, str) or not Path(executable).is_absolute():
        raise RuntimeError("runtime preflight returned an unsafe axolotl CLI path")
    return executable


def _validate_dataset_rows(
    *,
    path: Path,
    split: str,
    expected_count: int,
    tokenizer: Any,
    config: ExperimentConfig,
) -> dict[str, int]:
    prompt = config.data["prompt_contract"]
    count = 0
    maximum_tokens = 0
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                raise ValueError(f"{split}:{line_number} blank rows are forbidden")
            count += 1
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"{split}:{line_number} invalid JSON: {exc.msg}"
                ) from exc
            if not isinstance(row, dict) or not isinstance(row.get("messages"), list):
                raise ValueError(f"{split}:{line_number} messages must be an array")
            messages = row["messages"]
            if (
                len(messages) != 3
                or not all(isinstance(message, dict) for message in messages)
                or [message.get("role") for message in messages]
                != ["system", "user", "assistant"]
                or not all(
                    isinstance(message.get("content"), str) for message in messages
                )
            ):
                raise ValueError(
                    f"{split}:{line_number} message role/content contract failed"
                )
            system_hash = hashlib.sha256(messages[0]["content"].encode()).hexdigest()
            if system_hash != prompt["system_prompt_sha256"]:
                raise ValueError(
                    f"{split}:{line_number} system prompt SHA-256 mismatch"
                )
            try:
                target = json.loads(messages[2]["content"])
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"{split}:{line_number} assistant target is not JSON"
                ) from exc
            if (
                not isinstance(target, dict)
                or set(target) != {"assessment"}
                or target["assessment"] not in {"present", "not_observed", "uncertain"}
            ):
                raise ValueError(
                    f"{split}:{line_number} assistant target contract failed"
                )
            rendered = tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                reasoning_effort=prompt["reasoning_effort"],
            )
            if not isinstance(rendered, str):
                raise ValueError(
                    f"{split}:{line_number} chat template did not return text"
                )
            if any(marker in rendered for marker in prompt["forbidden_markers"]):
                raise ValueError(
                    f"{split}:{line_number} rendered forbidden THINK marker"
                )
            token_ids = tokenizer.apply_chat_template(
                messages,
                tokenize=True,
                reasoning_effort=prompt["reasoning_effort"],
            )
            token_count = len(token_ids)
            maximum_tokens = max(maximum_tokens, token_count)
            if token_count > config.data["training"]["common"]["sequence_len"]:
                raise ValueError(f"{split}:{line_number} exceeds the 2048-token limit")
    if count != expected_count:
        raise ValueError(f"{split} row count mismatch: {count}!={expected_count}")
    return {"count": count, "maximum_tokens": maximum_tokens}


def _verify_rendered_directory(config: ExperimentConfig) -> None:
    run_directory = config.run_directory
    _assert_within_namespace(config, run_directory)
    if not run_directory.is_dir():
        raise FileNotFoundError("approved run directory has not been rendered")
    approved_path = run_directory / "approved-config.yaml"
    hash_path = run_directory / "approved-config.sha256"
    generated_path = run_directory / GENERATED_NAME
    inventory_path = run_directory / "inventory.json"
    if approved_path.read_bytes() != config.raw_bytes:
        raise ValueError("approved config bytes differ from the current config")
    if hash_path.read_text(encoding="ascii") != config.sha256 + "\n":
        raise ValueError("approved config hash file is invalid")
    if generated_path.read_bytes() != _serialized_axolotl(config):
        raise ValueError("generated Axolotl config was changed after render")
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    if inventory != _inventory_payload(config, run_directory):
        raise ValueError("inventory content or artifact hashes changed after render")


def _verify_model_snapshot(
    model_path: Path, config: ExperimentConfig
) -> dict[str, Any]:
    manifest_path = model_path / "aegislm_model_manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError("pinned model snapshot manifest is missing")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    model = config.data["model"]
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema_version") != "aegislm.model-snapshot.v2"
        or manifest.get("model_id") != model["training_repo"]
        or manifest.get("revision") != model["training_revision"]
        or manifest.get("missing_shards") != []
        or type(manifest.get("safetensors_shards")) is not int
        or manifest["safetensors_shards"] < 1
        or type(manifest.get("safetensors_bytes")) is not int
        or manifest["safetensors_bytes"] < 1
    ):
        raise ValueError(
            "local model snapshot identity does not match the approved pin"
        )
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise ValueError("model snapshot manifest has no file inventory")
    observed_paths: set[str] = set()
    inventory_digest = hashlib.sha256()
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "bytes", "sha256"}:
            raise ValueError("model snapshot inventory entry schema drift")
        name = item["path"]
        expected_bytes = item["bytes"]
        expected_sha256 = item["sha256"]
        if (
            not isinstance(name, str)
            or not _is_safe_manifest_path(name)
            or name in observed_paths
            or type(expected_bytes) is not int
            or expected_bytes < 0
            or not isinstance(expected_sha256, str)
            or len(expected_sha256) != 64
        ):
            raise ValueError("model snapshot inventory entry is unsafe")
        observed_paths.add(name)
        path = model_path / PurePosixPath(name)
        if not path.is_file() or path.is_symlink():
            raise FileNotFoundError(f"pinned model snapshot file is missing: {name}")
        if path.stat().st_size != expected_bytes:
            raise ValueError(f"model snapshot size mismatch: {name}")
        if _sha256_file(path) != expected_sha256:
            raise ValueError(f"model snapshot SHA-256 mismatch: {name}")
        inventory_digest.update(
            f"{name}\t{expected_bytes}\t{expected_sha256}\n".encode("utf-8")
        )
    actual_paths = {
        path.relative_to(model_path).as_posix()
        for path in model_path.rglob("*")
        if path.is_file()
        and path.name != "aegislm_model_manifest.json"
        and path.relative_to(model_path).parts[:1] != (".cache",)
    }
    if actual_paths != observed_paths:
        raise ValueError("model snapshot file set differs from the frozen inventory")
    required = {"config.json", "tokenizer_config.json", "tokenizer.json"}
    if not required.issubset(observed_paths):
        raise FileNotFoundError("pinned model snapshot is missing tokenizer metadata")
    computed_inventory = inventory_digest.hexdigest()
    if manifest.get("inventory_sha256") != computed_inventory:
        raise ValueError("model snapshot aggregate inventory SHA-256 mismatch")
    index_sha256 = manifest.get("index_sha256")
    index_path = model_path / "model.safetensors.index.json"
    if (
        not isinstance(index_sha256, str)
        or len(index_sha256) != 64
        or not index_path.is_file()
        or _sha256_file(index_path) != index_sha256
    ):
        raise ValueError("model snapshot index SHA-256 mismatch")
    return {
        "manifest_sha256": _sha256_file(manifest_path),
        "inventory_sha256": computed_inventory,
        "file_count": len(observed_paths),
        "files_verified": True,
    }


def _is_safe_manifest_path(value: str) -> bool:
    if not value or "\\" in value:
        return False
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    return (
        not posix.is_absolute()
        and not windows.is_absolute()
        and ".." not in posix.parts
    )


def _serialized_axolotl(config: ExperimentConfig) -> bytes:
    return yaml.safe_dump(
        render_axolotl_config(config), sort_keys=False, allow_unicode=True
    ).encode("utf-8")


def _assert_within_namespace(config: ExperimentConfig, path: Path) -> None:
    namespace = (
        config.repo_root
        / config.data["artifacts"]["root"]
        / config.data["artifacts"]["model_namespace"]
    ).resolve()
    try:
        path.resolve().relative_to(namespace)
    except ValueError as exc:
        raise ValueError(
            "run directory escaped the Mistral artifact namespace"
        ) from exc


def _require_hash(path: Path, expected: str, label: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"{label} is missing: {path}")
    if _sha256_file(path) != expected:
        raise ValueError(f"{label} SHA-256 mismatch")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_new_json(path: Path, value: dict[str, Any]) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


if __name__ == "__main__":
    main()
