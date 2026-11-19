"""Exact-schema loader for the frozen Mistral F5-X experiment contract."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

import yaml


PROFILE_ORDER = ("g1-qlora-ddp", "g1-bf16-lora-fsdp2")
RUN_ID_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
PLACEHOLDERS = ("CHANGEME", "PLACEHOLDER", "TODO", "TBD", "REQUIRED")
SECRET_KEYS = {
    "api_key",
    "access_token",
    "auth_token",
    "password",
    "private_key",
    "secret",
}

EXPECTED: dict[str, Any] = {
    "experiment": {
        "id": "mistral-f5x-unified-config-v2",
        "phase": "F5-X",
        "stage": "G1",
        "active_profile": str,
        "run_id": str,
    },
    "approvals": {
        "g0_static_configuration": True,
        "dependency_install": True,
        "model_download": False,
        "workspace_symlinks": False,
        "g1_gpu_execution": True,
        "g2_10_step": False,
        "g3_100_step": False,
        "merge": False,
        "evidence_adapter": False,
        "full_epoch": False,
    },
    "model": {
        "source_repo": "mistralai/Mistral-Small-4-119B-2603",
        "source_revision": "a11f36bebf709121056b1dbcc943d1c6afbe494d",
        "training_repo": "axolotl-ai-co/Mistral-Small-4-119B-2603-BF16",
        "training_revision": "7918b06c0799750ce522f949bcc97dff2dca632a",
        "tokenizer_repo": "axolotl-ai-co/Mistral-Small-4-119B-2603-BF16",
        "tokenizer_revision": "7918b06c0799750ce522f949bcc97dff2dca632a",
        "local_path": "model/mistral-small-4-119b-2603-bf16",
        "text_only": True,
        "reasoning_effort": "none",
    },
    "framework": {
        "name": "Axolotl",
        "version": "0.17.0",
        "transformers_version": "5.9.0",
        "cut_cross_entropy_repository": "axolotl-ai-cloud/ml-cross-entropy",
        "cut_cross_entropy_revision": "5f0c7a7778b5b17d37738fae10065ed3034373af",
    },
    "dataset": {
        "profile": "phase-f-source-decision-v1",
        "format": "openai_messages_jsonl",
        "root": "data/processed/phase-f-source-decision-v1",
        "train_file": "train.jsonl",
        "validation_file": "validation.jsonl",
        "manifest_file": "dataset_manifest.json",
        "train_count": 10000,
        "validation_count": 1000,
        "train_sha256": (
            "2d46c7d8161cbf97cc4efeb1a8c223311f4260ccf7a333dbe3cd71b73715f322"
        ),
        "validation_sha256": (
            "ab576d0332282244b68711f5fb7129c171cd0b95784f914cf5a7255e880d5481"
        ),
        "manifest_sha256": (
            "b987d174657061b0d0cdf263f738025514abbd9e3bb054251ca7d9d1777daa4e"
        ),
    },
    "prompt_contract": {
        "chat_template": "tokenizer_default",
        "roles_to_train": ["assistant"],
        "train_on_eos": "turn",
        "assistant_only": True,
        "reasoning_effort": "none",
        "system_prompt_sha256": (
            "9a72abf082ce57817ed0186719aeede75e51579c8131c95afd62b736485352ef"
        ),
        "forbidden_markers": ["[THINK]", "[/THINK]"],
    },
    "training": {
        "common": {
            "sequence_len": 2048,
            "seed": 20260728,
            "micro_batch_size": 1,
            "gradient_accumulation_steps": 1,
            "max_steps": 1,
            "lora_rank": 8,
            "lora_alpha": 16,
            "lora_dropout": 0.0,
            "expert_lora": True,
            "lora_target_modules": (
                r"model.language_model.layers.[\d]+."
                r"(mlp|cross_attn|self_attn).(up|down|gate|q|k|v|o)_proj"
            ),
            "lora_target_parameters": [
                "mlp.experts.gate_up_proj",
                "mlp.experts.down_proj",
            ],
            "learning_rate": 1.0e-4,
            "optimizer": "adamw_torch_fused",
            "lr_scheduler": "cosine",
            "warmup_steps": 0,
            "weight_decay": 0.0,
            "gradient_checkpointing": True,
            "attn_implementation": "flash_attention_2",
        },
        "profiles": {
            "g1-qlora-ddp": {
                "adapter": "qlora",
                "distributed": "ddp",
                "load_in_4bit": True,
                "quantize_moe_experts": True,
                "bf16": True,
            },
            "g1-bf16-lora-fsdp2": {
                "adapter": "lora",
                "distributed": "fsdp2",
                "bf16": True,
                "fsdp_version": 2,
                "fsdp_config": {
                    "auto_wrap_policy": "TRANSFORMER_BASED_WRAP",
                    "transformer_layer_cls_to_wrap": "Mistral4DecoderLayer",
                    "state_dict_type": "SHARDED_STATE_DICT",
                    "reshard_after_forward": True,
                },
            },
        },
    },
    "artifacts": {
        "root": "training_artifacts",
        "model_namespace": "mistral-small-4-119b",
        "run_directory": str,
    },
    "gates": {
        "g1": True,
        "g2": False,
        "g3": False,
        "merge": False,
        "evidence_adapter": False,
        "full_epoch": False,
    },
}


@dataclass(frozen=True)
class ExperimentConfig:
    """A validated configuration together with its approval identity."""

    path: Path
    repo_root: Path
    data: dict[str, Any]
    raw_bytes: bytes
    sha256: str

    @property
    def active_profile(self) -> str:
        return str(self.data["experiment"]["active_profile"])

    @property
    def run_id(self) -> str:
        return str(self.data["experiment"]["run_id"])

    @property
    def run_directory(self) -> Path:
        return self.repo_root / str(self.data["artifacts"]["run_directory"])


def load_experiment_config(
    path: Path | str, *, repo_root: Path | str | None = None
) -> ExperimentConfig:
    """Load and validate the sole human-edited experiment YAML."""
    config_path = Path(path).resolve()
    root = (
        Path(repo_root).resolve()
        if repo_root is not None
        else config_path.parent.parent
    )
    raw = config_path.read_bytes()
    try:
        parsed = yaml.safe_load(raw.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError(f"invalid experiment YAML: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("experiment config must be a mapping")
    errors: list[str] = []
    _validate_exact(parsed, EXPECTED, "config", errors)
    _reject_unsafe_values(parsed, "config", errors)
    _validate_dynamic_contract(parsed, errors)
    if errors:
        raise ValueError("; ".join(errors))
    return ExperimentConfig(
        path=config_path,
        repo_root=root,
        data=parsed,
        raw_bytes=raw,
        sha256=hashlib.sha256(raw).hexdigest(),
    )


def _validate_exact(
    actual: Any, expected: Any, location: str, errors: list[str]
) -> None:
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            errors.append(f"{location} must be a mapping")
            return
        actual_keys = set(actual)
        expected_keys = set(expected)
        for key in sorted(expected_keys - actual_keys):
            errors.append(f"{location}.{key} is required")
        for key in sorted(actual_keys - expected_keys):
            errors.append(f"{location}.{key} is not allowed")
        for key in expected_keys & actual_keys:
            _validate_exact(actual[key], expected[key], f"{location}.{key}", errors)
        return
    if expected is str:
        if not isinstance(actual, str):
            errors.append(f"{location} must be a string")
        return
    if type(actual) is not type(expected) or actual != expected:
        errors.append(f"{location} must be {expected!r}")


def _reject_unsafe_values(value: Any, location: str, errors: list[str]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower()
            if normalized in SECRET_KEYS or normalized.endswith("_secret"):
                errors.append(f"{location}.{key} is a forbidden secret-like field")
            _reject_unsafe_values(child, f"{location}.{key}", errors)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_unsafe_values(child, f"{location}[{index}]", errors)
    elif isinstance(value, str):
        upper = value.upper()
        if any(marker in upper for marker in PLACEHOLDERS):
            errors.append(f"{location} contains a forbidden placeholder")


def _validate_dynamic_contract(data: dict[str, Any], errors: list[str]) -> None:
    experiment = data.get("experiment")
    artifacts = data.get("artifacts")
    training = data.get("training")
    if not isinstance(experiment, dict):
        return
    if not isinstance(artifacts, dict):
        return
    if not isinstance(training, dict):
        return
    profile = experiment.get("active_profile")
    if profile not in PROFILE_ORDER:
        errors.append(
            f"config.experiment.active_profile must be one of {PROFILE_ORDER!r}"
        )
    profiles = training.get("profiles")
    if isinstance(profiles, dict) and tuple(profiles) != PROFILE_ORDER:
        errors.append(
            "config.training.profiles must keep the frozen QLoRA then LoRA order"
        )
    run_id = experiment.get("run_id")
    if not isinstance(run_id, str) or RUN_ID_PATTERN.fullmatch(run_id) is None:
        errors.append("config.experiment.run_id is unsafe")
        return
    expected_directory = f"training_artifacts/mistral-small-4-119b/{run_id}"
    if artifacts.get("run_directory") != expected_directory:
        errors.append(
            "config.artifacts.run_directory must match the frozen namespace and run_id"
        )
    model_value = data.get("model")
    model = model_value if isinstance(model_value, dict) else {}
    dataset_value = data.get("dataset")
    dataset = dataset_value if isinstance(dataset_value, dict) else {}
    prompt_value = data.get("prompt_contract")
    prompt = prompt_value if isinstance(prompt_value, dict) else {}
    framework_value = data.get("framework")
    framework = framework_value if isinstance(framework_value, dict) else {}
    path_values = {
        "config.model.local_path": model.get("local_path"),
        "config.dataset.root": dataset.get("root"),
        "config.dataset.train_file": dataset.get("train_file"),
        "config.dataset.validation_file": dataset.get("validation_file"),
        "config.dataset.manifest_file": dataset.get("manifest_file"),
        "config.artifacts.root": artifacts.get("root"),
        "config.artifacts.model_namespace": artifacts.get("model_namespace"),
        "config.artifacts.run_directory": artifacts.get("run_directory"),
    }
    for location, value in path_values.items():
        if not isinstance(value, str) or not _is_safe_relative(value):
            errors.append(f"{location} must be a safe repository-relative path")
    for section in (model, framework):
        for key, value in section.items():
            if key.endswith("revision") and (
                not isinstance(value, str) or COMMIT_PATTERN.fullmatch(value) is None
            ):
                errors.append(f"config revision {key} must be a pinned commit")
    for key in ("train_sha256", "validation_sha256", "manifest_sha256"):
        value = dataset.get(key)
        if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
            errors.append(f"config.dataset.{key} must be SHA-256")
    prompt_hash = prompt.get("system_prompt_sha256")
    if (
        not isinstance(prompt_hash, str)
        or SHA256_PATTERN.fullmatch(prompt_hash) is None
    ):
        errors.append("config.prompt_contract.system_prompt_sha256 must be SHA-256")


def _is_safe_relative(value: str) -> bool:
    if not value or "\\" in value:
        return False
    if PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute():
        return False
    return ".." not in PurePosixPath(value).parts
