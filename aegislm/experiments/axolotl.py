"""Pure Axolotl renderer for the two frozen Mistral G1 profiles."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from aegislm.experiments.config import ExperimentConfig


PLUGIN = "axolotl.integrations.cut_cross_entropy.CutCrossEntropyPlugin"


def render_axolotl_config(config: ExperimentConfig) -> dict[str, Any]:
    """Return a deterministic Axolotl mapping without touching the filesystem."""
    data = config.data
    common = data["training"]["common"]
    profile = data["training"]["profiles"][config.active_profile]
    run_directory = config.run_directory.resolve()
    rendered: dict[str, Any] = {
        "strict": True,
        "base_model": str((config.repo_root / data["model"]["local_path"]).resolve()),
        "revision_of_model": data["model"]["training_revision"],
        "trust_remote_code": False,
        "plugins": [PLUGIN],
        "datasets": [
            {
                "path": str(
                    (
                        config.repo_root
                        / data["dataset"]["root"]
                        / data["dataset"]["train_file"]
                    ).resolve()
                ),
                "type": "chat_template",
                "chat_template": data["prompt_contract"]["chat_template"],
                "field_messages": "messages",
                "roles_to_train": deepcopy(data["prompt_contract"]["roles_to_train"]),
                "train_on_eos": data["prompt_contract"]["train_on_eos"],
            }
        ],
        "dataset_prepared_path": str(run_directory / "prepared"),
        "val_set_size": 0,
        "sequence_len": common["sequence_len"],
        "sample_packing": False,
        "chat_template": data["prompt_contract"]["chat_template"],
        "chat_template_kwargs": {
            "reasoning_effort": data["prompt_contract"]["reasoning_effort"]
        },
        "adapter": profile["adapter"],
        "lora_r": common["lora_rank"],
        "lora_alpha": common["lora_alpha"],
        "lora_dropout": common["lora_dropout"],
        "lora_target_modules": common["lora_target_modules"],
        "lora_target_parameters": deepcopy(common["lora_target_parameters"]),
        "lora_mlp_kernel": False,
        "lora_qkv_kernel": False,
        "lora_o_kernel": False,
        "output_dir": str(run_directory / "adapter"),
        "micro_batch_size": common["micro_batch_size"],
        "gradient_accumulation_steps": common["gradient_accumulation_steps"],
        "max_steps": common["max_steps"],
        "learning_rate": common["learning_rate"],
        "optimizer": common["optimizer"],
        "lr_scheduler": common["lr_scheduler"],
        "warmup_steps": common["warmup_steps"],
        "weight_decay": common["weight_decay"],
        "bf16": profile["bf16"],
        "tf32": True,
        "gradient_checkpointing": common["gradient_checkpointing"],
        "attn_implementation": common["attn_implementation"],
        "eval_strategy": "no",
        "save_strategy": "no",
        "save_first_step": False,
        "logging_steps": 1,
        "include_tkps": True,
        "seed": common["seed"],
        "use_tensorboard": False,
        "auto_resume_from_checkpoints": False,
    }
    if config.active_profile == "g1-qlora-ddp":
        rendered.update(
            {
                "load_in_4bit": profile["load_in_4bit"],
                "quantize_moe_experts": profile["quantize_moe_experts"],
            }
        )
    else:
        rendered.update(
            {
                "fsdp_version": profile["fsdp_version"],
                "fsdp_config": deepcopy(profile["fsdp_config"]),
            }
        )
    _assert_render_boundaries(rendered, run_directory)
    return rendered


def _assert_render_boundaries(rendered: dict[str, Any], run_directory: Path) -> None:
    for key in ("output_dir", "dataset_prepared_path"):
        try:
            rendered_path = Path(rendered[key]).resolve()
            rendered_path.relative_to(run_directory)
        except ValueError as exc:
            raise ValueError(
                f"rendered {key} escaped the approved run namespace"
            ) from exc
    if "deepspeed" in rendered or "fsdp" in rendered:
        raise ValueError("deprecated distributed keys are forbidden")
