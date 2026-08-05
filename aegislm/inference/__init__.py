"""Inference helpers for base models and adapters."""

from aegislm.inference.adapter import make_unsloth_response_generator
from aegislm.inference.baseline import (
    GenerateResponse,
    make_static_response_generator,
    make_transformers_response_generator,
    run_baseline_inference,
)
from aegislm.inference.openai_compatible import (
    make_openai_compatible_response_generator,
)
from aegislm.inference.chat_dataset import run_chat_dataset_inference
from aegislm.inference.binary import GenerateBinaryResponse, run_binary_inference

__all__ = [
    "GenerateResponse",
    "GenerateBinaryResponse",
    "make_openai_compatible_response_generator",
    "run_chat_dataset_inference",
    "make_static_response_generator",
    "make_transformers_response_generator",
    "make_unsloth_response_generator",
    "run_baseline_inference",
    "run_binary_inference",
]
