"""Safe normalized binary-analysis records and prompt formatting."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, Literal, TypedDict, cast

from jsonschema import Draft202012Validator

from aegislm.schemas import (
    BINARY_ANALYSIS_RECORD_SCHEMA,
    BINARY_ASSESSMENT_OUTPUT_SCHEMA,
)

_BINARY_RECORD_VALIDATOR = Draft202012Validator(BINARY_ANALYSIS_RECORD_SCHEMA)
_BINARY_OUTPUT_VALIDATOR = Draft202012Validator(BINARY_ASSESSMENT_OUTPUT_SCHEMA)
_FORBIDDEN_PAYLOAD_KEYS = {
    "raw_bytes",
    "bytes",
    "byte_dump",
    "payload",
    "executable",
    "file_content",
}


class BinaryPromptMessage(TypedDict):
    """Chat message accepted by model inference helpers."""

    role: Literal["system", "user"]
    content: str


class BinaryRecordValidationError(ValueError):
    """Raised when a normalized binary record violates its contract."""


BINARY_SYSTEM_PROMPT = """You are AegisLM, a defensive binary-analysis assistant.

Return exactly one JSON object and no Markdown. The object must contain:
- scope: target_cwe, binary_format, architecture
- assessment: present, not_observed, or uncertain
- findings: function_id, representation, observation, confidence
- limitations: array of strings
- recommendations: array of strings

Use only the supplied pseudo-C, bounded assembly evidence, and static features.
Do not infer from dataset provenance, labels, source symbols, or file paths.
The assessment is scoped to the target CWE and is not a claim that the whole
program is safe. Do not provide exploit, malware deployment, persistence,
credential theft, or evasion instructions."""


def validate_binary_record(record: Mapping[str, Any]) -> None:
    """Validate schema and prohibit embedded executable/raw-byte payloads."""
    errors = sorted(
        _BINARY_RECORD_VALIDATOR.iter_errors(dict(record)),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        raise BinaryRecordValidationError(
            "; ".join(_format_schema_error(error) for error in errors)
        )
    forbidden_paths = _find_forbidden_payload_keys(record)
    if forbidden_paths:
        raise BinaryRecordValidationError(
            "raw executable or byte payload key(s) are forbidden: "
            + ", ".join(forbidden_paths)
        )


def validate_binary_output(output: Mapping[str, Any]) -> list[str]:
    """Return binary output schema errors; an empty list means valid."""
    return [
        _format_schema_error(error)
        for error in sorted(
            _BINARY_OUTPUT_VALIDATOR.iter_errors(dict(output)),
            key=lambda item: list(item.absolute_path),
        )
    ]


def format_binary_prompt(
    record: Mapping[str, Any],
) -> list[BinaryPromptMessage]:
    """Format model-visible evidence while withholding labels and provenance."""
    validate_binary_record(record)
    artifact = cast(Mapping[str, Any], record["artifact"])
    analysis = cast(Mapping[str, Any], record["analysis"])
    task = cast(Mapping[str, Any], record["task"])
    visible = {
        "scope": {
            "target_cwe": task["target_cwe"],
            "binary_format": artifact["format"],
            "architecture": artifact["architecture"],
            "compiler": artifact["compiler"],
            "optimization": artifact["optimization"],
            "stripped": artifact["stripped"],
        },
        "functions": analysis["functions"],
        "extraction_warnings": analysis["warnings"],
    }
    return [
        {"role": "system", "content": BINARY_SYSTEM_PROMPT},
        {
            "role": "user",
            "content": "\n\n".join(
                [
                    "Assess the target CWE using only the normalized binary evidence.",
                    json.dumps(visible, ensure_ascii=False, indent=2, sort_keys=True),
                    "Return only the required binary assessment JSON object.",
                ]
            ),
        },
    ]


def _find_forbidden_payload_keys(
    value: Any,
    *,
    prefix: str = "",
) -> list[str]:
    paths: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            name = str(key)
            path = f"{prefix}.{name}" if prefix else name
            if name.lower() in _FORBIDDEN_PAYLOAD_KEYS:
                paths.append(path)
            paths.extend(_find_forbidden_payload_keys(item, prefix=path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            paths.extend(
                _find_forbidden_payload_keys(item, prefix=f"{prefix}[{index}]")
            )
    return paths


def _format_schema_error(error: Any) -> str:
    path = ".".join(str(item) for item in error.absolute_path)
    return f"{path}: {error.message}" if path else error.message
