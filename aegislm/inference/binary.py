"""Inference runner for normalized Phase F binary-analysis records."""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegislm.datasets.binary import BinaryPromptMessage, format_binary_prompt

GenerateBinaryResponse = Callable[[list[BinaryPromptMessage]], str]


def run_binary_inference(
    *,
    dataset_path: Path,
    predictions_path: Path,
    model_id: str,
    run_id: str,
    generate_response: GenerateBinaryResponse,
    generation_metadata: Mapping[str, Any] | None = None,
) -> int:
    """Generate Prediction-compatible JSONL for a normalized binary dataset."""
    records = _load_jsonl(dataset_path)
    predictions_path.parent.mkdir(parents=True, exist_ok=True)
    with predictions_path.open("w", encoding="utf-8") as stream:
        for record in records:
            messages = format_binary_prompt(record)
            started_at = time.perf_counter()
            raw_output = generate_response(messages)
            latency_ms = (time.perf_counter() - started_at) * 1000.0
            stream.write(
                json.dumps(
                    {
                        "record_id": record["id"],
                        "model_id": model_id,
                        "run_id": run_id,
                        "raw_output": raw_output,
                        "latency_ms": round(latency_ms, 4),
                        "generated_at": datetime.now(UTC)
                        .isoformat()
                        .replace("+00:00", "Z"),
                        "metadata": {
                            "prompt_message_count": len(messages),
                            **dict(generation_metadata or {}),
                        },
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
    return len(records)


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), 1
    ):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{line_number}: invalid JSONL: {exc.msg}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_number}: record must be an object")
        records.append(value)
    return records
