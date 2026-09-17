"""Inference over already-materialized chat-message JSONL datasets."""

from __future__ import annotations

import json
import time
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from aegislm.inference.baseline import GenerateResponse
from aegislm.prompts import PromptMessage


def run_chat_dataset_inference(
    *,
    dataset_path: Path,
    predictions_path: Path,
    model_id: str,
    run_id: str,
    generate_response: GenerateResponse,
    generation_metadata: Mapping[str, Any] | None = None,
    workers: int = 1,
) -> int:
    """Generate predictions from a label-blind system/user message dataset."""
    if workers < 1:
        raise ValueError("workers must be at least 1")
    records = _load_jsonl(dataset_path)
    ids = [str(record.get("id") or "") for record in records]
    if any(not record_id for record_id in ids) or len(set(ids)) != len(ids):
        raise ValueError("chat dataset ids must be non-empty and unique")
    prompts = [_chat_prompt(record) for record in records]

    def infer(item: tuple[str, list[PromptMessage]]) -> dict[str, Any]:
        record_id, messages = item
        started_at = time.perf_counter()
        raw_output = generate_response(messages)
        latency_ms = (time.perf_counter() - started_at) * 1000.0
        return {
            "record_id": record_id,
            "model_id": model_id,
            "run_id": run_id,
            "raw_output": raw_output,
            "latency_ms": round(latency_ms, 4),
            "generated_at": _utc_now_iso(),
            "metadata": {
                "prompt_message_count": len(messages),
                "workers": workers,
                **dict(generation_metadata or {}),
            },
        }

    work = list(zip(ids, prompts, strict=True))
    if workers == 1:
        predictions = [infer(item) for item in work]
    else:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            predictions = list(executor.map(infer, work))

    predictions_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = predictions_path.with_suffix(predictions_path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        for prediction in predictions:
            stream.write(
                json.dumps(prediction, ensure_ascii=False, sort_keys=True) + "\n"
            )
    temporary.replace(predictions_path)
    return len(predictions)


def _chat_prompt(record: Mapping[str, Any]) -> list[PromptMessage]:
    messages = record.get("messages")
    if not isinstance(messages, Sequence) or isinstance(messages, (str, bytes)):
        raise ValueError(f"{record.get('id')}: messages must be an array")
    prompt: list[PromptMessage] = []
    for index, message in enumerate(messages):
        if not isinstance(message, Mapping):
            raise ValueError(f"{record.get('id')}: messages.{index} must be an object")
        role = message.get("role")
        content = message.get("content")
        if (
            role not in {"system", "user"}
            or not isinstance(content, str)
            or not content
        ):
            raise ValueError(
                f"{record.get('id')}: messages.{index} must be a non-empty "
                "system/user message"
            )
        prompt.append(cast(PromptMessage, {"role": role, "content": content}))
    if tuple(message["role"] for message in prompt) != ("system", "user"):
        raise ValueError(f"{record.get('id')}: expected system then user messages")
    return prompt


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        1,
    ):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_number}: object required")
        records.append(value)
    return records


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")
