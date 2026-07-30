"""OpenAI-compatible HTTP inference client without an SDK dependency."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, cast
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from aegislm.inference.baseline import GenerateResponse
from aegislm.prompts import PromptMessage


def make_openai_compatible_response_generator(
    *,
    base_url: str,
    model_id: str,
    max_new_tokens: int,
    temperature: float,
    timeout_seconds: float,
    api_key: str | None = None,
    response_json_schema: Mapping[str, Any] | None = None,
    response_schema_name: str = "aegislm_response",
) -> GenerateResponse:
    """Build a response generator for a vLLM-style chat completions API."""
    endpoint = _chat_completions_endpoint(base_url)
    guided_schema = (
        _make_vllm_guided_schema(response_json_schema)
        if response_json_schema is not None
        else None
    )

    def generate_response(messages: list[PromptMessage]) -> str:
        payload: dict[str, Any] = {
            "model": model_id,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_new_tokens,
            "stream": False,
        }
        if guided_schema is not None:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": response_schema_name,
                    "schema": guided_schema,
                    "strict": True,
                },
            }
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        request = Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urlopen(request, timeout=timeout_seconds) as response:
                response_payload = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"chat completions request failed with HTTP {exc.code}: {detail}"
            ) from exc
        except URLError as exc:
            raise RuntimeError(
                f"chat completions request failed: {exc.reason}"
            ) from exc
        except json.JSONDecodeError as exc:
            raise RuntimeError("chat completions response was not valid JSON") from exc

        try:
            content = response_payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise RuntimeError(
                "chat completions response did not contain choices[0].message.content"
            ) from exc
        if not isinstance(content, str):
            raise RuntimeError("chat completions message content must be a string")
        return cast(str, content)

    return generate_response


def _make_vllm_guided_schema(value: Mapping[str, Any]) -> dict[str, Any]:
    """Copy a schema while removing keywords unsupported by vLLM's grammar.

    ``uniqueItems`` remains enforced by AegisLM's semantic validators. vLLM
    0.26 rejects the keyword before generation, so it is omitted only from the
    constrained-decoding copy sent to the serving backend.
    """

    def copy_value(item: Any) -> Any:
        if isinstance(item, Mapping):
            return {
                str(key): copy_value(child)
                for key, child in item.items()
                if key != "uniqueItems"
            }
        if isinstance(item, list):
            return [copy_value(child) for child in item]
        return item

    return cast(dict[str, Any], copy_value(value))


def _chat_completions_endpoint(base_url: str) -> str:
    normalized = base_url.rstrip("/")
    if not normalized:
        raise ValueError("base_url must be non-empty")
    if normalized.endswith("/chat/completions"):
        return normalized
    return f"{normalized}/chat/completions"
