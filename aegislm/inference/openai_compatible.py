"""OpenAI-compatible HTTP inference client without an SDK dependency."""

from __future__ import annotations

import json
from typing import cast
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
) -> GenerateResponse:
    """Build a response generator for a vLLM-style chat completions API."""
    endpoint = _chat_completions_endpoint(base_url)

    def generate_response(messages: list[PromptMessage]) -> str:
        payload = {
            "model": model_id,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_new_tokens,
            "stream": False,
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


def _chat_completions_endpoint(base_url: str) -> str:
    normalized = base_url.rstrip("/")
    if not normalized:
        raise ValueError("base_url must be non-empty")
    if normalized.endswith("/chat/completions"):
        return normalized
    return f"{normalized}/chat/completions"
