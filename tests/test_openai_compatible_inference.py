import json
from typing import Any, cast
from collections.abc import Mapping
from urllib.request import Request

from aegislm.inference import make_openai_compatible_response_generator
from aegislm.schemas import SOURCE_EVIDENCE_LINES_OUTPUT_SCHEMA


class _FakeResponse:
    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(
            {"choices": [{"message": {"content": '{"risk_level":"low"}'}}]}
        ).encode()


def test_openai_compatible_generator_posts_chat_completion(
    monkeypatch: Any,
) -> None:
    captured: dict[str, Any] = {}

    def fake_urlopen(request: Request, timeout: float) -> _FakeResponse:
        captured["url"] = request.full_url
        captured["headers"] = dict(request.header_items())
        payload_data = request.data
        assert isinstance(payload_data, bytes)
        captured["payload"] = json.loads(payload_data)
        captured["timeout"] = timeout
        return _FakeResponse()

    monkeypatch.setattr("aegislm.inference.openai_compatible.urlopen", fake_urlopen)
    generate = make_openai_compatible_response_generator(
        base_url="http://127.0.0.1:8000/v1/",
        model_id="aegislm-80b",
        max_new_tokens=512,
        temperature=0.0,
        timeout_seconds=30.0,
        api_key="test-key",
    )

    content = generate([{"role": "user", "content": "analyze"}])

    assert content == '{"risk_level":"low"}'
    assert captured["url"] == "http://127.0.0.1:8000/v1/chat/completions"
    assert captured["payload"]["model"] == "aegislm-80b"
    assert captured["payload"]["max_tokens"] == 512
    assert captured["headers"]["Authorization"] == "Bearer test-key"
    assert captured["timeout"] == 30.0


def test_openai_compatible_generator_posts_guided_json_schema(
    monkeypatch: Any,
) -> None:
    captured: dict[str, Any] = {}

    def fake_urlopen(request: Request, timeout: float) -> _FakeResponse:
        payload_data = request.data
        assert isinstance(payload_data, bytes)
        captured["payload"] = json.loads(payload_data)
        return _FakeResponse()

    monkeypatch.setattr("aegislm.inference.openai_compatible.urlopen", fake_urlopen)
    generate = make_openai_compatible_response_generator(
        base_url="http://127.0.0.1:8000/v1",
        model_id="aegislm-evidence",
        max_new_tokens=256,
        temperature=0.0,
        timeout_seconds=30.0,
        response_json_schema=SOURCE_EVIDENCE_LINES_OUTPUT_SCHEMA,
        response_schema_name="source_evidence_lines",
    )

    generate([{"role": "user", "content": "select evidence"}])

    response_format = captured["payload"]["response_format"]
    assert response_format["type"] == "json_schema"
    assert response_format["json_schema"]["name"] == "source_evidence_lines"
    assert response_format["json_schema"]["strict"] is True
    guided = response_format["json_schema"]["schema"]
    assert "uniqueItems" not in guided["properties"]["evidence_ranges"]
    properties = cast(
        Mapping[str, Mapping[str, Any]],
        SOURCE_EVIDENCE_LINES_OUTPUT_SCHEMA["properties"],
    )
    assert properties["evidence_ranges"]["uniqueItems"] is True
