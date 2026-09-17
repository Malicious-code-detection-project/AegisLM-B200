from __future__ import annotations

import hashlib

from aegislm.datasets.source import build_source_target, validate_source_output
from aegislm.datasets.source_compact import (
    format_compact_evidence_prompt,
    project_full_report_target,
    render_source_assessment,
    validate_compact_evidence_output,
)


def _record() -> dict:
    code = "void f(char *dst, const char *src) { strcpy(dst, src); }"

    return {
        "schema_version": "aegislm.source-vulnerability-record.v1",
        "id": "case-1",
        "code": {
            "text": code,
            "sha256": hashlib.sha256(code.encode()).hexdigest(),
        },
        "task": {"target_cwe": "CWE-120"},
        "metadata": {
            "split": "train",
            "source_dataset": "fixture",
            "label": "present",
            "evidence_level": "code_span_grounded",
            "contains_executable_payload": False,
        },
    }


def _full_target() -> dict:
    result = build_source_target(
        _record(),
        findings=[
            {
                "code_span": "strcpy(dst, src);",
                "operation": "unbounded copy",
                "evidence": "The copy has no visible destination bound.",
                "confidence": "high",
            }
        ],
    )
    assert result.target is not None
    return result.target


def test_compact_contract_requires_exact_evidence() -> None:
    source = _record()["code"]["text"]
    valid = {
        "schema_version": "aegislm.source-compact-evidence.v1",
        "assessment": "present",
        "evidence_spans": ["strcpy(dst, src);"],
        "confidence": "high",
    }
    assert validate_compact_evidence_output(valid, source_code=source) == []

    missing = dict(valid, evidence_spans=[])
    assert validate_compact_evidence_output(missing, source_code=source)

    invented = dict(valid, evidence_spans=["memcpy(dst, src, n);"])
    assert any(
        "not an exact source substring" in error
        for error in validate_compact_evidence_output(
            invented,
            source_code=source,
        )
    )


def test_full_target_projection_and_renderer_round_trip() -> None:
    record = _record()
    compact = project_full_report_target(
        _full_target(),
        source_code=record["code"]["text"],
    )

    assert compact == {
        "schema_version": "aegislm.source-compact-evidence.v1",
        "assessment": "present",
        "evidence_spans": ["strcpy(dst, src);"],
        "confidence": "high",
    }
    report = render_source_assessment(
        compact,
        target_cwe="CWE-120",
        source_code=record["code"]["text"],
    )
    assert (
        validate_source_output(
            report,
            source_code=record["code"]["text"],
        )
        == []
    )
    assert report["findings"][0]["code_spans"] == ["strcpy(dst, src);"]


def test_compact_prompt_excludes_private_metadata() -> None:
    prompt = format_compact_evidence_prompt(_record())
    visible = "\n".join(message["content"] for message in prompt)

    assert "CWE-120" in visible
    assert "strcpy(dst, src);" in visible
    assert '"label"' not in visible
    assert '"split"' not in visible
    assert '"source_dataset"' not in visible
    assert "case-1" not in visible


def test_uncertain_requires_no_evidence_and_renders_without_findings() -> None:
    record = _record()
    compact = {
        "schema_version": "aegislm.source-compact-evidence.v1",
        "assessment": "uncertain",
        "evidence_spans": [],
        "confidence": "low",
    }
    assert (
        validate_compact_evidence_output(
            compact,
            source_code=record["code"]["text"],
        )
        == []
    )
    report = render_source_assessment(
        compact,
        target_cwe="CWE-120",
        source_code=record["code"]["text"],
    )
    assert report["assessment_basis"][0]["code_spans"] == [record["code"]["text"]]
    assert report["findings"] == []
