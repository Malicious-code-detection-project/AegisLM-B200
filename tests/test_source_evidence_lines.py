from __future__ import annotations

import hashlib

import pytest

from aegislm.datasets.source import SourceContractError, validate_source_output
from aegislm.datasets.source_evidence_lines import (
    format_evidence_lines_prompt,
    number_source_code,
    project_compact_to_evidence_lines,
    render_assessment_from_evidence_lines,
    resolve_evidence_ranges,
    validate_evidence_lines_output,
)


def _record() -> dict:
    code = "\n".join(
        [
            "void f(char *dst, const char *src) {",
            "    if (dst != NULL) {",
            "        strcpy(dst, src);",
            "    }",
            "}",
        ]
    )
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


def test_line_projection_resolves_to_exact_source() -> None:
    source = _record()["code"]["text"]
    compact = {
        "schema_version": "aegislm.source-compact-evidence.v1",
        "assessment": "present",
        "evidence_spans": ["if (dst != NULL)", "strcpy(dst, src);"],
        "confidence": "high",
    }
    target = project_compact_to_evidence_lines(compact, source_code=source)

    assert target["evidence_ranges"] == [{"start_line": 2, "end_line": 3}]
    assert resolve_evidence_ranges(target, source_code=source) == [
        "    if (dst != NULL) {\n        strcpy(dst, src);"
    ]


def test_line_validator_rejects_out_of_bounds_and_overlap() -> None:
    invalid = {
        "schema_version": "aegislm.source-evidence-lines.v1",
        "evidence_ranges": [
            {"start_line": 2, "end_line": 3},
            {"start_line": 3, "end_line": 8},
        ],
        "confidence": "high",
    }
    errors = validate_evidence_lines_output(invalid, line_count=5)

    assert any("exceeds source line count" in error for error in errors)
    assert any("overlaps" in error for error in errors)


def test_assessment_conditioned_prompt_has_numbered_code_without_metadata() -> None:
    prompt = format_evidence_lines_prompt(_record(), assessment="present")
    visible = "\n".join(item["content"] for item in prompt)

    assert "0003|        strcpy(dst, src);" in visible
    assert '"assessment": "present"' in visible
    assert '"label"' not in visible
    assert '"split"' not in visible
    assert "case-1" not in visible
    assert number_source_code(_record()["code"]["text"]).startswith("0001|")


def test_line_output_renders_valid_v2_report() -> None:
    record = _record()
    output = {
        "schema_version": "aegislm.source-evidence-lines.v1",
        "evidence_ranges": [{"start_line": 2, "end_line": 3}],
        "confidence": "high",
    }
    report = render_assessment_from_evidence_lines(
        output,
        assessment="present",
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


def test_line_resolver_drops_blank_only_ranges_but_requires_real_evidence() -> None:
    source = "void f() {\n\n    sink();\n}"
    mixed = {
        "schema_version": "aegislm.source-evidence-lines.v1",
        "evidence_ranges": [
            {"start_line": 2, "end_line": 2},
            {"start_line": 3, "end_line": 3},
        ],
        "confidence": "high",
    }
    blank_only = {
        "schema_version": "aegislm.source-evidence-lines.v1",
        "evidence_ranges": [{"start_line": 2, "end_line": 2}],
        "confidence": "high",
    }

    assert resolve_evidence_ranges(mixed, source_code=source) == ["    sink();"]
    with pytest.raises(SourceContractError, match="only blank lines"):
        resolve_evidence_ranges(blank_only, source_code=source)


def test_line_resolver_deduplicates_identical_text_from_distinct_lines() -> None:
    source = "void f() {\n    if (globalTrue) {\n    }\n    if (globalTrue) {\n    }\n}"
    output = {
        "schema_version": "aegislm.source-evidence-lines.v1",
        "evidence_ranges": [
            {"start_line": 2, "end_line": 2},
            {"start_line": 4, "end_line": 4},
        ],
        "confidence": "high",
    }

    assert resolve_evidence_ranges(output, source_code=source) == [
        "    if (globalTrue) {"
    ]
    report = render_assessment_from_evidence_lines(
        output,
        assessment="present",
        target_cwe="CWE-120",
        source_code=source,
    )
    assert validate_source_output(report, source_code=source) == []
