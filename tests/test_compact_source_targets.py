from __future__ import annotations

import hashlib
from copy import deepcopy

import pytest

from aegislm.datasets.source import build_source_target
from aegislm.datasets.sard_juliet import _ordered_unique_spans
from scripts.carry_compact_target_review import carry_compact_review


def _record() -> dict:
    code = "void f() {\n  char dst[4];\n  strcpy(dst, src);\n}"
    return {
        "schema_version": "aegislm.source-vulnerability-record.v1",
        "id": "sample-present",
        "task": {"target_cwe": "CWE-121"},
        "code": {
            "text": code,
            "sha256": hashlib.sha256(code.encode()).hexdigest(),
        },
        "metadata": {
            "label": "present",
            "evidence_level": "code_span_grounded",
            "source_dataset": "fixture",
            "split": "train",
            "contains_executable_payload": False,
        },
    }


def _finding() -> dict:
    return {
        "code_spans": ["char dst[4];", "strcpy(dst, src);"],
        "operation": "The unbounded copy writes into the four-byte destination.",
        "evidence": "The destination capacity is smaller than an unchecked source.",
        "confidence": "high",
    }


def _review(output: dict) -> dict:
    return {
        "id": "sample-present",
        "target_cwe": "CWE-121",
        "code": _record()["code"]["text"],
        "private_label": "present",
        "expected_output": output,
        "review_status": "pass",
        "operator_label_error": False,
        "operator_evidence_error": False,
        "checks": {"code_spans_are_exact": True},
        "reviewer": "reviewer",
        "review_method": "manual",
        "notes": "",
    }


def test_source_target_omits_full_code_excerpt_from_limitations() -> None:
    result = build_source_target(_record(), findings=[_finding()])

    assert result.target is not None
    limitations = result.target["limitations"]
    assert len(limitations) == 2
    assert "reviewed boundary includes" not in " ".join(limitations).lower()
    assert _record()["code"]["text"] not in " ".join(limitations)


def test_equal_position_evidence_spans_have_deterministic_order() -> None:
    short = 'data = CreateFile("example.txt",'
    full = 'data = CreateFile("example.txt",\n    GENERIC_READ,\n    0,\n    NULL);'
    code = f"void f() {{\n{full}\n}}"

    assert _ordered_unique_spans(code, [full, short]) == [short, full]
    assert _ordered_unique_spans(code, [short, full]) == [short, full]


def test_compact_review_carries_only_non_semantic_changes() -> None:
    baseline_output = build_source_target(_record(), findings=[_finding()]).target
    assert baseline_output is not None
    baseline_output = deepcopy(baseline_output)
    baseline_output["limitations"] = [
        "This assessment is limited to the requested CWE and supplied function.",
        "The reviewed boundary includes these supplied code excerpts: "
        + _record()["code"]["text"],
        "This result does not establish whole-program safety or exploitability.",
    ]
    candidate_output = deepcopy(baseline_output)
    candidate_output["limitations"] = [
        "This assessment is limited to the requested CWE and supplied function.",
        "This result does not establish whole-program safety or exploitability.",
    ]
    candidate_output["recommendations"] = [
        "Confirm with deterministic analysis and human review."
    ]

    carried = carry_compact_review(
        [_review(baseline_output)],
        [_review(candidate_output)],
    )

    assert carried[0]["review_status"] == "pass"
    assert carried[0]["operator_label_error"] is False
    assert "only non-semantic" in carried[0]["notes"]


def test_compact_review_rejects_evidence_changes() -> None:
    baseline_output = build_source_target(_record(), findings=[_finding()]).target
    assert baseline_output is not None
    candidate_output = deepcopy(baseline_output)
    candidate_output["findings"][0]["code_spans"] = ["strcpy(dst, src);"]

    with pytest.raises(ValueError, match="semantic output field changed: findings"):
        carry_compact_review(
            [_review(baseline_output)],
            [_review(candidate_output)],
        )
