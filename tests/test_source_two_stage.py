from __future__ import annotations

import hashlib
import json

import pytest

from aegislm.datasets.source import (
    SourceContractError,
    build_source_target,
)
from aegislm.datasets.source_two_stage import (
    build_predicted_assessment_evidence_challenge,
    build_source_evidence_gold,
)


def _record(record_id: str) -> dict:
    code = "void f() {\n    sink();\n}"
    return {
        "schema_version": "aegislm.source-vulnerability-record.v1",
        "id": record_id,
        "code": {
            "text": code,
            "sha256": hashlib.sha256(code.encode()).hexdigest(),
        },
        "task": {"target_cwe": "CWE-120"},
        "metadata": {
            "split": "fixture",
            "source_dataset": "fixture",
            "label": "present",
            "evidence_level": "code_span_grounded",
            "contains_executable_payload": False,
        },
    }


def test_two_stage_challenge_uses_only_predicted_assessment() -> None:
    rows = build_predicted_assessment_evidence_challenge(
        [_record("case-1")],
        [
            {
                "record_id": "case-1",
                "raw_output": json.dumps({"assessment": "not_observed"}),
            }
        ],
    )
    visible = "\n".join(message["content"] for message in rows[0]["messages"])

    assert '"assessment": "not_observed"' in visible
    assert "case-1" not in visible
    assert '"label"' not in visible


def test_two_stage_challenge_rejects_nonbinary_decision() -> None:
    with pytest.raises(SourceContractError, match="not a binary"):
        build_predicted_assessment_evidence_challenge(
            [_record("case-1")],
            [
                {
                    "record_id": "case-1",
                    "raw_output": json.dumps({"assessment": "uncertain"}),
                }
            ],
        )


def test_two_stage_projects_report_gold_to_line_ranges() -> None:
    record = _record("case-1")
    target = build_source_target(
        record,
        findings=[
            {
                "code_span": "sink();",
                "operation": "fixture operation",
                "evidence": "The supplied call is the scoped fixture evidence.",
                "confidence": "high",
            }
        ],
    ).target
    assert target is not None

    rows = build_source_evidence_gold(
        [record],
        [{"id": "case-1", "expected_output": target}],
    )

    assert rows == [
        {
            "id": "case-1",
            "expected_output": {
                "schema_version": "aegislm.source-evidence-lines.v1",
                "evidence_ranges": [{"start_line": 2, "end_line": 2}],
                "confidence": "high",
            },
        }
    ]


def test_two_stage_evidence_gold_requires_all_private_ids() -> None:
    with pytest.raises(SourceContractError, match="missing 1"):
        build_source_evidence_gold([_record("case-1")], [])
