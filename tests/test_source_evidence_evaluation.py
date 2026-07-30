from __future__ import annotations

import hashlib
import json

from aegislm.datasets.source_evidence_lines import format_evidence_lines_prompt
from aegislm.evaluation.harness import Prediction
from aegislm.evaluation.source_evidence_lines import (
    SourceEvidenceThresholds,
    evaluate_source_evidence_predictions,
)


def _record(record_id: str) -> dict:
    code = "if (n < size) {\n    buffer[n] = 1;\n}"
    return {
        "schema_version": "aegislm.source-vulnerability-record.v1",
        "id": record_id,
        "code": {
            "text": code,
            "sha256": hashlib.sha256(code.encode()).hexdigest(),
        },
        "task": {"target_cwe": "CWE-129"},
        "metadata": {
            "split": "validation",
            "source_dataset": "fixture",
            "label": "not_observed",
            "evidence_level": "code_span_grounded",
            "contains_executable_payload": False,
        },
    }


def _output(start: int = 1, end: int = 2) -> dict:
    return {
        "schema_version": "aegislm.source-evidence-lines.v1",
        "evidence_ranges": [{"start_line": start, "end_line": end}],
        "confidence": "high",
    }


def test_evidence_evaluator_scores_line_overlap_and_renderer() -> None:
    record = _record("case")
    challenge = [
        {
            "id": "case",
            "messages": format_evidence_lines_prompt(
                record,
                assessment="not_observed",
            ),
        }
    ]
    gold = [{"id": "case", "expected_output": _output()}]
    predictions = [
        Prediction("case", "model", "run", json.dumps(_output()), latency_ms=3.0)
    ]
    result = evaluate_source_evidence_predictions(
        challenge,
        gold,
        [record],
        predictions,
        thresholds=SourceEvidenceThresholds(minimum_sample_count=1),
        blind_test_used=True,
    )

    assert result["overall_pass"] is True
    assert result["metrics"]["evidence_f1"] == 1.0
    assert result["metrics"]["renderer_pass_rate"] == 1.0
    assert result["diagnostic_only"] is False
    assert result["blind_test_used"] is True


def test_evidence_evaluator_rejects_out_of_bounds_range() -> None:
    record = _record("case")
    challenge = [
        {
            "id": "case",
            "messages": format_evidence_lines_prompt(
                record,
                assessment="not_observed",
            ),
        }
    ]
    result = evaluate_source_evidence_predictions(
        challenge,
        [{"id": "case", "expected_output": _output()}],
        [record],
        [Prediction("case", "model", "run", json.dumps(_output(1, 8)))],
        thresholds=SourceEvidenceThresholds(minimum_sample_count=1),
    )

    assert result["overall_pass"] is False
    assert result["metrics"]["parse_success_rate"] == 1.0
    assert result["metrics"]["schema_pass_rate"] == 0.0
