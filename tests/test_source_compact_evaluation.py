from __future__ import annotations

import json

from aegislm.evaluation.harness import Prediction
from aegislm.evaluation.source_compact import (
    SourceCompactThresholds,
    evaluate_source_compact_predictions,
)


def _challenge(record_id: str, cwe: str, code: str) -> dict:
    payload = json.dumps(
        {
            "scope": {"target_cwe": cwe, "boundary": "supplied_function"},
            "source_code": code,
        },
        indent=2,
    )
    return {
        "id": record_id,
        "messages": [
            {"role": "system", "content": "compact contract"},
            {"role": "user", "content": f"Assess.\n\n{payload}\n\nReturn JSON."},
        ],
    }


def _output(assessment: str, span: str) -> dict:
    return {
        "schema_version": "aegislm.source-compact-evidence.v1",
        "assessment": assessment,
        "evidence_spans": [span],
        "confidence": "high",
    }


def test_compact_evaluator_scores_decision_evidence_and_renderer() -> None:
    rows = [
        ("positive", "present", "strcpy(dst, src);"),
        ("negative", "not_observed", "if (n < size)"),
    ]
    challenge = [_challenge(item[0], "CWE-120", item[2]) for item in rows]
    gold = [
        {"id": item[0], "expected_output": _output(item[1], item[2])} for item in rows
    ]
    predictions = [
        Prediction(
            item[0],
            "model",
            "run",
            json.dumps(_output(item[1], item[2])),
        )
        for item in rows
    ]
    result = evaluate_source_compact_predictions(
        challenge,
        gold,
        predictions,
        thresholds=SourceCompactThresholds(minimum_sample_count=2),
    )

    assert result["overall_pass"] is True
    assert result["metrics"]["precision"] == 1.0
    assert result["metrics"]["recall"] == 1.0
    assert result["metrics"]["evidence_f1"] == 1.0
    assert result["metrics"]["renderer_pass_rate"] == 1.0


def test_compact_evaluator_rejects_invented_span() -> None:
    challenge = [_challenge("case", "CWE-120", "strcpy(dst, src);")]
    gold = [
        {
            "id": "case",
            "expected_output": _output("present", "strcpy(dst, src);"),
        }
    ]
    prediction = Prediction(
        "case",
        "model",
        "run",
        json.dumps(_output("present", "memcpy(dst, src, n);")),
    )
    result = evaluate_source_compact_predictions(
        challenge,
        gold,
        [prediction],
        thresholds=SourceCompactThresholds(minimum_sample_count=1),
    )

    assert result["overall_pass"] is False
    assert result["metrics"]["parse_success_rate"] == 1.0
    assert result["metrics"]["schema_pass_rate"] == 0.0
    assert result["metrics"]["abstention_rate"] == 1.0
