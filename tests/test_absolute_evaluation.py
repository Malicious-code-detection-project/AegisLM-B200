import json
from typing import Any

from aegislm.evaluation import (
    AbsoluteThresholds,
    Prediction,
    evaluate_absolute_challenge,
)


def _output(risk_level: str, *, vulnerable_evidence: bool) -> dict[str, Any]:
    behaviors = (
        [
            {
                "behavior": "unsafe memory copy",
                "evidence": "The excerpt copies attacker-controlled input.",
                "confidence": "high",
            }
        ]
        if vulnerable_evidence
        else []
    )
    return {
        "summary": "Static source-code assessment.",
        "behavior_explanation": "The assessment is limited to visible code.",
        "risk_level": risk_level,
        "malware_like_behaviors": behaviors,
        "attack_mapping": [],
        "recommendations": ["Review the code with deterministic static analysis."],
        "limitations": ["No build or runtime behavior was analyzed."],
    }


def _prediction(record_id: str, risk_level: str) -> Prediction:
    return Prediction(
        record_id=record_id,
        model_id="test-model",
        run_id="test-run",
        raw_output=json.dumps(
            _output(risk_level, vulnerable_evidence=risk_level in {"high", "critical"})
        ),
        latency_ms=10.0,
    )


def _thresholds() -> AbsoluteThresholds:
    return AbsoluteThresholds(minimum_sample_count=4)


def test_perfect_absolute_predictions_pass_all_gates() -> None:
    gold = [
        {"record_id": "v1", "is_vulnerable": True},
        {"record_id": "v2", "is_vulnerable": True},
        {"record_id": "b1", "is_vulnerable": False},
        {"record_id": "b2", "is_vulnerable": False},
    ]
    predictions = [
        _prediction("v1", "high"),
        _prediction("v2", "critical"),
        _prediction("b1", "low"),
        _prediction("b2", "low"),
    ]

    result = evaluate_absolute_challenge(gold, predictions, thresholds=_thresholds())

    assert result["overall_pass"]
    assert result["metrics"]["precision"] == 1.0
    assert result["metrics"]["recall"] == 1.0
    assert result["metrics"]["false_positive_rate"] == 0.0
    assert all(result["gates"].values())


def test_abstention_on_positive_counts_against_recall() -> None:
    gold = [
        {"record_id": "v1", "is_vulnerable": True},
        {"record_id": "v2", "is_vulnerable": True},
        {"record_id": "b1", "is_vulnerable": False},
        {"record_id": "b2", "is_vulnerable": False},
    ]
    predictions = [
        _prediction("v1", "high"),
        _prediction("v2", "unknown"),
        _prediction("b1", "low"),
        _prediction("b2", "low"),
    ]

    result = evaluate_absolute_challenge(gold, predictions, thresholds=_thresholds())

    assert not result["overall_pass"]
    assert result["metrics"]["recall"] == 0.5
    assert result["metrics"]["false_negative_count"] == 1
    assert result["metrics"]["abstention_rate"] == 0.25


def test_invalid_and_missing_predictions_fail_completeness_and_format() -> None:
    gold = [
        {"record_id": "v1", "is_vulnerable": True},
        {"record_id": "b1", "is_vulnerable": False},
    ]
    predictions = [
        Prediction(
            record_id="v1",
            model_id="test-model",
            run_id="test-run",
            raw_output="not json",
        )
    ]
    thresholds = AbsoluteThresholds(minimum_sample_count=2)

    result = evaluate_absolute_challenge(gold, predictions, thresholds=thresholds)

    assert not result["overall_pass"]
    assert result["metrics"]["missing_prediction_count"] == 1
    assert result["metrics"]["parse_success_rate"] == 0.0
    assert not result["gates"]["complete_prediction_set"]
