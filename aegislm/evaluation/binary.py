"""Absolute evaluation helpers for normalized binary-analysis predictions."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any

from aegislm.datasets.binary import validate_binary_output_for_record
from aegislm.evaluation.harness import Prediction


@dataclass(frozen=True)
class BinaryThresholds:
    """Phase F binary quality gates."""

    minimum_sample_count: int = 200
    minimum_precision: float = 0.90
    minimum_recall: float = 0.95
    maximum_false_positive_rate: float = 0.05
    maximum_abstention_rate: float = 0.05
    minimum_parse_success_rate: float = 0.99
    minimum_schema_pass_rate: float = 0.99
    minimum_evidence_rate: float = 0.90
    minimum_compiler_consistency_rate: float = 0.95


def evaluate_binary_predictions(
    records: list[dict[str, Any]],
    predictions: list[Prediction],
    *,
    thresholds: BinaryThresholds | None = None,
) -> dict[str, Any]:
    """Evaluate binary assessment predictions and compiler-group consistency."""
    active = thresholds or BinaryThresholds()
    prediction_by_id = _index_predictions(predictions)
    cases = [
        _evaluate_case(record, prediction_by_id.get(str(record["id"])))
        for record in records
    ]
    gold_positive = sum(case["gold"] == "present" for case in cases)
    gold_negative = sum(case["gold"] == "not_observed" for case in cases)
    true_positive = sum(
        case["gold"] == "present" and case["assessment"] == "present" for case in cases
    )
    false_positive = sum(
        case["gold"] == "not_observed" and case["assessment"] == "present"
        for case in cases
    )
    true_negative = sum(
        case["gold"] == "not_observed" and case["assessment"] == "not_observed"
        for case in cases
    )
    false_negative = gold_positive - true_positive
    abstentions = sum(
        case["assessment"] not in {"present", "not_observed"} for case in cases
    )
    precision = _ratio(true_positive, true_positive + false_positive)
    recall = _ratio(true_positive, gold_positive)
    fpr = _ratio(false_positive, gold_negative)
    consistency = _compiler_consistency(cases)
    metrics = {
        "total_count": len(cases),
        "true_positive_count": true_positive,
        "false_positive_count": false_positive,
        "true_negative_count": true_negative,
        "false_negative_count": false_negative,
        "missing_prediction_count": sum(case["missing"] for case in cases),
        "extra_prediction_count": len(
            set(prediction_by_id) - {str(record["id"]) for record in records}
        ),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "false_positive_rate": round(fpr, 4),
        "abstention_rate": round(_ratio(abstentions, len(cases)), 4),
        "parse_success_rate": _rate(cases, "parse_success"),
        "schema_pass_rate": _rate(cases, "schema_valid"),
        "evidence_rate": _rate(cases, "evidence_present"),
        "compiler_consistency_rate": round(consistency, 4),
    }
    gates = {
        "minimum_sample_count": len(cases) >= active.minimum_sample_count,
        "complete_prediction_set": (
            metrics["missing_prediction_count"] == 0
            and metrics["extra_prediction_count"] == 0
        ),
        "minimum_precision": precision >= active.minimum_precision,
        "minimum_recall": recall >= active.minimum_recall,
        "maximum_false_positive_rate": fpr <= active.maximum_false_positive_rate,
        "maximum_abstention_rate": metrics["abstention_rate"]
        <= active.maximum_abstention_rate,
        "minimum_parse_success_rate": metrics["parse_success_rate"]
        >= active.minimum_parse_success_rate,
        "minimum_schema_pass_rate": metrics["schema_pass_rate"]
        >= active.minimum_schema_pass_rate,
        "minimum_evidence_rate": metrics["evidence_rate"]
        >= active.minimum_evidence_rate,
        "minimum_compiler_consistency_rate": consistency
        >= active.minimum_compiler_consistency_rate,
    }
    return {
        "evaluation_type": "absolute_binary_derived_challenge",
        "overall_pass": all(gates.values()),
        "thresholds": asdict(active),
        "gates": gates,
        "metrics": metrics,
        "cases": cases,
    }


def _evaluate_case(
    record: dict[str, Any],
    prediction: Prediction | None,
) -> dict[str, Any]:
    metadata = record["metadata"]
    case = {
        "record_id": record["id"],
        "compiler_group_id": metadata["compiler_group_id"],
        "gold": metadata["label"],
        "assessment": None,
        "missing": prediction is None,
        "parse_success": False,
        "schema_valid": False,
        "evidence_present": False,
        "errors": [],
    }
    if prediction is None:
        case["errors"].append("prediction missing")
        return case
    try:
        output = json.loads(prediction.raw_output)
    except json.JSONDecodeError as exc:
        case["errors"].append(f"invalid JSON: {exc.msg}")
        return case
    if not isinstance(output, dict):
        case["errors"].append("output must be a JSON object")
        return case
    case["parse_success"] = True
    errors = validate_binary_output_for_record(output, record)
    case["errors"].extend(errors)
    case["schema_valid"] = not errors
    if not errors:
        case["assessment"] = output["assessment"]
        findings = output["findings"]
        case["evidence_present"] = (
            output["assessment"] != "present"
            or bool(findings)
            and all(
                isinstance(item.get("observation"), str)
                and bool(item["observation"].strip())
                for item in findings
            )
        )
    return case


def _compiler_consistency(cases: list[dict[str, Any]]) -> float:
    assessments_by_group: dict[str, list[str]] = {}
    for case in cases:
        assessment = case["assessment"]
        if isinstance(assessment, str):
            assessments_by_group.setdefault(case["compiler_group_id"], []).append(
                assessment
            )
    multi_variant = [
        values for values in assessments_by_group.values() if len(values) >= 2
    ]
    if not multi_variant:
        return 0.0
    consistent = sum(len(set(values)) == 1 for values in multi_variant)
    return _ratio(consistent, len(multi_variant))


def _index_predictions(predictions: list[Prediction]) -> dict[str, Prediction]:
    indexed: dict[str, Prediction] = {}
    for prediction in predictions:
        if prediction.record_id in indexed:
            raise ValueError(f"duplicate prediction record_id: {prediction.record_id}")
        indexed[prediction.record_id] = prediction
    return indexed


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _rate(cases: list[dict[str, Any]], key: str) -> float:
    return round(_ratio(sum(bool(case[key]) for case in cases), len(cases)), 4)
