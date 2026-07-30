"""Absolute diagnostic evaluation for the compact source evidence contract."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from aegislm.datasets.source_compact import (
    render_source_assessment,
    validate_compact_evidence_output,
)
from aegislm.evaluation.harness import Prediction


@dataclass(frozen=True)
class SourceCompactThresholds:
    minimum_sample_count: int = 100
    minimum_precision: float = 0.75
    minimum_recall: float = 0.75
    maximum_false_positive_rate: float = 0.20
    maximum_abstention_rate: float = 0.10
    minimum_parse_success_rate: float = 0.99
    minimum_schema_pass_rate: float = 0.99
    minimum_evidence_precision: float = 0.50
    minimum_evidence_recall: float = 0.50
    minimum_renderer_pass_rate: float = 1.00


def evaluate_source_compact_predictions(
    challenge_rows: list[dict[str, Any]],
    gold_rows: list[dict[str, Any]],
    predictions: list[Prediction],
    *,
    thresholds: SourceCompactThresholds | None = None,
) -> dict[str, Any]:
    """Evaluate decisions, exact spans, gold overlap, and rendered v2 reports."""
    active = thresholds or SourceCompactThresholds()
    challenge = _index_rows(challenge_rows, "challenge")
    gold = _index_rows(gold_rows, "gold")
    if set(challenge) != set(gold):
        raise ValueError("compact challenge and gold ids differ")
    predicted = _index_predictions(predictions)
    cases = [
        _evaluate_case(
            record_id,
            challenge[record_id],
            gold[record_id],
            predicted.get(record_id),
        )
        for record_id in challenge
    ]
    positives = sum(case["gold"] == "present" for case in cases)
    negatives = sum(case["gold"] == "not_observed" for case in cases)
    tp = sum(
        case["gold"] == "present" and case["assessment"] == "present" for case in cases
    )
    fp = sum(
        case["gold"] == "not_observed" and case["assessment"] == "present"
        for case in cases
    )
    tn = sum(
        case["gold"] == "not_observed" and case["assessment"] == "not_observed"
        for case in cases
    )
    fn = positives - tp
    abstentions = sum(
        case["assessment"] not in {"present", "not_observed"} for case in cases
    )
    evidence_tp = sum(case["evidence_true_positive_count"] for case in cases)
    evidence_predicted = sum(case["evidence_predicted_count"] for case in cases)
    evidence_gold = sum(case["evidence_gold_count"] for case in cases)
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, positives)
    fpr = _ratio(fp, negatives)
    evidence_precision = _ratio(evidence_tp, evidence_predicted)
    evidence_recall = _ratio(evidence_tp, evidence_gold)
    metrics = {
        "total_count": len(cases),
        "true_positive_count": tp,
        "false_positive_count": fp,
        "true_negative_count": tn,
        "false_negative_count": fn,
        "missing_prediction_count": sum(case["missing"] for case in cases),
        "extra_prediction_count": len(set(predicted) - set(gold)),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "false_positive_rate": round(fpr, 4),
        "abstention_rate": round(_ratio(abstentions, len(cases)), 4),
        "parse_success_rate": _rate(cases, "parse_success"),
        "schema_pass_rate": _rate(cases, "schema_valid"),
        "renderer_pass_rate": _rate(cases, "renderer_valid"),
        "evidence_precision": round(evidence_precision, 4),
        "evidence_recall": round(evidence_recall, 4),
        "evidence_f1": round(
            _ratio(
                2 * evidence_precision * evidence_recall,
                evidence_precision + evidence_recall,
            ),
            4,
        ),
        "latency_p50_ms": _latency(cases, 0.50),
        "latency_p95_ms": _latency(cases, 0.95),
    }
    gates = {
        "minimum_sample_count": len(cases) >= active.minimum_sample_count,
        "complete_prediction_set": (
            metrics["missing_prediction_count"] == 0
            and metrics["extra_prediction_count"] == 0
        ),
        "both_binary_labels_present": positives > 0 and negatives > 0,
        "minimum_precision": precision >= active.minimum_precision,
        "minimum_recall": recall >= active.minimum_recall,
        "maximum_false_positive_rate": fpr <= active.maximum_false_positive_rate,
        "maximum_abstention_rate": (
            metrics["abstention_rate"] <= active.maximum_abstention_rate
        ),
        "minimum_parse_success_rate": (
            metrics["parse_success_rate"] >= active.minimum_parse_success_rate
        ),
        "minimum_schema_pass_rate": (
            metrics["schema_pass_rate"] >= active.minimum_schema_pass_rate
        ),
        "minimum_evidence_precision": (
            evidence_precision >= active.minimum_evidence_precision
        ),
        "minimum_evidence_recall": evidence_recall >= active.minimum_evidence_recall,
        "minimum_renderer_pass_rate": (
            metrics["renderer_pass_rate"] >= active.minimum_renderer_pass_rate
        ),
    }
    model_ids = sorted({item.model_id for item in predictions})
    run_ids = sorted({item.run_id for item in predictions})
    return {
        "evaluation_type": "diagnostic_source_compact_evidence",
        "diagnostic_only": True,
        "overall_pass": all(gates.values()),
        "model_id": model_ids[0] if len(model_ids) == 1 else "mixed",
        "run_id": run_ids[0] if len(run_ids) == 1 else "mixed",
        "thresholds": asdict(active),
        "gates": gates,
        "metrics": metrics,
        "cases": cases,
    }


def write_source_compact_summary(result: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _evaluate_case(
    record_id: str,
    challenge: dict[str, Any],
    gold: dict[str, Any],
    prediction: Prediction | None,
) -> dict[str, Any]:
    source_code, target_cwe = _prompt_scope(challenge)
    expected = gold.get("expected_output")
    if not isinstance(expected, dict):
        raise ValueError(f"{record_id}: compact gold expected_output is invalid")
    expected_errors = validate_compact_evidence_output(
        expected,
        source_code=source_code,
    )
    if expected_errors:
        raise ValueError(f"{record_id}: invalid compact gold: {expected_errors}")
    gold_spans = set(str(span) for span in expected["evidence_spans"])
    case: dict[str, Any] = {
        "record_id": record_id,
        "gold": expected["assessment"],
        "assessment": None,
        "missing": prediction is None,
        "parse_success": False,
        "schema_valid": False,
        "renderer_valid": False,
        "evidence_true_positive_count": 0,
        "evidence_predicted_count": 0,
        "evidence_gold_count": len(gold_spans),
        "latency_ms": prediction.latency_ms if prediction is not None else None,
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
    errors = validate_compact_evidence_output(output, source_code=source_code)
    if errors:
        case["errors"].extend(errors)
        return case
    case["schema_valid"] = True
    case["assessment"] = output["assessment"]
    predicted_spans = set(str(span) for span in output["evidence_spans"])
    case["evidence_true_positive_count"] = len(gold_spans & predicted_spans)
    case["evidence_predicted_count"] = len(predicted_spans)
    try:
        render_source_assessment(
            output,
            target_cwe=target_cwe,
            source_code=source_code,
        )
    except ValueError as exc:
        case["errors"].append(f"renderer failed: {exc}")
        return case
    case["renderer_valid"] = True
    return case


def _prompt_scope(row: dict[str, Any]) -> tuple[str, str]:
    messages = row.get("messages")
    if not isinstance(messages, list) or len(messages) != 2:
        raise ValueError(f"{row.get('id')}: invalid compact challenge messages")
    user = messages[1]
    if not isinstance(user, dict) or not isinstance(user.get("content"), str):
        raise ValueError(f"{row.get('id')}: invalid compact user message")
    content = str(user["content"])
    start = content.find("{")
    if start < 0:
        raise ValueError(f"{row.get('id')}: prompt JSON missing")
    payload, _ = json.JSONDecoder().raw_decode(content[start:])
    if not isinstance(payload, dict) or not isinstance(payload.get("scope"), dict):
        raise ValueError(f"{row.get('id')}: prompt scope missing")
    source_code = payload.get("source_code")
    target_cwe = payload["scope"].get("target_cwe")
    if not isinstance(source_code, str) or not isinstance(target_cwe, str):
        raise ValueError(f"{row.get('id')}: prompt source or CWE missing")
    return source_code, target_cwe


def _index_rows(
    rows: list[dict[str, Any]],
    name: str,
) -> dict[str, dict[str, Any]]:
    indexed = {str(row["id"]): row for row in rows}
    if len(indexed) != len(rows):
        raise ValueError(f"compact {name} contains duplicate ids")
    return indexed


def _index_predictions(predictions: list[Prediction]) -> dict[str, Prediction]:
    indexed: dict[str, Prediction] = {}
    for prediction in predictions:
        if prediction.record_id in indexed:
            raise ValueError(f"duplicate prediction record_id: {prediction.record_id}")
        indexed[prediction.record_id] = prediction
    return indexed


def _ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def _rate(cases: list[dict[str, Any]], key: str) -> float:
    return round(_ratio(sum(bool(case[key]) for case in cases), len(cases)), 4)


def _latency(cases: list[dict[str, Any]], percentile: float) -> float | None:
    values = sorted(
        float(case["latency_ms"]) for case in cases if case["latency_ms"] is not None
    )
    if not values:
        return None
    index = max(0, min(len(values) - 1, int((len(values) - 1) * percentile)))
    return round(values[index], 4)
