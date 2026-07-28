"""Evaluation and validation helpers for AegisLM."""

from aegislm.evaluation.absolute import (
    AbsoluteThresholds,
    evaluate_absolute_challenge,
    write_absolute_report,
    write_absolute_summary,
)
from aegislm.evaluation.challenge import (
    build_blind_code_challenge,
    collect_training_fingerprints,
    write_jsonl,
)
from aegislm.evaluation.binary import (
    BinaryThresholds,
    evaluate_binary_predictions,
)
from aegislm.evaluation.harness import (
    Prediction,
    evaluate_predictions,
    load_jsonl,
    load_predictions,
    write_report_html,
    write_summary_json,
)
from aegislm.evaluation.validation import (
    ValidationResult,
    parse_model_output,
    validate_dataset_record,
    validate_model_output,
)

__all__ = [
    "AbsoluteThresholds",
    "Prediction",
    "BinaryThresholds",
    "ValidationResult",
    "build_blind_code_challenge",
    "collect_training_fingerprints",
    "evaluate_absolute_challenge",
    "evaluate_binary_predictions",
    "evaluate_predictions",
    "load_jsonl",
    "load_predictions",
    "parse_model_output",
    "validate_dataset_record",
    "validate_model_output",
    "write_absolute_report",
    "write_absolute_summary",
    "write_jsonl",
    "write_report_html",
    "write_summary_json",
]
