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
from aegislm.evaluation.source import (
    SourceThresholds,
    evaluate_source_predictions,
    write_source_report,
    write_source_summary,
)
from aegislm.evaluation.source_decision import (
    SourceDecisionThresholds,
    evaluate_source_decisions,
    write_source_decision_summary,
)
from aegislm.evaluation.source_compact import (
    SourceCompactThresholds,
    evaluate_source_compact_predictions,
    write_source_compact_summary,
)
from aegislm.evaluation.source_evidence_lines import (
    SourceEvidenceThresholds,
    evaluate_source_evidence_predictions,
    write_source_evidence_summary,
)
from aegislm.evaluation.source_two_stage import (
    SourceTwoStageThresholds,
    evaluate_source_two_stage_predictions,
    write_source_two_stage_summary,
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
    "SourceThresholds",
    "SourceDecisionThresholds",
    "SourceCompactThresholds",
    "SourceEvidenceThresholds",
    "ValidationResult",
    "build_blind_code_challenge",
    "collect_training_fingerprints",
    "evaluate_absolute_challenge",
    "evaluate_binary_predictions",
    "evaluate_predictions",
    "evaluate_source_predictions",
    "evaluate_source_decisions",
    "evaluate_source_compact_predictions",
    "evaluate_source_evidence_predictions",
    "write_source_report",
    "write_source_summary",
    "write_source_decision_summary",
    "write_source_compact_summary",
    "write_source_evidence_summary",
    "SourceTwoStageThresholds",
    "evaluate_source_two_stage_predictions",
    "write_source_two_stage_summary",
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
