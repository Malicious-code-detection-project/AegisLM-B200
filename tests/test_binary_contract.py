from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from aegislm.datasets.binary import (
    BinaryRecordValidationError,
    format_binary_prompt,
    validate_binary_record,
)
from aegislm.evaluation import BinaryThresholds, Prediction, evaluate_binary_predictions
from aegislm.inference.binary import run_binary_inference


def _record(
    record_id: str = "binary-fixture-1",
    *,
    label: str = "present",
    compiler_group_id: str = "group-1",
) -> dict:
    return {
        "schema_version": "aegislm.binary-analysis-record.v1",
        "id": record_id,
        "artifact": {
            "sha256": "a" * 64,
            "format": "ELF",
            "architecture": "x86_64",
            "compiler": "clang",
            "optimization": "O2",
            "stripped": True,
            "external_artifact_ref": "approved://binary-fixture-1",
        },
        "analysis": {
            "analyzer": "offline-extractor",
            "analyzer_version": "1.0",
            "decompiler": "test-decompiler",
            "decompiler_version": "1.0",
            "functions": [
                {
                    "function_id": "function-1",
                    "function_hash": "b" * 64,
                    "pseudo_c": "copy(dst, src);",
                    "assembly_evidence": ["call copy"],
                    "static_features": {
                        "imports": ["copy"],
                        "sections": [".text"],
                        "strings": [],
                        "symbols": [],
                    },
                }
            ],
            "warnings": ["Symbols are stripped."],
        },
        "task": {"target_cwe": "CWE-120"},
        "metadata": {
            "split": "test",
            "source_dataset": "private-fixture",
            "label": label,
            "compiler_group_id": compiler_group_id,
            "contains_executable_payload": False,
        },
    }


def _output(assessment: str) -> str:
    return json.dumps(
        {
            "scope": {
                "target_cwe": "CWE-120",
                "binary_format": "ELF",
                "architecture": "x86_64",
            },
            "assessment": assessment,
            "findings": (
                [
                    {
                        "function_id": "function-1",
                        "representation": "pseudo_c",
                        "observation": "The pseudo-C contains a security-sensitive copy.",
                        "confidence": "medium",
                    }
                ]
                if assessment == "present"
                else []
            ),
            "limitations": ["The assessment is scoped to the supplied function."],
            "recommendations": ["Confirm with deterministic analysis."],
        }
    )


def test_binary_record_and_prompt_hide_provenance_and_gold() -> None:
    record = _record()

    validate_binary_record(record)
    messages = format_binary_prompt(record)
    prompt = json.dumps(messages)

    assert "private-fixture" not in prompt
    assert '"label"' not in prompt
    assert "approved://binary-fixture-1" not in prompt
    assert "a" * 64 not in prompt
    assert "copy(dst, src)" in prompt
    assert "CWE-120" in prompt


def test_binary_record_rejects_raw_payload_key() -> None:
    record = _record()
    record["analysis"]["functions"][0]["static_features"]["raw_bytes"] = "7f454c46"

    with pytest.raises(BinaryRecordValidationError, match="raw_bytes"):
        validate_binary_record(record)


def test_binary_evaluation_applies_absolute_and_consistency_gates() -> None:
    records = [
        _record("positive-gcc", label="present", compiler_group_id="positive"),
        _record("positive-clang", label="present", compiler_group_id="positive"),
        _record("negative-gcc", label="not_observed", compiler_group_id="negative"),
        _record("negative-clang", label="not_observed", compiler_group_id="negative"),
    ]
    predictions = [
        Prediction(
            record_id=record["id"],
            model_id="fixture",
            run_id="binary-test",
            raw_output=_output(record["metadata"]["label"]),
        )
        for record in records
    ]

    summary = evaluate_binary_predictions(
        records,
        predictions,
        thresholds=BinaryThresholds(minimum_sample_count=4),
    )

    assert summary["overall_pass"]
    assert summary["metrics"]["precision"] == 1.0
    assert summary["metrics"]["recall"] == 1.0
    assert summary["metrics"]["compiler_consistency_rate"] == 1.0


def test_binary_prompt_does_not_mutate_record() -> None:
    record = _record()
    original = deepcopy(record)

    format_binary_prompt(record)

    assert record == original


def test_binary_inference_writes_prediction_compatible_jsonl(tmp_path: Path) -> None:
    dataset_path = tmp_path / "binary.jsonl"
    predictions_path = tmp_path / "predictions.jsonl"
    dataset_path.write_text(json.dumps(_record()) + "\n", encoding="utf-8")

    count = run_binary_inference(
        dataset_path=dataset_path,
        predictions_path=predictions_path,
        model_id="fixture",
        run_id="binary-round-trip",
        generate_response=lambda _messages: _output("present"),
    )

    prediction = json.loads(predictions_path.read_text(encoding="utf-8"))
    assert count == 1
    assert prediction["record_id"] == "binary-fixture-1"
    assert prediction["run_id"] == "binary-round-trip"
    assert json.loads(prediction["raw_output"])["assessment"] == "present"
