from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from aegislm.evaluation.source import (
    SourceThresholds,
    evaluate_source_predictions,
    write_source_report,
    write_source_summary,
)
from aegislm.inference.chat_dataset import run_chat_dataset_inference
from aegislm.evaluation.harness import Prediction
from aegislm.prompts import PromptMessage


def _challenge_row(record_id: str) -> dict[str, Any]:
    return {
        "id": record_id,
        "messages": [
            {"role": "system", "content": "Return JSON."},
            {"role": "user", "content": f"Review {record_id}."},
        ],
    }


def test_chat_dataset_inference_preserves_order_with_concurrent_workers(
    tmp_path: Path,
) -> None:
    dataset = tmp_path / "challenge.jsonl"
    predictions = tmp_path / "predictions.jsonl"
    rows = [_challenge_row("one"), _challenge_row("two")]
    dataset.write_text(
        "".join(json.dumps(row) + "\n" for row in rows),
        encoding="utf-8",
    )

    def generate(messages: list[PromptMessage]) -> str:
        return json.dumps({"prompt": messages[1]["content"]})

    count = run_chat_dataset_inference(
        dataset_path=dataset,
        predictions_path=predictions,
        model_id="model",
        run_id="run",
        generate_response=generate,
        workers=2,
    )

    written = [json.loads(line) for line in predictions.read_text().splitlines()]
    assert count == 2
    assert [row["record_id"] for row in written] == ["one", "two"]
    assert all(row["metadata"]["workers"] == 2 for row in written)
    assert not predictions.with_suffix(".jsonl.tmp").exists()


def test_chat_dataset_inference_rejects_assistant_gold(tmp_path: Path) -> None:
    dataset = tmp_path / "challenge.jsonl"
    row = _challenge_row("one")
    row["messages"].append({"role": "assistant", "content": '{"gold": true}'})
    dataset.write_text(json.dumps(row) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="system/user"):
        run_chat_dataset_inference(
            dataset_path=dataset,
            predictions_path=tmp_path / "predictions.jsonl",
            model_id="model",
            run_id="run",
            generate_response=lambda _messages: "{}",
        )


def test_source_report_writers_include_latency_and_identity(tmp_path: Path) -> None:
    record = {
        "id": "positive",
        "code": {"text": "int f() { return 1; }"},
        "metadata": {"label": "present"},
    }
    prediction = Prediction(
        record_id="positive",
        model_id="model",
        run_id="run",
        raw_output="{}",
        latency_ms=12.5,
    )

    result = evaluate_source_predictions(
        [record],
        [prediction],
        thresholds=SourceThresholds(minimum_sample_count=1),
    )
    summary = tmp_path / "summary.json"
    report = tmp_path / "report.html"
    write_source_summary(result, summary)
    write_source_report(result, report)

    written = json.loads(summary.read_text())
    assert written["model_id"] == "model"
    assert written["run_id"] == "run"
    assert written["metrics"]["latency_p50_ms"] == 12.5
    assert "AegisLM Source Absolute Evaluation" in report.read_text()


def test_smoke_subset_is_balanced_and_does_not_copy_gold_to_challenge(
    tmp_path: Path,
) -> None:
    challenge = tmp_path / "challenge.jsonl"
    gold = tmp_path / "gold.jsonl"
    challenge_output = tmp_path / "smoke" / "challenge.jsonl"
    gold_output = tmp_path / "smoke" / "gold.jsonl"
    challenge_rows = [_challenge_row(f"record-{index}") for index in range(8)]
    gold_rows = [
        {
            "id": f"record-{index}",
            "expected_output": {
                "assessment": "present" if index < 4 else "not_observed"
            },
        }
        for index in range(8)
    ]
    challenge.write_text(
        "".join(json.dumps(row) + "\n" for row in challenge_rows),
        encoding="utf-8",
    )
    gold.write_text(
        "".join(json.dumps(row) + "\n" for row in gold_rows),
        encoding="utf-8",
    )

    subprocess.run(
        [
            sys.executable,
            "scripts/build_source_smoke_subset.py",
            "--challenge",
            str(challenge),
            "--gold",
            str(gold),
            "--challenge-output",
            str(challenge_output),
            "--gold-output",
            str(gold_output),
            "--per-class",
            "2",
        ],
        check=True,
    )

    selected_challenge = [
        json.loads(line) for line in challenge_output.read_text().splitlines()
    ]
    selected_gold = [json.loads(line) for line in gold_output.read_text().splitlines()]
    assert len(selected_challenge) == len(selected_gold) == 4
    assert {row["id"] for row in selected_challenge} == {
        row["id"] for row in selected_gold
    }
    assert all(set(row) == {"id", "messages"} for row in selected_challenge)
    assert {row["expected_output"]["assessment"] for row in selected_gold} == {
        "present",
        "not_observed",
    }


def test_diagnostic_thresholds_match_q1_gate() -> None:
    thresholds = SourceThresholds.diagnostic()

    assert thresholds.minimum_sample_count == 20
    assert thresholds.minimum_precision == 0.75
    assert thresholds.minimum_recall == 0.75
    assert thresholds.maximum_false_positive_rate == 0.20
    assert thresholds.maximum_abstention_rate == 0.10
    assert thresholds.maximum_repetition_rate == 0.01
    assert thresholds.maximum_abnormal_length_rate == 0.01
