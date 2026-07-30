from __future__ import annotations

import json

from aegislm.datasets.source_decision import (
    SOURCE_DECISION_SYSTEM_PROMPT,
    build_decision_development_subset,
    to_decision_challenge_record,
    to_decision_training_record,
)
from aegislm.evaluation.harness import Prediction
from aegislm.evaluation.source_decision import evaluate_source_decisions


def _source_row(assessment: str = "present") -> dict:
    return {
        "id": "case-1",
        "messages": [
            {"role": "system", "content": "full report contract"},
            {"role": "user", "content": "scope and supplied code"},
            {
                "role": "assistant",
                "content": json.dumps(
                    {
                        "assessment": assessment,
                        "findings": [{"code_spans": ["x"]}],
                    }
                ),
            },
        ],
    }


def test_decision_training_record_has_one_field_target() -> None:
    result = to_decision_training_record(_source_row())

    assert result["messages"][0]["content"] == SOURCE_DECISION_SYSTEM_PROMPT
    assert json.loads(result["messages"][2]["content"]) == {"assessment": "present"}
    assert "findings" not in result["messages"][2]["content"]


def test_decision_challenge_does_not_include_assistant_or_gold() -> None:
    row = _source_row()
    result = to_decision_challenge_record(
        {"id": row["id"], "messages": row["messages"][:2]}
    )

    assert [message["role"] for message in result["messages"]] == [
        "system",
        "user",
    ]
    assert "expected_output" not in result
    assert all(message["role"] != "assistant" for message in result["messages"])


def test_decision_development_subset_is_balanced_and_answer_free() -> None:
    rows = []
    for index in range(4):
        for assessment in ("present", "not_observed"):
            row = _source_row(assessment)
            row["id"] = f"{assessment}-{index}"
            rows.append(row)

    first = build_decision_development_subset(rows, per_class=2, seed=17)
    second = build_decision_development_subset(
        list(reversed(rows)),
        per_class=2,
        seed=17,
    )

    assert first == second
    challenge, gold = first
    assert len(challenge) == len(gold) == 4
    assert {row["id"] for row in challenge} == {row["id"] for row in gold}
    assert all(
        [message["role"] for message in row["messages"]] == ["system", "user"]
        for row in challenge
    )
    assert {row["expected_output"]["assessment"] for row in gold} == {
        "present",
        "not_observed",
    }


def test_decision_evaluator_accepts_exact_minimal_contract() -> None:
    result = evaluate_source_decisions(
        [
            {"id": "positive", "expected_output": {"assessment": "present"}},
            {
                "id": "negative",
                "expected_output": {"assessment": "not_observed"},
            },
        ],
        [
            Prediction("positive", "model", "run", '{"assessment":"present"}'),
            Prediction(
                "negative",
                "model",
                "run",
                '{"assessment":"not_observed"}',
            ),
        ],
        blind_test_used=True,
    )

    assert result["metrics"]["precision"] == 1.0
    assert result["metrics"]["recall"] == 1.0
    assert result["metrics"]["schema_pass_rate"] == 1.0
    assert result["diagnostic_only"] is False
    assert result["blind_test_used"] is True


def test_decision_evaluator_rejects_report_fields() -> None:
    result = evaluate_source_decisions(
        [{"id": "positive", "expected_output": {"assessment": "present"}}],
        [
            Prediction(
                "positive",
                "model",
                "run",
                '{"assessment":"present","findings":[]}',
            )
        ],
    )

    assert result["metrics"]["parse_success_rate"] == 1.0
    assert result["metrics"]["schema_pass_rate"] == 0.0
    assert result["metrics"]["abstention_rate"] == 1.0
