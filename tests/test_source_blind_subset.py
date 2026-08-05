from __future__ import annotations

import hashlib

import pytest

from aegislm.datasets.source import SourceContractError, build_source_target
from aegislm.datasets.source_blind_subset import (
    build_fresh_blind_contracts,
    build_untouched_blind_subset,
)


def _challenge(record_id: str) -> dict[str, object]:
    return {"id": record_id, "messages": [], "expected_output": None}


def _gold(record_id: str, assessment: str) -> dict[str, object]:
    return {
        "id": record_id,
        "expected_output": {"assessment": assessment},
    }


def test_build_untouched_blind_subset_excludes_only_exposed_ids() -> None:
    challenges = [_challenge("a"), _challenge("b"), _challenge("c")]
    gold = [
        _gold("a", "present"),
        _gold("b", "not_observed"),
        _gold("c", "present"),
    ]
    records = [{"id": "a"}, {"id": "b"}, {"id": "c"}, {"id": "extra"}]

    result = build_untouched_blind_subset(
        challenges,
        gold,
        records,
        [
            {"record_id": "b", "raw_output": "{}"},
            {"record_id": "b", "raw_output": "{}"},
        ],
        expected_count=2,
    )

    assert [row["id"] for row in result.challenge] == ["a", "c"]
    assert [row["id"] for row in result.gold] == ["a", "c"]
    assert [row["id"] for row in result.private_records] == ["a", "c"]
    assert result.manifest["source_count"] == 3
    assert result.manifest["exposed_count"] == 1
    assert result.manifest["untouched_count"] == 2
    assert result.manifest["labels"] == {"present": 2}
    assert result.manifest["model_visible_gold_count"] == 0


def test_build_untouched_blind_subset_rejects_unknown_exposure() -> None:
    with pytest.raises(SourceContractError, match="unknown ids"):
        build_untouched_blind_subset(
            [_challenge("a")],
            [_gold("a", "present")],
            [{"id": "a"}],
            [{"record_id": "other"}],
        )


def test_build_untouched_blind_subset_rejects_visible_gold_and_count_drift() -> None:
    visible = _challenge("a")
    visible["expected_output"] = {"assessment": "present"}
    with pytest.raises(SourceContractError, match="model-visible gold"):
        build_untouched_blind_subset(
            [visible],
            [_gold("a", "present")],
            [{"id": "a"}],
            [],
        )

    with pytest.raises(SourceContractError, match="untouched count"):
        build_untouched_blind_subset(
            [_challenge("a")],
            [_gold("a", "present")],
            [{"id": "a"}],
            [],
            expected_count=2,
        )


def test_build_fresh_blind_contracts_projects_decision_and_evidence() -> None:
    code = "void f() {\n    sink();\n}"
    record = {
        "schema_version": "aegislm.source-vulnerability-record.v1",
        "id": "case-present",
        "code": {
            "text": code,
            "sha256": hashlib.sha256(code.encode()).hexdigest(),
        },
        "task": {"target_cwe": "CWE-120"},
        "metadata": {
            "split": "test",
            "source_dataset": "fixture",
            "label": "present",
            "evidence_level": "code_span_grounded",
            "contains_executable_payload": False,
        },
    }
    target = build_source_target(
        record,
        findings=[
            {
                "code_span": "sink();",
                "operation": "fixture operation",
                "evidence": "The supplied call is the scoped fixture evidence.",
                "confidence": "high",
            }
        ],
    ).target
    assert target is not None
    challenge = [
        {
            "id": "case-present",
            "messages": [
                {"role": "system", "content": "source"},
                {"role": "user", "content": code},
            ],
        }
    ]
    report_gold = [
        {
            "id": "case-present",
            "expected_output": target,
        }
    ]

    result = build_fresh_blind_contracts(challenge, report_gold, [record])

    assert result.decision_gold == [
        {
            "id": "case-present",
            "expected_output": {"assessment": "present"},
        }
    ]
    assert result.decision_challenge[0]["id"] == "case-present"
    assert len(result.decision_challenge[0]["messages"]) == 2
    assert result.evidence_gold[0]["id"] == "case-present"
    assert result.evidence_gold[0]["expected_output"]["evidence_ranges"] == [
        {"start_line": 2, "end_line": 2}
    ]
    assert result.manifest["status"] == "frozen_blind"
    assert result.manifest["model_visible_gold_count"] == 0
