from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

from aegislm.datasets.source import (
    build_source_target,
    derive_patch_findings,
    format_source_prompt,
    source_prompt_variant_id,
    validate_source_output,
    validate_source_record,
)
from aegislm.datasets.source_audit import (
    audit_source_targets,
    count_source_training_tokens,
)
from aegislm.evaluation.harness import Prediction
from aegislm.evaluation.source import SourceThresholds, evaluate_source_predictions


class _Tokenizer:
    def __init__(self, token_count: int = 128) -> None:
        self.name_or_path = "mock-qwen-tokenizer"
        self.token_count = token_count
        self.messages: list[dict[str, str]] = []
        self.enable_thinking: bool | None = None

    def apply_chat_template(
        self,
        messages: list[dict[str, str]],
        *,
        tokenize: bool,
        add_generation_prompt: bool,
        enable_thinking: bool,
    ) -> list[int]:
        assert tokenize is True
        assert add_generation_prompt is False
        self.messages = messages
        self.enable_thinking = enable_thinking
        return list(range(self.token_count))


class _BatchTokenizer:
    def __init__(self, token_count: int = 128) -> None:
        self.name_or_path = "mock-qwen-batch-tokenizer"
        self.token_count = token_count
        self.messages: list[dict[str, str]] = []
        self.enable_thinking: bool | None = None

    def apply_chat_template(
        self,
        messages: list[dict[str, str]],
        *,
        tokenize: bool,
        add_generation_prompt: bool,
        enable_thinking: bool,
    ) -> dict[str, list[int]]:
        self.messages = messages
        self.enable_thinking = enable_thinking
        return {
            "input_ids": list(range(self.token_count)),
            "attention_mask": [1] * self.token_count,
        }


def _record(
    *,
    label: str = "present",
    evidence_level: str = "code_span_grounded",
    record_id: str = "source-1",
) -> dict[str, Any]:
    code = "int read_at(char *p, int i) { return p[i]; }"
    return {
        "schema_version": "aegislm.source-vulnerability-record.v1",
        "id": record_id,
        "code": {
            "text": code,
            "sha256": hashlib.sha256(code.encode()).hexdigest(),
        },
        "task": {"target_cwe": "CWE-125"},
        "metadata": {
            "split": "test",
            "source_dataset": "private-test-dataset",
            "label": label,
            "evidence_level": evidence_level,
            "contains_executable_payload": False,
        },
    }


def _finding() -> dict[str, str]:
    return {
        "code_span": "return p[i];",
        "operation": "array indexing",
        "evidence": "The index is used to read from p within the supplied function.",
        "confidence": "high",
    }


def _target(record: dict[str, Any]) -> dict[str, Any]:
    result = build_source_target(record, findings=[_finding()])
    assert result.target is not None
    return result.target


def test_source_record_output_and_exact_span_validation() -> None:
    record = _record()
    target = _target(record)

    assert validate_source_record(record) == []
    assert validate_source_output(target, source_code=record["code"]["text"]) == []

    missing = copy.deepcopy(target)
    missing["findings"] = []
    assert any("non-empty" in error for error in validate_source_output(missing))

    invented = copy.deepcopy(target)
    invented["findings"][0]["code_span"] = "strcpy(dst, src);"
    assert any(
        "exact source substring" in error
        for error in validate_source_output(
            invented,
            source_code=record["code"]["text"],
        )
    )


def test_source_prompt_excludes_private_control_metadata() -> None:
    record = _record(record_id="private-record-id")
    prompt = format_source_prompt(record)
    text = "\n".join(message["content"] for message in prompt)

    assert "CWE-125" in text
    assert record["code"]["text"] in text
    assert "private-test-dataset" not in text
    assert "private-record-id" not in text
    assert '"label"' not in text
    assert '"split"' not in text


def test_not_observed_rejects_global_safety_claim() -> None:
    record = _record(label="not_observed")
    target = build_source_target(record).target
    assert target is not None
    target["limitations"] = ["This program is safe."]

    assert "not_observed output makes a global safety claim" in validate_source_output(
        target,
        source_code=record["code"]["text"],
    )


def test_target_builder_excludes_ungrounded_and_uncertain_records() -> None:
    ungrounded = _record(evidence_level="cwe_scoped")
    uncertain = _record(label="uncertain")

    first = build_source_target(ungrounded, findings=[_finding()])
    second = build_source_target(uncertain, findings=[_finding()])

    assert first.eligible is False
    assert first.reason == "evidence_level_not_grounded"
    assert second.eligible is False
    assert second.reason == "uncertain_not_supervised"


def test_verified_patch_pair_derives_exact_before_spans() -> None:
    before = "int f(char *p, int i) {\n    return p[i];\n}"
    after = "int f(char *p, int i) {\n    return p && i == 0 ? p[0] : 0;\n}"

    findings = derive_patch_findings(before, after)

    assert findings
    assert all(finding["code_span"] in before for finding in findings)
    assert all(finding["confidence"] == "high" for finding in findings)


def test_prompt_variant_is_deterministic_and_label_independent() -> None:
    positive = _record(label="present")
    negative = _record(label="not_observed")

    assert source_prompt_variant_id(positive) == source_prompt_variant_id(negative)
    assert format_source_prompt(positive) == format_source_prompt(negative)


def test_token_counter_uses_full_chat_template_without_thinking() -> None:
    tokenizer = _Tokenizer(token_count=321)
    record = _record()

    count = count_source_training_tokens(
        tokenizer,
        format_source_prompt(record),
        _target(record),
    )

    assert count == 321
    assert tokenizer.enable_thinking is False
    assert tokenizer.messages[-1]["role"] == "assistant"


def test_token_counter_reads_batch_encoding_input_ids() -> None:
    tokenizer = _BatchTokenizer(token_count=777)
    record = _record()

    count = count_source_training_tokens(
        tokenizer,
        format_source_prompt(record),
        _target(record),
    )

    assert count == 777


def test_source_evaluator_computes_absolute_metrics() -> None:
    positive = _record(record_id="positive")
    negative = _record(label="not_observed", record_id="negative")
    predictions = [
        Prediction(
            record_id="positive",
            model_id="model",
            run_id="run",
            raw_output=json.dumps(_target(positive)),
        ),
        Prediction(
            record_id="negative",
            model_id="model",
            run_id="run",
            raw_output=json.dumps(build_source_target(negative).target),
        ),
    ]

    result = evaluate_source_predictions(
        [positive, negative],
        predictions,
        thresholds=SourceThresholds(minimum_sample_count=2),
    )

    assert result["overall_pass"] is True
    assert result["metrics"]["precision"] == 1.0
    assert result["metrics"]["recall"] == 1.0
    assert result["metrics"]["false_positive_rate"] == 0.0
    assert result["metrics"]["schema_pass_rate"] == 1.0
    assert result["metrics"]["evidence_rate"] == 1.0


def test_r2_audit_stops_when_evidence_supply_is_missing() -> None:
    code = "int f(char *p) { return p[1]; }"
    materialized = {
        "id": "phase-f-source-test",
        "input": {
            "task": "Assess CWE-125.",
            "context": f"Source-code excerpt:\n{code}",
            "signals": {"scoped_cwe": ["CWE-125"]},
        },
    }
    manifest = {
        "record_id": "phase-f-source-test",
        "materialization": "train",
        "split": "train",
        "source_dataset": "DiverseVul",
        "label_value": "present",
        "evidence_level": "cwe_scoped",
        "cwe": "CWE-125",
    }

    result = audit_source_targets(
        [materialized],
        [manifest],
        tokenizer=_Tokenizer(),
    )

    assert result["status"] == "evidence_supply_blocked"
    assert result["overall_pass"] is False
    assert result["metrics"]["eligible_count"] == 0
    assert result["metrics"]["prompt_leakage_count"] == 0
    assert result["metrics"]["tokenizer_loaded"] is True
    assert result["metrics"]["exclusion_counts"] == {"evidence_level_not_grounded": 1}


def test_audit_excludes_sequences_over_real_tokenizer_cutoff() -> None:
    code = "int f(char *p) { return p[1]; }"
    materialized = {
        "id": "phase-f-source-pair",
        "input": {
            "task": "Assess CWE-125.",
            "context": f"Source-code excerpt:\n{code}",
            "signals": {"scoped_cwe": ["CWE-125"]},
        },
    }
    manifest = {
        "record_id": "phase-f-source-pair",
        "materialization": "cross_dataset_test",
        "split": "test",
        "source_dataset": "PairDataset",
        "label_value": "present",
        "evidence_level": "patch_localized",
        "cwe": "CWE-125",
    }
    finding = {
        "code_span": "return p[1];",
        "operation": "array indexing",
        "evidence": "The paired fixed function changes this exact operation.",
        "confidence": "high",
    }

    result = audit_source_targets(
        [materialized],
        [manifest],
        tokenizer=_Tokenizer(token_count=2049),
        cutoff_len=2048,
        grounded_findings_by_id={"phase-f-source-pair": [finding]},
        required_counts={},
    )

    assert result["metrics"]["eligible_count"] == 0
    assert result["metrics"]["tokenizer_cutoff_excluded_count"] == 1
    assert result["metrics"]["maximum_observed_token_count"] == 2049
