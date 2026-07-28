import hashlib
import json
from typing import Any

import pytest

from aegislm.evaluation import (
    build_blind_code_challenge,
    collect_training_fingerprints,
)
from aegislm.prompts import format_baseline_prompt


def _record(index: int, target: int, code: str) -> dict[str, Any]:
    fingerprint = hashlib.sha256(code.encode()).hexdigest()
    label = "vulnerable" if target else "not labeled vulnerable"
    return {
        "id": f"diversevul-{index}",
        "source": {
            "type": "public_security_dataset",
            "name": "bstee615/diversevul",
        },
        "input": {
            "task": "explain vulnerability label",
            "context": (
                f"DiverseVul function excerpt. Dataset label: {label}.\n\n"
                f"Code excerpt:\n{code}"
            ),
            "signals": {
                "dataset": "DiverseVul",
                "target": target,
                "label": label,
                "code_excerpt_sha256": fingerprint,
            },
        },
        "expected_output": {"risk_level": "high" if target else "low"},
        "metadata": {"split": "test"},
    }


def test_challenge_is_balanced_deterministic_and_label_blind() -> None:
    records = [
        _record(1, 0, "int safe_one(void) { return 1; }"),
        _record(2, 0, "int safe_two(void) { return 2; }"),
        _record(3, 1, "void risky_one(char *x) { strcpy(buf, x); }"),
        _record(4, 1, "void risky_two(char *x) { gets(x); }"),
    ]

    prompts, gold, summary = build_blind_code_challenge(records, per_class=2, seed=7)
    second_prompts, second_gold, _ = build_blind_code_challenge(
        records, per_class=2, seed=7
    )

    assert prompts == second_prompts
    assert gold == second_gold
    assert summary["selected_benign"] == 2
    assert summary["selected_vulnerable"] == 2
    assert sum(1 for item in gold if item["is_vulnerable"]) == 2

    for prompt in prompts:
        assert prompt["id"].startswith("aegislm-code-")
        assert "expected_output" not in prompt
        assert prompt["input"]["signals"] == {}
        assert prompt["source"]["name"] == "AegisLM blind code challenge"
        rendered = json.dumps(
            format_baseline_prompt(prompt), ensure_ascii=False
        ).lower()
        assert "dataset label" not in rendered
        assert '"target"' not in rendered
        assert "bstee615" not in rendered
        assert "diversevul" not in rendered


def test_training_fingerprint_overlap_is_excluded() -> None:
    overlapping = _record(1, 0, "int same(void) { return 0; }")
    records = [
        overlapping,
        _record(2, 0, "int other(void) { return 0; }"),
        _record(3, 1, "void risky(void) { gets(buf); }"),
    ]
    fingerprints = collect_training_fingerprints([overlapping])

    prompts, gold, summary = build_blind_code_challenge(
        records,
        per_class=1,
        seed=1,
        training_fingerprints=fingerprints,
    )

    assert summary["excluded_training_overlap"] == 1
    assert len(prompts) == len(gold) == 2
    assert all(item["record_id"] != overlapping["id"] for item in gold)


def test_challenge_requires_enough_records_in_each_class() -> None:
    with pytest.raises(ValueError, match="not enough balanced"):
        build_blind_code_challenge(
            [_record(1, 1, "void risky(void) { gets(buf); }")],
            per_class=1,
            seed=1,
        )
