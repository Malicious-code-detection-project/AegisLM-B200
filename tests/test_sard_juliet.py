from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any

from aegislm.datasets.sard_juliet import (
    extract_juliet_functions,
    materialize_juliet_profile,
    summarize_juliet_manual_review,
)


class _Tokenizer:
    def __init__(self, length: int = 200) -> None:
        self.length = length

    def apply_chat_template(self, _messages: Any, **_kwargs: Any) -> list[int]:
        return list(range(self.length))


def _archive(tmp_path: Path, count: int = 3) -> Path:
    archive = tmp_path / "juliet.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        for index in range(count):
            bundle.writestr(
                (
                    "C/testcases/CWE190_Integer_Overflow/s01/"
                    f"CWE190_Integer_Overflow__int_add_{index + 1:02d}.c"
                ),
                f"""
void CWE190_Integer_Overflow__int_add_{index + 1:02d}_bad()
{{
    int data = 2147483647 - {index};
    /* POTENTIAL FLAW: adding one may overflow */
    data = data + 1;
    printIntLine(data);
}}

static void goodB2G1()
{{
    int data = 2147483647 - {index};
    /* FIX: check the bound before adding */
    if (data < 2147483647)
    {{
        data = data + 1;
    }}
    printIntLine(data);
}}

void CWE190_Integer_Overflow__int_add_{index + 1:02d}_good()
{{
    goodB2G1();
}}
""",
            )
        bundle.writestr(
            "C/testcases/CWE190_Integer_Overflow/s01/"
            "CWE190_Integer_Overflow__int_add_11.c",
            "void ignored_bad() { /* POTENTIAL FLAW: x */ x++; }",
        )
    return archive


def test_extracts_balanced_functions_and_removes_label_leakage(tmp_path: Path) -> None:
    functions, catalog = extract_juliet_functions(_archive(tmp_path))

    assert len(functions) == 6
    assert sum(item.label == "present" for item in functions) == 3
    assert sum(item.label == "not_observed" for item in functions) == 3
    assert all("sample_function" in item.code for item in functions)
    assert all("CWE190" not in item.code for item in functions)
    assert all("good" not in item.code.lower() for item in functions)
    assert all("bad" not in item.code.lower() for item in functions)
    positive = next(item for item in functions if item.label == "present")
    assert positive.findings[0]["code_span"] == "data = data + 1;"
    assert positive.findings[0]["code_span"] in positive.code
    assert len(catalog) == 3
    assert all(row["contains_executable_payload"] is False for row in catalog)


def test_materialization_is_group_first_deterministic_and_gold_is_private(
    tmp_path: Path,
) -> None:
    functions, _ = extract_juliet_functions(_archive(tmp_path))

    first = materialize_juliet_profile(
        functions,
        tokenizer=_Tokenizer(),
        train_pairs=1,
        validation_pairs=1,
        test_pairs=1,
    )
    second = materialize_juliet_profile(
        functions,
        tokenizer=_Tokenizer(),
        train_pairs=1,
        validation_pairs=1,
        test_pairs=1,
    )

    assert first["status"] == "manual_review_required"
    assert first["model_visible_label_leakage_count"] == 0
    assert first["exact_code_duplicate_rate"] == 0
    assert first["eligible_counts"] == second["eligible_counts"]
    assert first["manifest"] == second["manifest"]
    assert len({row["group_id"] for row in first["manifest"]}) == 3
    for row in first["records"]["test"]:
        prompt = json.dumps(row["messages"][:2])
        assert "NIST SARD" not in prompt
        assert '"label"' not in prompt
        assert '"split"' not in prompt


def test_token_cutoff_rejects_the_entire_pair(tmp_path: Path) -> None:
    functions, _ = extract_juliet_functions(_archive(tmp_path, count=1))
    profile = materialize_juliet_profile(
        functions,
        tokenizer=_Tokenizer(length=2049),
        train_pairs=1,
        validation_pairs=0,
        test_pairs=0,
    )

    assert profile["status"] == "evidence_supply_blocked"
    assert profile["eligible_record_count"] == 0
    assert profile["excluded_group_counts"] == {"tokenizer_cutoff_exceeded": 1}


def test_manual_review_requires_all_decisions_and_enforces_error_gate() -> None:
    rows = [
        {
            "id": f"row-{index}",
            "operator_label_error": index < 3,
            "operator_evidence_error": False,
        }
        for index in range(100)
    ]

    result = summarize_juliet_manual_review(rows)

    assert result["pass"] is True
    assert result["error_count"] == 3
    rows[99]["operator_evidence_error"] = None
    try:
        summarize_juliet_manual_review(rows)
    except ValueError as exc:
        assert "unfinished boolean decisions" in str(exc)
    else:
        raise AssertionError("unfinished manual review must fail")
