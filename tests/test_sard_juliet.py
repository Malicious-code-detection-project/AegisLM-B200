from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any

from aegislm.datasets.sard_juliet import (
    _build_function,
    _clean_annotation,
    _cwe_evidence_errors,
    _following_operation_spans,
    _required_cwe_spans,
    extract_juliet_functions,
    materialize_juliet_profile,
    summarize_juliet_manual_review,
)
from scripts.render_sard_manual_review import _render
from scripts.apply_sard_manual_review_decisions import _apply_decisions


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
    int dataGoodLimit = 2147483647;
    /* FIX: check the bound before adding */
    if (data < dataGoodLimit)
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
    assert all(
        "good" not in json.dumps(item.assessment_basis).lower()
        and "bad" not in json.dumps(item.assessment_basis).lower()
        for item in functions
    )
    positive = next(item for item in functions if item.label == "present")
    assert "data = data + 1;" in positive.findings[0]["code_spans"]
    assert all(span in positive.code for span in positive.findings[0]["code_spans"])
    assert positive.assessment_basis
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


def test_manual_review_can_fail_early_after_error_budget_is_exhausted() -> None:
    rows = [
        {
            "id": f"row-{index}",
            "operator_label_error": False if index < 6 else None,
            "operator_evidence_error": True if index < 6 else None,
        }
        for index in range(100)
    ]

    result = summarize_juliet_manual_review(rows)

    assert result["status"] == "fail_early"
    assert result["pass"] is False
    assert result["reviewed_count"] == 6
    assert result["unfinished_count"] == 94
    assert result["error_count"] == 6


def test_manual_review_renderer_exposes_code_basis_and_decision_fields() -> None:
    markdown = _render(
        [
            {
                "id": "review-1",
                "target_cwe": "CWE-122",
                "private_label": "present",
                "code": "memcpy(dst, src, 100);",
                "expected_output": {
                    "assessment_basis": [{"code_spans": ["memcpy(dst, src, 100);"]}],
                    "findings": [],
                },
                "review_status": None,
                "operator_label_error": None,
                "operator_evidence_error": None,
                "reviewer": "Codex",
                "review_method": "grouped causal-pattern review",
                "checks": {"code_spans_are_exact": True},
                "notes": "",
            }
        ]
    )

    assert "# SARD Source Manual Review" in markdown
    assert "CWE-122" in markdown
    assert "memcpy(dst, src, 100);" in markdown
    assert "Assessment basis" in markdown
    assert "Reviewer: `Codex`" in markdown
    assert "`code_spans_are_exact`: `True`" in markdown


def test_buffer_evidence_includes_destination_capacity_and_pointer_link() -> None:
    code = """void sample_function()
{
    int * data;
    int candidate_symbol_1[50];
    int source[100] = {0};
    data = candidate_symbol_1;
    for (size_t i = 0; i < 100; i++)
    {
        data[i] = source[i];
    }
}"""

    spans = _required_cwe_spans(
        "CWE-121",
        "present",
        code,
        ["for (size_t i = 0; i < 100; i++)", "data[i] = source[i];"],
    )

    assert "int candidate_symbol_1[50];" in spans
    assert "data = candidate_symbol_1;" in spans
    assert "int source[100] = {0};" in spans
    assert "data[i] = source[i];" in spans
    assert _cwe_evidence_errors("CWE-121", "present", spans) == []


def test_loop_bound_evidence_requires_input_and_loop() -> None:
    complete = [
        "recvResult = recv(socket, data, 99, 0);",
        'sscanf(inputBuffer, "%d", &n);',
        "for (intVariable = 0; intVariable < n; intVariable++)",
    ]

    assert _cwe_evidence_errors("CWE-606", "present", complete) == []
    assert _cwe_evidence_errors("CWE-606", "present", complete[1:]) == [
        "input_source_missing"
    ]
    assert _cwe_evidence_errors("CWE-606", "present", complete[:1]) == [
        "loop_bound_bridge_missing",
        "loop_missing",
    ]


def test_pointer_deallocation_evidence_requires_change_and_free() -> None:
    complete = ["data++;", "free(data);"]

    assert _cwe_evidence_errors("CWE-761", "present", complete) == []
    assert _cwe_evidence_errors("CWE-761", "present", ["free(data);"]) == [
        "pointer_change_missing"
    ]


def test_uninitialized_fix_evidence_does_not_treat_comparison_as_assignment() -> None:
    code = """static void sample_function()
{
    int * data;
    data = (int *)malloc(10*sizeof(int));
    if (data == NULL) {exit(-1);}
    for(i=0; i<10; i++)
    {
        data[i] = i;
    }
    for(i=0; i<10; i++)
    {
        printIntLine(data[i]);
    }
}"""

    spans = _required_cwe_spans("CWE-457", "not_observed", code, [])

    assert "if (data == NULL) {exit(-1);}" not in spans
    assert "data[i] = i;" in spans
    assert _cwe_evidence_errors("CWE-457", "not_observed", spans) == []


def test_read_annotation_tracks_io_and_conversion_instead_of_socket_setup() -> None:
    remainder = """
    SOCKET connectSocket = INVALID_SOCKET;
    connectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    recvResult = recv(connectSocket, inputBuffer, 99, 0);
    data = atoi(inputBuffer);
    """

    spans = _following_operation_spans(
        remainder,
        {},
        description="Read data using a connect socket.",
    )

    assert "recvResult = recv(connectSocket, inputBuffer, 99, 0);" in spans
    assert "data = atoi(inputBuffer);" in spans


def test_absence_only_fix_annotation_is_not_training_supervision() -> None:
    code = """
    static void example_good()
    {
        char * data = new char;
        /* POTENTIAL FLAW: delete data in the source */
        delete data;
        /* FIX: Do NOT attempt to delete the memory */
        ;
    }
    """

    result = _build_function(
        "archive.cpp",
        "group",
        "hash",
        "CWE-415",
        "not_observed",
        "example_good",
        code,
    )

    assert result is None


def test_external_only_executable_path_is_not_grounded() -> None:
    spans = [
        'wchar_t dataBuffer[100] = L"";',
        "wcscpy(data, candidate_symbol_1);",
        "SYSTEM(data);",
    ]

    assert _cwe_evidence_errors("CWE-426", "present", spans) == [
        "executable_path_literal_missing"
    ]


def test_heap_to_delete_link_is_required_for_cwe_590() -> None:
    complete = [
        "twoIntsStruct * dataBuffer = new twoIntsStruct;",
        "data = dataBuffer;",
        "delete data;",
    ]

    assert _cwe_evidence_errors("CWE-590", "not_observed", complete) == []
    assert _cwe_evidence_errors(
        "CWE-590",
        "not_observed",
        ["twoIntsStruct * dataBuffer = new twoIntsStruct;", "delete data;"],
    ) == ["heap_pointer_link_missing"]


def test_unchecked_allocation_requires_a_pointer_use() -> None:
    complete = [
        "data = (wchar_t *)calloc(20, sizeof(wchar_t));",
        'wcscpy(data, L"Initialize");',
    ]

    assert _cwe_evidence_errors("CWE-690", "present", complete) == []
    assert _cwe_evidence_errors("CWE-690", "present", complete[:1]) == [
        "unchecked_pointer_use_missing"
    ]


def test_runtime_crypto_key_requires_input_and_hash_use() -> None:
    complete = [
        "fgetws(cryptoKey, 100, stdin);",
        "CryptHashData(hHash, (BYTE *) cryptoKey, keyLen, 0);",
    ]

    assert _cwe_evidence_errors("CWE-321", "not_observed", complete) == []
    assert _cwe_evidence_errors("CWE-321", "not_observed", complete[:1]) == [
        "key_derivation_input_missing"
    ]


def test_juliet_good_bad_terms_are_removed_from_supervision() -> None:
    cleaned = _clean_annotation(
        "BadSource reaches the bad sink while GoodSink avoids it"
    )

    assert cleaned == (
        "risk setup reaches the risk operation while defensive operation avoids it."
    )


def test_manual_review_decisions_require_the_complete_rubric() -> None:
    rows = [{"id": "review-1", "operator_label_error": None}]
    decision = {
        "id": "review-1",
        "review_status": "pass",
        "operator_label_error": False,
        "operator_evidence_error": False,
        "checks": {
            "label_matches_target_cwe": True,
            "vulnerable_or_fixed_path_is_feasible": True,
            "code_spans_are_exact": True,
            "causal_relationship_is_complete": True,
            "cwe_explanation_is_specific": True,
            "irrelevant_spans_are_absent": True,
        },
        "notes": "Reviewed against the fixed rubric.",
        "reviewer": "Codex",
        "review_method": "grouped causal-pattern review",
    }

    updated = _apply_decisions(rows, [decision])

    assert updated[0]["review_status"] == "pass"
    assert updated[0]["reviewer"] == "Codex"
