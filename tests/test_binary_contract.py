from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from aegislm.datasets.binary import (
    BinaryRecordValidationError,
    binary_target_relation_visible,
    build_binary_pair_role_targets,
    build_binary_pair_strict_role_targets,
    build_binary_pair_strict_v4_role_targets,
    build_binary_pair_strict_v5_role_targets,
    build_binary_pair_strict_v6_role_targets,
    build_binary_pair_strict_v7_role_targets,
    build_binary_pair_targets,
    build_binary_target,
    compact_binary_record,
    format_binary_prompt,
    format_binary_role_prompt,
    validate_binary_record,
    validate_binary_output_for_record,
    validate_binary_role_output_for_record,
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
                        "observation": (
                            "The supplied pseudo-C contains `copy(dst, src);`."
                        ),
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


def test_binary_role_prompt_requests_v2_contract_without_provenance() -> None:
    record = _record()

    messages = format_binary_role_prompt(record)
    prompt = json.dumps(messages)

    assert "evidence_id" in prompt
    assert "from_evidence_id" in prompt
    assert "private-fixture" not in prompt
    assert '"label"' not in prompt


def test_binary_target_is_semantically_linked_to_supplied_pseudo_c() -> None:
    record = compact_binary_record(_record())
    target = build_binary_target(record)

    assert validate_binary_output_for_record(target, record) == []
    assert "copy(dst, src);" in target["findings"][0]["observation"]

    target["findings"][0]["observation"] = "A generic unsupported claim."
    assert validate_binary_output_for_record(target, record) == [
        "findings.0.observation: no exact supplied evidence fragment"
    ]


def test_binary_present_target_requires_findings() -> None:
    record = _record()
    target = json.loads(_output("present"))
    target["findings"] = []

    assert "findings: present assessment requires observable evidence" in (
        validate_binary_output_for_record(target, record)
    )


def _role_output(
    assessment: str,
    evidence: list[dict[str, str]],
    relations: list[dict[str, str]],
) -> dict:
    return {
        "scope": {
            "target_cwe": "CWE-120",
            "binary_format": "ELF",
            "architecture": "x86_64",
        },
        "assessment": assessment,
        "findings": [
            {
                "function_id": "function-1",
                "representation": "pseudo_c",
                "evidence": evidence,
                "relations": relations,
                "confidence": "high",
            }
        ],
        "limitations": ["Scoped to supplied pseudo-C."],
        "recommendations": ["Confirm with deterministic analysis."],
    }


def test_binary_role_output_requires_grounded_roles_linked_to_sink() -> None:
    record = _record()
    record["analysis"]["functions"][0]["pseudo_c"] = (
        "data = recv(fd, source, 100, 0);\ncopy(dst, data);"
    )
    output = _role_output(
        "present",
        [
            {
                "evidence_id": "source-1",
                "role": "source",
                "code_span": "data = recv(fd, source, 100, 0);",
                "explanation": "External data enters the operation.",
            },
            {
                "evidence_id": "sink-1",
                "role": "sink",
                "code_span": "copy(dst, data);",
                "explanation": "The supplied operation consumes that data.",
            },
        ],
        [
            {
                "from_evidence_id": "source-1",
                "to_evidence_id": "sink-1",
                "relationship": "flows_to",
            }
        ],
    )

    assert validate_binary_role_output_for_record(output, record) == []

    output["findings"][0]["evidence"][0]["code_span"] = "unsupported source"
    assert (
        "findings.0.evidence.0.code_span: not an exact supplied evidence span"
        in validate_binary_role_output_for_record(output, record)
    )


def test_binary_role_output_rejects_missing_or_incompatible_sink_relation() -> None:
    record = _record()
    record["analysis"]["functions"][0]["pseudo_c"] = (
        "if (data == NULL) return;\ncopy(dst, data);"
    )
    output = _role_output(
        "not_observed",
        [
            {
                "evidence_id": "guard-1",
                "role": "control",
                "code_span": "if (data == NULL) return;",
                "explanation": "The null guard prevents the unsafe use.",
            },
            {
                "evidence_id": "sink-1",
                "role": "sink",
                "code_span": "copy(dst, data);",
                "explanation": "This is the constrained use.",
            },
        ],
        [
            {
                "from_evidence_id": "guard-1",
                "to_evidence_id": "sink-1",
                "relationship": "flows_to",
            }
        ],
    )

    errors = validate_binary_role_output_for_record(output, record)

    assert (
        "findings.0.relations.0.relationship: incompatible with control role" in errors
    )
    assert "findings.0.relations: no required role is linked to a sink" in errors

    output["findings"][0]["relations"][0]["relationship"] = "constrains"
    assert validate_binary_role_output_for_record(output, record) == []


def test_binary_role_output_rejects_unknown_relation_reference() -> None:
    record = _record()
    output = _role_output(
        "present",
        [
            {
                "evidence_id": "source-1",
                "role": "source",
                "code_span": "copy(dst, src);",
                "explanation": "Supplied source operation.",
            },
            {
                "evidence_id": "sink-1",
                "role": "sink",
                "code_span": "copy(dst, src);",
                "explanation": "Supplied sink operation.",
            },
        ],
        [
            {
                "from_evidence_id": "missing",
                "to_evidence_id": "sink-1",
                "relationship": "flows_to",
            }
        ],
    )

    assert "findings.0.relations.0.from_evidence_id: unknown" in (
        validate_binary_role_output_for_record(output, record)
    )


def _binary_pair(
    target_cwe: str,
    present_pseudo_c: str,
    fixed_pseudo_c: str,
) -> tuple[dict, dict]:
    present = _record(label="present")
    fixed = _record(
        record_id="binary-fixture-2",
        label="not_observed",
    )
    for record, pseudo_c in (
        (present, present_pseudo_c),
        (fixed, fixed_pseudo_c),
    ):
        record["task"]["target_cwe"] = target_cwe
        record["analysis"]["functions"][0]["pseudo_c"] = pseudo_c
    return present, fixed


def test_binary_role_target_preserves_destination_capacity_and_copy_sink() -> None:
    present, fixed = _binary_pair(
        "CWE-121",
        "char dst[8];\nchar src[32];\nmemcpy(dst, src, 32);",
        "char dst[32];\nchar src[8];\nmemcpy(dst, src, 8);",
    )

    present_target, fixed_target = build_binary_pair_role_targets(present, fixed)

    for record, target, capacity in (
        (present, present_target, "char dst[8];"),
        (fixed, fixed_target, "char dst[32];"),
    ):
        assert validate_binary_role_output_for_record(target, record) == []
        evidence = target["findings"][0]["evidence"]
        assert capacity in {item["code_span"] for item in evidence}
        assert "memcpy" in next(
            item["code_span"] for item in evidence if item["role"] == "sink"
        )


def test_binary_role_target_rejects_memory_copy_without_destination_capacity() -> None:
    present, fixed = _binary_pair(
        "CWE-121",
        "char dst[8];\nmemcpy(dst, src, 32);",
        "memcpy(dst, src, 8);",
    )

    with pytest.raises(
        BinaryRecordValidationError,
        match="not_observed has no role linked",
    ):
        build_binary_pair_role_targets(present, fixed)


def test_binary_role_target_preserves_negative_offset_and_sink() -> None:
    present, fixed = _binary_pair(
        "CWE-124",
        "data = -1;\nmemcpy(buffer + -1, source, 8);",
        "data = 1;\nif (data >= 0) {\nmemcpy(buffer + data, source, 8);",
    )

    present_target, fixed_target = build_binary_pair_role_targets(present, fixed)

    assert validate_binary_role_output_for_record(present_target, present) == []
    assert validate_binary_role_output_for_record(fixed_target, fixed) == []
    present_evidence = present_target["findings"][0]["evidence"]
    assert any("-1" in item["code_span"] for item in present_evidence)
    assert any(item["role"] == "sink" for item in present_evidence)


def test_binary_role_target_requires_null_guard_for_fixed_allocation_use() -> None:
    present, fixed = _binary_pair(
        "CWE-690",
        "data = malloc(32);\n*data = 1;",
        "data = malloc(32);\nif (data == NULL) return;\n*data = 1;",
    )

    present_target, fixed_target = build_binary_pair_role_targets(present, fixed)

    assert validate_binary_role_output_for_record(present_target, present) == []
    assert validate_binary_role_output_for_record(fixed_target, fixed) == []
    fixed_evidence = fixed_target["findings"][0]["evidence"]
    assert any(item["role"] == "control" for item in fixed_evidence)
    assert any("NULL" in item["code_span"] for item in fixed_evidence)

    fixed["analysis"]["functions"][0]["pseudo_c"] = "data = malloc(32);\n*data = 1;"
    with pytest.raises(
        BinaryRecordValidationError,
        match="not_observed has no role linked",
    ):
        build_binary_pair_role_targets(present, fixed)


def test_binary_role_target_requires_write_and_read_loop_bounds_for_cwe457() -> None:
    present, fixed = _binary_pair(
        "CWE-457",
        (
            "for (i = 0; i < 5; i++)\n"
            "data[i] = 0;\n"
            "for (i = 0; i < 10; i++)\n"
            "printIntLine(data[i]);"
        ),
        (
            "for (i = 0; i < 10; i++)\n"
            "data[i] = 0;\n"
            "for (j = 0; j < 10; j++)\n"
            "printIntLine(data[j]);"
        ),
    )

    present_target, fixed_target = build_binary_pair_role_targets(present, fixed)

    for record, target in ((present, present_target), (fixed, fixed_target)):
        assert validate_binary_role_output_for_record(target, record) == []
        evidence = target["findings"][0]["evidence"]
        assert sum(item["role"] == "bound" for item in evidence) == 2
        assert any(item["role"] == "sink" for item in evidence)


def test_binary_role_target_links_selected_buffer_capacity_for_cwe126() -> None:
    present, fixed = _binary_pair(
        "CWE-126",
        (
            "char dataBadBuffer[50];\nchar dest[100];\nchar *data;\n"
            "data = dataBadBuffer;\nlength = strlen(dest);\n"
            "memcpy(dest, data, length);"
        ),
        (
            "char dataGoodBuffer[100];\nchar dest[100];\nchar *data;\n"
            "data = dataGoodBuffer;\nlength = strlen(dest);\n"
            "memcpy(dest, data, length);"
        ),
    )

    present_target, fixed_target = build_binary_pair_role_targets(present, fixed)

    for target, expected in (
        (present_target, "data = dataBadBuffer;"),
        (fixed_target, "data = dataGoodBuffer;"),
    ):
        evidence = target["findings"][0]["evidence"]
        assert expected in {item["code_span"] for item in evidence}
        assert any(item["role"] == "bound" for item in evidence)
        assert not any(
            item["role"] == "source" and "strlen(dest)" in item["code_span"]
            for item in evidence
        )


def test_binary_strict_role_target_rejects_generic_cwe_fallback() -> None:
    present, fixed = _binary_pair(
        "CWE-23",
        "data = recv(fd, path, 100, 0);\nopen(data, 0);",
        'data = "file.txt";\nopen(data, 0);',
    )

    with pytest.raises(
        BinaryRecordValidationError,
        match="CWE-23 has no strict role extractor",
    ):
        build_binary_pair_strict_role_targets(present, fixed)


def test_binary_strict_role_target_accepts_complete_cwe_extractor() -> None:
    present, fixed = _binary_pair(
        "CWE-121",
        "char dst[8];\nmemmove(dst, src, 32);",
        "char dst[32];\nmemmove(dst, src, 8);",
    )

    present_target, fixed_target = build_binary_pair_strict_role_targets(
        present,
        fixed,
    )

    assert validate_binary_role_output_for_record(present_target, present) == []
    assert validate_binary_role_output_for_record(fixed_target, fixed) == []


def test_binary_strict_v4_quarantines_manual_failure_cwes() -> None:
    present, fixed = _binary_pair(
        "CWE-124",
        "data = -1;\nbuffer[data] = 1;",
        "if (data >= 0) {\nbuffer[data] = 1;",
    )

    with pytest.raises(
        BinaryRecordValidationError,
        match="CWE-124 quarantined after strict v3 manual review",
    ):
        build_binary_pair_strict_v4_role_targets(present, fixed)


def test_binary_strict_v4_retains_supported_extractors() -> None:
    present, fixed = _binary_pair(
        "CWE-134",
        "fgets(data, 100, stdin);\nprintf(data);",
        'fgets(data, 100, stdin);\nprintf("%s", data);',
    )

    present_target, fixed_target = build_binary_pair_strict_v4_role_targets(
        present,
        fixed,
    )

    assert validate_binary_role_output_for_record(present_target, present) == []
    assert validate_binary_role_output_for_record(fixed_target, fixed) == []


def test_binary_strict_v5_quarantines_cwe121() -> None:
    present, fixed = _binary_pair(
        "CWE-121",
        "char dst[8];\nmemcpy(dst, src, 32);",
        "char dst[32];\nmemcpy(dst, src, 8);",
    )

    with pytest.raises(
        BinaryRecordValidationError,
        match="CWE-121 quarantined after strict v4 manual review",
    ):
        build_binary_pair_strict_v5_role_targets(present, fixed)


def test_binary_strict_v6_quarantines_cwe122() -> None:
    present, fixed = _binary_pair(
        "CWE-122",
        "char *dst = malloc(8);\nmemcpy(dst, src, 32);",
        "char *dst = malloc(32);\nmemcpy(dst, src, 32);",
    )

    with pytest.raises(
        BinaryRecordValidationError,
        match="CWE-122 quarantined after strict v5 manual review",
    ):
        build_binary_pair_strict_v6_role_targets(present, fixed)


def test_binary_strict_v7_quarantines_cwe126() -> None:
    present, fixed = _binary_pair(
        "CWE-126",
        "char src[8];\nmemcpy(dst, src, 32);",
        "char src[32];\nmemcpy(dst, src, 32);",
    )

    with pytest.raises(
        BinaryRecordValidationError,
        match="CWE-126 quarantined after strict v6 manual review",
    ):
        build_binary_pair_strict_v7_role_targets(present, fixed)


def test_binary_role_target_links_external_format_source_and_literal_fix() -> None:
    present, fixed = _binary_pair(
        "CWE-134",
        "fgetws(dataBuffer, 100, stdin);\nfwprintf(stdout, dataBuffer);",
        'fgetws(dataBuffer, 100, stdin);\nfwprintf(stdout, L"%s", dataBuffer);',
    )

    present_target, fixed_target = build_binary_pair_role_targets(present, fixed)

    assert present_target["findings"][0]["evidence"][0]["code_span"].startswith(
        "fgetws"
    )
    assert fixed_target["findings"][0]["evidence"][0]["code_span"] == (
        'fwprintf(stdout, L"%s", dataBuffer);'
    )


@pytest.mark.parametrize(
    ("target_cwe", "operation", "guard"),
    [
        ("CWE-190", "data * data", "if (data < 1000)"),
        ("CWE-191", "data - 1", "if (data > -2147483648)"),
    ],
)
def test_binary_role_target_links_numeric_input_and_guard(
    target_cwe: str,
    operation: str,
    guard: str,
) -> None:
    present, fixed = _binary_pair(
        target_cwe,
        f'fscanf(stdin, "%d", &data);\nprintIntLine({operation});',
        f'fscanf(stdin, "%d", &data);\n{guard}\nprintIntLine({operation});',
    )

    present_target, fixed_target = build_binary_pair_role_targets(present, fixed)

    assert "fscanf" in present_target["findings"][0]["evidence"][0]["code_span"]
    assert any(
        item["role"] == "control" and item["code_span"] == guard
        for item in fixed_target["findings"][0]["evidence"]
    )


@pytest.mark.parametrize("target_cwe", ["CWE-194", "CWE-195"])
def test_binary_role_target_links_conversion_source_to_copy_length(
    target_cwe: str,
) -> None:
    present, fixed = _binary_pair(
        target_cwe,
        (
            "input = recv(fd, buffer, 8, 0);\n"
            "data = (short)input;\n"
            "memcpy(dest, source, (long)data);"
        ),
        "data = 8;\nmemcpy(dest, source, (long)data);",
    )

    present_target, fixed_target = build_binary_pair_role_targets(present, fixed)

    present_evidence = present_target["findings"][0]["evidence"]
    assert any("data = (short)input;" == item["code_span"] for item in present_evidence)
    assert any(
        item["role"] == "sink" and "memcpy" in item["code_span"]
        for item in present_evidence
    )
    assert fixed_target["assessment"] == "not_observed"


def test_binary_target_selects_variable_index_and_boundary_relation() -> None:
    record = _record()
    record["task"]["target_cwe"] = "CWE-124"
    record["analysis"]["functions"][0]["pseudo_c"] = (
        "data = -1;\nread_int(&data);\nif (data < 10) {\nbuffer[data] = 1;\n}"
    )

    target = build_binary_target(record)
    observation = target["findings"][0]["observation"]

    assert "buffer[data] = 1;" in observation
    assert "if (data < 10) {" in observation


def test_binary_target_rejects_constant_folded_numeric_output() -> None:
    record = _record()
    record["task"]["target_cwe"] = "CWE-190"
    record["analysis"]["functions"][0]["pseudo_c"] = (
        "void target_function(void) {\n"
        "printLongLongLine(0x8000000000000000);\n"
        "return;\n"
        "}"
    )

    with pytest.raises(
        BinaryRecordValidationError,
        match="no observable target relation",
    ):
        build_binary_target(record)


@pytest.mark.parametrize(
    ("target_cwe", "pseudo_c"),
    [
        ("CWE-78", 'execlp("sh", "sh", "-c", dataBuffer, 0);'),
        (
            "CWE-121",
            "wchar_t dest[50];\nwchar_t *data;\nwcscat(dest, data);",
        ),
        ("CWE-134", "swprintf(dest, 99, dataBuffer);"),
        ("CWE-401", 'data = strdup("value");\nreturn;'),
        (
            "CWE-457",
            "data = malloc(80);\nprintIntLine(*(int *)data);",
        ),
    ],
)
def test_binary_relation_validator_recognizes_decompiler_vocabulary(
    target_cwe: str,
    pseudo_c: str,
) -> None:
    assert binary_target_relation_visible(target_cwe, pseudo_c)


def test_binary_relation_validator_ignores_decompiler_comment_tokens() -> None:
    pseudo_c = """
/* WARNING: Unknown calling convention -- yet parameter storage is locked */
data = malloc(100);
free(data);
"""

    assert not binary_target_relation_visible("CWE-761", pseudo_c)


def test_binary_target_does_not_use_pointer_declarations_as_evidence() -> None:
    record = _record("present")
    record["task"]["target_cwe"] = "CWE-672"
    record["analysis"]["functions"][0]["pseudo_c"] = (
        "void target_function(void) {\n"
        "  int * data;\n"
        "  free(data);\n"
        "  printIntLine(*data);\n"
        "}\n"
    )

    target = build_binary_target(record)

    observation = target["findings"][0]["observation"]
    assert "`int * data;`" not in observation
    assert "`free(data);`" in observation
    assert "`printIntLine(*data);`" in observation


def test_binary_pair_target_prefers_contrastive_underread_evidence() -> None:
    present = _record("present")
    fixed = _record("fixed", label="not_observed")
    for record in (present, fixed):
        record["task"]["target_cwe"] = "CWE-127"
        record["artifact"]["compiler"] = "gcc"
        record["artifact"]["optimization"] = "O2"
    present["analysis"]["functions"][0]["pseudo_c"] = (
        "void target_function(void) {\n"
        "  wcscpy(dest,__s + -8);\n"
        "  printWLine(dest);\n"
        "}\n"
    )
    fixed["analysis"]["functions"][0]["pseudo_c"] = (
        "void target_function(void) {\n  wcscpy(dest,__s);\n  printWLine(dest);\n}\n"
    )

    present_target, fixed_target = build_binary_pair_targets(present, fixed)

    assert "`wcscpy(dest,__s + -8);`" in present_target["findings"][0]["observation"]
    assert "`wcscpy(dest,__s);`" in fixed_target["findings"][0]["observation"]


def test_binary_pair_target_does_not_prefer_nul_initializers_for_cwe195() -> None:
    present = _record("present")
    fixed = _record("fixed", label="not_observed")
    for record in (present, fixed):
        record["task"]["target_cwe"] = "CWE-195"
    present["analysis"]["functions"][0]["pseudo_c"] = (
        "void target_function(void) {\n"
        "  int data = atoi(inputBuffer);\n"
        "  inputBuffer[0] = '\\0';\n"
        "  char *buf = malloc((long)data);\n"
        "}\n"
    )
    fixed["analysis"]["functions"][0]["pseudo_c"] = (
        "void target_function(void) {\n"
        "  int data = atoi(inputBuffer);\n"
        "  if (data > 0) {\n"
        "    char *buf = malloc((long)data);\n"
        "  }\n"
        "}\n"
    )

    present_target, _ = build_binary_pair_targets(present, fixed)

    observation = present_target["findings"][0]["observation"]
    assert "`inputBuffer[0] = '\\0';`" not in observation
    assert "`char *buf = malloc((long)data);`" in observation


def test_binary_pair_target_uses_path_source_sink_and_fixed_name() -> None:
    present = _record("present")
    fixed = _record("fixed", label="not_observed")
    for record in (present, fixed):
        record["task"]["target_cwe"] = "CWE-23"
    present["analysis"]["functions"][0]["pseudo_c"] = (
        "void target_function(void) {\n"
        "  dataBuffer[0] = '\\0';\n"
        "  fgets(dataBuffer, 4096, stdin);\n"
        "  open(dataBuffer, 0x42, 0x180);\n"
        "}\n"
    )
    fixed["analysis"]["functions"][0]["pseudo_c"] = (
        "void target_function(void) {\n"
        '  builtin_strncpy(dataBuffer, "/tmp/file.txt", 14);\n'
        "  open(dataBuffer, 0x42, 0x180);\n"
        "}\n"
    )

    present_target, fixed_target = build_binary_pair_targets(present, fixed)

    present_observation = present_target["findings"][0]["observation"]
    fixed_observation = fixed_target["findings"][0]["observation"]
    assert "`dataBuffer[0] = '\\0';`" not in present_observation
    assert "`fgets(dataBuffer, 4096, stdin);`" in present_observation
    assert "`open(dataBuffer, 0x42, 0x180);`" in present_observation
    assert '`builtin_strncpy(dataBuffer, "/tmp/file.txt", 14);`' in fixed_observation


def test_binary_pair_target_uses_resource_guard_and_release_controls() -> None:
    present = _record("present")
    fixed = _record("fixed", label="not_observed")
    for record in (present, fixed):
        record["task"]["target_cwe"] = "CWE-400"
    present["analysis"]["functions"][0]["pseudo_c"] = (
        "void target_function(void) {\n"
        "  count = atoi(inputBuffer);\n"
        "  usleep(count);\n"
        "}\n"
    )
    fixed["analysis"]["functions"][0]["pseudo_c"] = (
        "void target_function(void) {\n"
        "  count = atoi(inputBuffer);\n"
        "  if ((count < 1) || (2000 < count)) {\n"
        '    printLine("Sleep time too long");\n'
        "  } else {\n"
        "    usleep(count);\n"
        "  }\n"
        "}\n"
    )

    _, fixed_target = build_binary_pair_targets(present, fixed)

    assert (
        "`if ((count < 1) || (2000 < count)) {`"
        in (fixed_target["findings"][0]["observation"])
    )

    present["task"]["target_cwe"] = "CWE-401"
    fixed["task"]["target_cwe"] = "CWE-401"
    present["analysis"]["functions"][0]["pseudo_c"] = (
        "void target_function(void) {\n  data = malloc(400);\n  return;\n}\n"
    )
    fixed["analysis"]["functions"][0]["pseudo_c"] = (
        "void target_function(void) {\n  data = malloc(400);\n  free(data);\n}\n"
    )

    _, fixed_target = build_binary_pair_targets(present, fixed)
    assert "`free(data);`" in fixed_target["findings"][0]["observation"]


def test_binary_pair_target_uses_safe_conversion_and_format_controls() -> None:
    present = _record("present")
    fixed = _record("fixed", label="not_observed")
    for record in (present, fixed):
        record["task"]["target_cwe"] = "CWE-195"
    present["analysis"]["functions"][0]["pseudo_c"] = (
        "void target_function(void) {\n"
        "  data = atoi(inputBuffer);\n"
        "  buf = malloc((long)data);\n"
        "}\n"
    )
    fixed["analysis"]["functions"][0]["pseudo_c"] = (
        "void target_function(void) {\n  data = 99;\n  buf = malloc((long)data);\n}\n"
    )

    _, fixed_target = build_binary_pair_targets(present, fixed)
    assert "`data = 99;`" in fixed_target["findings"][0]["observation"]

    present["task"]["target_cwe"] = "CWE-134"
    fixed["task"]["target_cwe"] = "CWE-134"
    present["analysis"]["functions"][0]["pseudo_c"] = (
        "void target_function(void) {\n  snprintf(dest, 99, dataBuffer);\n}\n"
    )
    fixed["analysis"]["functions"][0]["pseudo_c"] = (
        'void target_function(void) {\n  snprintf(dest, 99, "%s", dataBuffer);\n}\n'
    )

    _, fixed_target = build_binary_pair_targets(present, fixed)
    assert (
        '`snprintf(dest, 99, "%s", dataBuffer);`'
        in (fixed_target["findings"][0]["observation"])
    )


@pytest.mark.parametrize(
    (
        "target_cwe",
        "present_pseudo",
        "fixed_pseudo",
        "present_fragment",
        "fixed_fragment",
    ),
    [
        (
            "CWE-121",
            "wchar_t dest[50];\n"
            "wchar_t dataBuffer[100];\n"
            "wmemset(dataBuffer,L'A',99);\n"
            "__wcscat_chk(dest,dataBuffer,0x32);",
            "wchar_t dest[50];\n"
            "wchar_t dataBuffer[100];\n"
            "wmemset(dataBuffer,L'A',0x31);\n"
            "__wcscat_chk(dest,dataBuffer,0x32);",
            "wmemset(dataBuffer,L'A',99);",
            "wmemset(dataBuffer,L'A',0x31);",
        ),
        (
            "CWE-126",
            "data = dataBadBuffer;\n"
            "for (i = 0; i < destLen; i = i + 1) {\n"
            "dest[i] = data[i];\n"
            "}",
            "data = dataGoodBuffer;\n"
            "for (i = 0; i < destLen; i = i + 1) {\n"
            "dest[i] = data[i];\n"
            "}",
            "data = dataBadBuffer;",
            "data = dataGoodBuffer;",
        ),
        (
            "CWE-789",
            "uVar5 = strtoul(inputBuffer,0,0);\npvVar7 = operator_new__(uVar5 << 2);",
            "uVar5 = strtoul(inputBuffer,0,0);\n"
            "if ((99 < uVar5) || (uVar5 <= 5)) goto reject;\n"
            "pvVar7 = operator_new__(uVar5 << 2);",
            "pvVar7 = operator_new__(uVar5 << 2);",
            "if ((99 < uVar5) || (uVar5 <= 5)) goto reject;",
        ),
        (
            "CWE-78",
            'data_buf = recv(socket_fd);\n__stream = popen((char *)data_buf,"w");',
            "data_buf._0_8_ = __LC2;\n"
            "data_buf._8_8_ = _UNK_00100308;\n"
            '__stream = popen((char *)data_buf,"w");',
            '__stream = popen((char *)data_buf,"w");',
            "data_buf._0_8_ = __LC2;",
        ),
    ],
)
def test_binary_pair_target_exposes_specialized_pair_controls(
    target_cwe: str,
    present_pseudo: str,
    fixed_pseudo: str,
    present_fragment: str,
    fixed_fragment: str,
) -> None:
    present = _record("present")
    fixed = _record("fixed", label="not_observed")
    for record in (present, fixed):
        record["task"]["target_cwe"] = target_cwe
    present["analysis"]["functions"][0]["pseudo_c"] = present_pseudo
    fixed["analysis"]["functions"][0]["pseudo_c"] = fixed_pseudo

    present_target, fixed_target = build_binary_pair_targets(present, fixed)

    assert f"`{present_fragment}`" in present_target["findings"][0]["observation"]
    assert f"`{fixed_fragment}`" in fixed_target["findings"][0]["observation"]


def test_binary_pair_target_rejects_ungrounded_fixed_representation() -> None:
    present = _record("present")
    fixed = _record("fixed", label="not_observed")
    for record in (present, fixed):
        record["task"]["target_cwe"] = "CWE-762"
    present["analysis"]["functions"][0]["pseudo_c"] = (
        "data = operator_new__(800);\nfree(data);"
    )
    fixed["analysis"]["functions"][0]["pseudo_c"] = "return;"

    with pytest.raises(
        BinaryRecordValidationError,
        match="no observable remediation evidence",
    ):
        build_binary_pair_targets(present, fixed)


def test_binary_pair_target_rejects_print_only_underread_evidence() -> None:
    present = _record("present")
    fixed = _record("fixed", label="not_observed")
    for record in (present, fixed):
        record["task"]["target_cwe"] = "CWE-127"
    present["analysis"]["functions"][0]["pseudo_c"] = "printWLine(dest);"
    fixed["analysis"]["functions"][0]["pseudo_c"] = "printWLine(dest);"

    with pytest.raises(
        BinaryRecordValidationError,
        match="no observable target relation|no target-specific pseudo-C operation",
    ):
        build_binary_pair_targets(present, fixed)


def test_binary_pair_target_deduplicates_repeated_decompiler_lines() -> None:
    present = _record("present")
    fixed = _record("fixed", label="not_observed")
    for record in (present, fixed):
        record["task"]["target_cwe"] = "CWE-401"
    present["analysis"]["functions"][0]["pseudo_c"] = "data = malloc(400);\nreturn;"
    fixed["analysis"]["functions"][0]["pseudo_c"] = (
        "data = malloc(400);\nfree(data);\ndata = malloc(400);\nfree(data);"
    )

    _, fixed_target = build_binary_pair_targets(present, fixed)

    observation = fixed_target["findings"][0]["observation"]
    assert observation.count("`free(data);`") == 1
    assert observation.count("`data = malloc(400);`") == 1


@pytest.mark.parametrize(
    ("target_cwe", "present_pseudo", "fixed_pseudo"),
    [
        (
            "CWE-121",
            "char dest[50];\n"
            "char source[100];\n"
            "memset(source, 'A', 99);\n"
            "memcpy(dest, source, 99);",
            "char source[100];\nmemset(source, 'A', 49);",
        ),
        (
            "CWE-457",
            "printIntLine(data);",
            "data = 5;",
        ),
    ],
)
def test_binary_pair_target_rejects_fixed_control_without_constrained_sink(
    target_cwe: str,
    present_pseudo: str,
    fixed_pseudo: str,
) -> None:
    present = _record("present")
    fixed = _record("fixed", label="not_observed")
    for record in (present, fixed):
        record["task"]["target_cwe"] = target_cwe
    present["analysis"]["functions"][0]["pseudo_c"] = present_pseudo
    fixed["analysis"]["functions"][0]["pseudo_c"] = fixed_pseudo

    with pytest.raises(
        BinaryRecordValidationError,
        match="no observable remediation evidence",
    ):
        build_binary_pair_targets(present, fixed)


def test_binary_pair_target_keeps_fixed_control_and_constrained_sink() -> None:
    present = _record("present")
    fixed = _record("fixed", label="not_observed")
    for record in (present, fixed):
        record["task"]["target_cwe"] = "CWE-121"
    present["analysis"]["functions"][0]["pseudo_c"] = (
        "char dest[50];\n"
        "char source[100];\n"
        "memset(source, 'A', 99);\n"
        "memcpy(dest, source, 99);"
    )
    fixed["analysis"]["functions"][0]["pseudo_c"] = (
        "char dest[50];\n"
        "char source[100];\n"
        "memset(source, 'A', 49);\n"
        "memcpy(dest, source, sizeof(dest));"
    )

    _, fixed_target = build_binary_pair_targets(present, fixed)

    observation = fixed_target["findings"][0]["observation"]
    assert "`memset(source, 'A', 49);`" in observation
    assert "`memcpy(dest, source, sizeof(dest));`" in observation


@pytest.mark.parametrize(
    ("target_cwe", "present_pseudo", "fixed_pseudo", "fixed_fragments"),
    [
        (
            "CWE-121",
            "char dest[64];\n"
            "char source[100];\n"
            "dest[0] = '\\0';\n"
            "strncat(dest, source, 100);",
            "char dest[176];\n"
            "char source[100];\n"
            "dest[0] = '\\0';\n"
            "strncat(dest, source, 100);",
            (
                "char dest[176];",
                "dest[0] = '\\0';",
                "strncat(dest, source, 100);",
            ),
        ),
        (
            "CWE-457",
            "printLongLongLine(data);",
            "printLongLongLine(5);",
            ("printLongLongLine(5);",),
        ),
        (
            "CWE-23",
            "wcscat(dataBuffer, user_path);\n"
            "std::ifstream::open(&inputFile, dataBuffer, 8);",
            'wcscat(dataBuffer, L"/tmp/file.txt");\n'
            "std::ifstream::open(&inputFile, dataBuffer, 8);",
            (
                'wcscat(dataBuffer, L"/tmp/file.txt");',
                "std::ifstream::open(&inputFile, dataBuffer, 8);",
            ),
        ),
        (
            "CWE-401",
            "data = operator_new__(100);\nprintLine(data);",
            "data = operator_new__(100);\nprintLine(data);\noperator_delete__(data);",
            ("data = operator_new__(100);", "operator_delete__(data);"),
        ),
    ],
)
def test_binary_pair_target_normalizes_decompiler_role_evidence(
    target_cwe: str,
    present_pseudo: str,
    fixed_pseudo: str,
    fixed_fragments: tuple[str, ...],
) -> None:
    present = _record("present")
    fixed = _record("fixed", label="not_observed")
    for record in (present, fixed):
        record["task"]["target_cwe"] = target_cwe
    present["analysis"]["functions"][0]["pseudo_c"] = present_pseudo
    fixed["analysis"]["functions"][0]["pseudo_c"] = fixed_pseudo

    _, fixed_target = build_binary_pair_targets(present, fixed)

    observation = fixed_target["findings"][0]["observation"]
    for fragment in fixed_fragments:
        assert f"`{fragment}`" in observation


@pytest.mark.parametrize(
    "fixed_pseudo",
    [
        "char dest[64];\n"
        "char source[100];\n"
        "dest[0] = '\\0';\n"
        "strncat(dest, source, 100);",
        "char dest[176];\nchar source[100];\nstrncat(dest, source, 100);",
    ],
)
def test_binary_pair_target_rejects_unsafe_or_uninitialized_bounded_append(
    fixed_pseudo: str,
) -> None:
    present = _record("present")
    fixed = _record("fixed", label="not_observed")
    for record in (present, fixed):
        record["task"]["target_cwe"] = "CWE-121"
    present["analysis"]["functions"][0]["pseudo_c"] = (
        "char dest[64];\n"
        "char source[100];\n"
        "dest[0] = '\\0';\n"
        "strncat(dest, source, 100);"
    )
    fixed["analysis"]["functions"][0]["pseudo_c"] = fixed_pseudo

    with pytest.raises(
        BinaryRecordValidationError,
        match="no observable remediation evidence",
    ):
        build_binary_pair_targets(present, fixed)


def test_binary_pair_target_links_cwe457_initialization_to_same_variable_sink() -> None:
    present = _record("present")
    fixed = _record("fixed", label="not_observed")
    for record in (present, fixed):
        record["task"]["target_cwe"] = "CWE-457"
    present["analysis"]["functions"][0]["pseudo_c"] = "printWLine(data);"
    fixed["analysis"]["functions"][0]["pseudo_c"] = (
        'printLine("Benign, fixed string");\n'
        "printWLine(anon_var_dwarf_41);\n"
        'data = L"string";\n'
        "printWLine(data);"
    )

    _, fixed_target = build_binary_pair_targets(present, fixed)

    observation = fixed_target["findings"][0]["observation"]
    assert '`data = L"string";`' in observation
    assert "`printWLine(data);`" in observation
    assert "anon_var_dwarf_41" not in observation
    assert "Benign, fixed string" not in observation


@pytest.mark.parametrize(
    ("present_pseudo", "fixed_pseudo", "fixed_fragments"),
    [
        (
            "printIntLine(data[i].intOne);",
            "data[i].intOne = i;\nprintIntLine(data[i_1].intOne);",
            ("data[i].intOne = i;", "printIntLine(data[i_1].intOne);"),
        ),
        (
            "pvVar1 = malloc(40);\n"
            "printIntLine(*(undefined4 *)((long)pvVar1 + (long)i * 4));",
            "pvVar1 = malloc(40);\n"
            "*(int *)((long)pvVar1 + (long)i * 4) = i;\n"
            "printIntLine(*(undefined4 *)((long)pvVar1 + (long)i_1 * 4));",
            (
                "*(int *)((long)pvVar1 + (long)i * 4) = i;",
                "printIntLine(*(undefined4 *)((long)pvVar1 + (long)i_1 * 4));",
            ),
        ),
    ],
)
def test_binary_pair_target_links_cwe457_memory_writes_to_reads(
    present_pseudo: str,
    fixed_pseudo: str,
    fixed_fragments: tuple[str, str],
) -> None:
    present = _record("present")
    fixed = _record("fixed", label="not_observed")
    for record in (present, fixed):
        record["task"]["target_cwe"] = "CWE-457"
    present["analysis"]["functions"][0]["pseudo_c"] = present_pseudo
    fixed["analysis"]["functions"][0]["pseudo_c"] = fixed_pseudo

    _, fixed_target = build_binary_pair_targets(present, fixed)

    observation = fixed_target["findings"][0]["observation"]
    for fragment in fixed_fragments:
        assert f"`{fragment}`" in observation


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
