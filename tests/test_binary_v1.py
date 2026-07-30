from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from aegislm.datasets.binary_v1 import (
    freeze_binary_v1,
    prepare_binary_v1,
    summarize_binary_manual_review,
)
from aegislm.datasets.phase_f import load_jsonl, write_jsonl
from scripts.finalize_phase_f_binary_v1_review import finalize_review
from scripts.build_phase_f_binary_tokenizer_gate import build_tokenizer_gate
from scripts.select_phase_f_binary_relation_supply import select_relation_supply
from scripts.apply_phase_f_binary_review_decisions import apply_decisions


class _Tokenizer:
    name_or_path = "test-qwen-tokenizer"

    def apply_chat_template(self, _messages: Any, **_kwargs: Any) -> list[int]:
        return list(range(300))


class _VariantLengthTokenizer:
    name_or_path = "variant-length-tokenizer"

    def apply_chat_template(self, messages: Any, **_kwargs: Any) -> list[int]:
        prompt = messages[1]["content"]
        return list(range(5000 if '"compiler": "gcc"' in prompt else 300))


def _record(
    pair_id: str,
    label: str,
    compiler: str,
    optimization: str,
    cwe: str,
) -> dict[str, Any]:
    opaque = hashlib.sha256(f"{pair_id}:{label}".encode()).hexdigest()[:16]
    variant = f"{compiler}-{optimization}".lower()
    pseudo_c = (
        "void target_function(void)\n{\n"
        + (
            "char dst[8];\nmemcpy(dst, source, 32);"
            if label == "present"
            else "char dst[32];\nmemcpy(dst, source, sizeof(dst));"
        )
        + "\nreturn;\n}"
    )
    return {
        "schema_version": "aegislm.binary-analysis-record.v1",
        "id": f"binary-b0-{opaque}-{variant}",
        "artifact": {
            "sha256": hashlib.sha256(
                f"{pair_id}:{label}:{variant}".encode()
            ).hexdigest(),
            "format": "ELF",
            "architecture": "x86_64",
            "compiler": compiler,
            "optimization": optimization,
            "stripped": False,
            "external_artifact_ref": f"artifact://fixture/{pair_id}",
        },
        "analysis": {
            "analyzer": "fixture",
            "analyzer_version": "1",
            "decompiler": "fixture",
            "decompiler_version": "1",
            "functions": [
                {
                    "function_id": f"function-{opaque}",
                    "function_hash": hashlib.sha256(pseudo_c.encode()).hexdigest(),
                    "pseudo_c": pseudo_c,
                    "assembly_evidence": ["call memcpy"],
                    "static_features": {
                        "imports": ["memcpy"],
                        "sections": [".text"],
                        "strings": [],
                        "symbols": [],
                    },
                }
            ],
            "warnings": ["fixture"],
        },
        "task": {"target_cwe": cwe},
        "metadata": {
            "split": "test",
            "source_dataset": "private-fixture",
            "label": label,
            "compiler_group_id": f"binary-group-{opaque}",
            "contains_executable_payload": False,
        },
    }


def _inputs() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    pair_ids = [f"pair-{index}" for index in range(6)]
    records = [
        _record(pair_id, label, compiler, optimization, f"CWE-{120 + index % 2}")
        for index, pair_id in enumerate(pair_ids)
        for label in ("present", "not_observed")
        for compiler in ("gcc", "clang")
        for optimization in ("O0", "O2")
    ]
    return records, {"accepted_pair_ids": pair_ids}


def test_binary_v1_builds_pair_first_balanced_contract() -> None:
    records, gate = _inputs()

    prepared = prepare_binary_v1(
        records,
        gate,
        tokenizer=_Tokenizer(),
        train_pairs=3,
        validation_pairs=1,
        test_pairs=2,
        consistency_pairs=1,
        manual_review_records=4,
    )

    audit = prepared["audit"]
    assert audit["overall_pass"]
    assert audit["counts"]["train_records"] == 6
    assert audit["counts"]["validation_records"] == 2
    assert audit["counts"]["challenge_records"] == 4
    assert audit["counts"]["consistency_records"] == 8
    assert audit["metrics"]["pair_split_overlap_count"] == 0
    assert all(len(row["messages"]) == 2 for row in prepared["challenge"])
    assert {row["id"] for row in prepared["challenge"]} == {
        row["id"] for row in prepared["gold"]
    }
    prompt = json.dumps(prepared["challenge"], ensure_ascii=False)
    assert "private-fixture" not in prompt
    assert '"label"' not in prompt


def test_binary_v1_is_deterministic_and_freezes_hashes(tmp_path: Path) -> None:
    records, gate = _inputs()
    first = prepare_binary_v1(
        records,
        gate,
        tokenizer=_Tokenizer(),
        train_pairs=3,
        validation_pairs=1,
        test_pairs=2,
        consistency_pairs=1,
        manual_review_records=4,
    )
    second = prepare_binary_v1(
        list(reversed(records)),
        gate,
        tokenizer=_Tokenizer(),
        train_pairs=3,
        validation_pairs=1,
        test_pairs=2,
        consistency_pairs=1,
        manual_review_records=4,
    )

    assert first["audit"] == second["audit"]
    assert first["manifest"] == second["manifest"]
    output = tmp_path / "phase-f-binary-v1"
    manifest = freeze_binary_v1(
        first,
        output,
        source_gate_path="/private/final-gate.json",
        source_records_path="/private/normalized-records.jsonl",
    )
    assert manifest["status"] == "manual_target_review_required"
    assert manifest["approved_for_training"] is False
    assert len(load_jsonl(output / "private" / "manual_review_100.jsonl")) == 4
    assert (output / "SHA256SUMS").is_file()
    assert (output / "dataset_info.json").is_file()


def test_binary_v1_manual_review_is_required_before_canary(
    tmp_path: Path,
) -> None:
    rows = [
        {
            "id": f"record-{index}",
            "operator_label_error": False,
            "operator_evidence_error": index < 5,
        }
        for index in range(100)
    ]
    assert summarize_binary_manual_review(rows)["pass"]
    rows[5]["operator_label_error"] = True
    assert not summarize_binary_manual_review(rows)["pass"]

    records, gate = _inputs()
    prepared = prepare_binary_v1(
        records,
        gate,
        tokenizer=_Tokenizer(),
        train_pairs=3,
        validation_pairs=1,
        test_pairs=2,
        consistency_pairs=1,
        manual_review_records=4,
    )
    output = tmp_path / "phase-f-binary-v1"
    freeze_binary_v1(
        prepared,
        output,
        source_gate_path="/private/final-gate.json",
        source_records_path="/private/normalized-records.jsonl",
    )
    review = load_jsonl(output / "private" / "manual_review_100.jsonl")
    for row in review:
        row["operator_label_error"] = False
        row["operator_evidence_error"] = False
    write_jsonl(review, output / "private" / "manual_review_100.jsonl")
    manifest = finalize_review(output)
    assert manifest["status"] == "approved_for_binary_canary"
    assert manifest["approved_for_training"] is True


def test_binary_v1_cutoff_audits_only_selected_variants() -> None:
    records, gate = _inputs()

    prepared = prepare_binary_v1(
        records,
        gate,
        tokenizer=_VariantLengthTokenizer(),
        train_pairs=3,
        validation_pairs=1,
        test_pairs=2,
        consistency_pairs=0,
        manual_review_records=4,
    )

    assert prepared["audit"]["metrics"]["maximum_token_count"] == 300
    assert prepared["audit"]["counts"]["selected_variants"]["gcc-O0"] == 0
    assert prepared["audit"]["counts"]["selected_variants"]["gcc-O2"] == 0


def test_binary_v1_accepts_single_variant_pairs_outside_consistency_subset() -> None:
    records, gate = _inputs()
    opaque_groups = {
        f"binary-group-{hashlib.sha256(f'pair-0:{label}'.encode()).hexdigest()[:16]}"
        for label in ("present", "not_observed")
    }
    records = [
        record
        for record in records
        if record["metadata"]["compiler_group_id"] not in opaque_groups
        or (
            record["artifact"]["compiler"] == "clang"
            and record["artifact"]["optimization"] == "O0"
        )
    ]

    prepared = prepare_binary_v1(
        records,
        gate,
        tokenizer=_Tokenizer(),
        train_pairs=3,
        validation_pairs=1,
        test_pairs=2,
        consistency_pairs=0,
        manual_review_records=4,
    )

    selected = {
        row["compiler_variant"]
        for row in prepared["manifest"]
        if row["pair_id"] == "pair-0"
    }
    assert selected == {"clang-O0"}


def test_binary_v1_reserves_full_variant_pairs_in_test_for_consistency() -> None:
    records, gate = _inputs()
    records = [
        record
        for record in records
        if record["id"].startswith(
            "binary-b0-"
            + hashlib.sha256(
                f"pair-0:{record['metadata']['label']}".encode()
            ).hexdigest()[:16]
        )
        or (
            record["artifact"]["compiler"] == "clang"
            and record["artifact"]["optimization"] == "O0"
        )
    ]

    prepared = prepare_binary_v1(
        records,
        gate,
        tokenizer=_Tokenizer(),
        train_pairs=3,
        validation_pairs=1,
        test_pairs=2,
        consistency_pairs=1,
        manual_review_records=4,
    )

    assert {
        row["split"] for row in prepared["manifest"] if row["pair_id"] == "pair-0"
    } == {"test"}
    assert prepared["audit"]["counts"]["consistency_pairs"] == 1
    assert prepared["audit"]["counts"]["consistency_records"] == 8


def test_binary_tokenizer_gate_selects_exact_supply_after_relation_gate() -> None:
    records, gate = _inputs()
    relation_gate = {
        "target_relation_policy": "observable-target-relation-v1",
        "qualified_pair_ids": gate["accepted_pair_ids"],
        "qualified_pair_variants": {
            pair_id: ["gcc-O0", "gcc-O2", "clang-O0", "clang-O2"]
            for pair_id in gate["accepted_pair_ids"]
        },
    }

    result = build_tokenizer_gate(
        relation_gate,
        [records],
        tokenizer=_Tokenizer(),
        required_pairs=5,
        cutoff_len=4096,
        minimum_consistency_pairs=1,
    )

    assert result["gate_pass"] is True
    assert result["accepted_pair_count"] == 5
    assert result["qualified_reserve_pair_count"] == 1
    assert result["quality_gates"]["accepted_pair_supply"] is True
    assert result["quality_gates"]["compiler_consistency_supply"] is True
    assert result["output_contract"] == "aegislm.binary-assessment-output.v1"
    assert result["review_eligible"] is False


def test_binary_tokenizer_gate_can_apply_v2_role_contract() -> None:
    records, gate = _inputs()
    for record in records:
        record["task"]["target_cwe"] = "CWE-121"
        if record["metadata"]["label"] == "present":
            pseudo_c = "char dst[8];\nmemcpy(dst, src, 32);"
        else:
            pseudo_c = "char dst[32];\nmemcpy(dst, src, 8);"
        record["analysis"]["functions"][0]["pseudo_c"] = pseudo_c
    relation_gate = {
        "target_relation_policy": "observable-target-relation-v1",
        "qualified_pair_ids": gate["accepted_pair_ids"],
        "qualified_pair_variants": {
            pair_id: ["gcc-O0", "gcc-O2", "clang-O0", "clang-O2"]
            for pair_id in gate["accepted_pair_ids"]
        },
    }

    result = build_tokenizer_gate(
        relation_gate,
        [records],
        tokenizer=_Tokenizer(),
        required_pairs=5,
        cutoff_len=4096,
        minimum_consistency_pairs=1,
        target_contract="v2",
    )

    assert result["gate_pass"] is True
    assert result["output_contract"] == "aegislm.binary-role-assessment-output.v2"
    assert result["target_policy"] == "role-structured-evidence-v2"


def test_binary_tokenizer_gate_can_apply_strict_v2_role_contract() -> None:
    records, gate = _inputs()
    for record in records:
        record["task"]["target_cwe"] = "CWE-121"
        if record["metadata"]["label"] == "present":
            pseudo_c = "char dst[8];\nmemmove(dst, src, 32);"
        else:
            pseudo_c = "char dst[32];\nmemmove(dst, src, 8);"
        record["analysis"]["functions"][0]["pseudo_c"] = pseudo_c
    relation_gate = {
        "target_relation_policy": "observable-target-relation-v1",
        "qualified_pair_ids": gate["accepted_pair_ids"],
        "qualified_pair_variants": {
            pair_id: ["gcc-O0", "gcc-O2", "clang-O0", "clang-O2"]
            for pair_id in gate["accepted_pair_ids"]
        },
    }

    result = build_tokenizer_gate(
        relation_gate,
        [records],
        tokenizer=_Tokenizer(),
        required_pairs=5,
        cutoff_len=4096,
        minimum_consistency_pairs=1,
        target_contract="v2-strict",
    )

    assert result["gate_pass"] is True
    assert result["target_policy"] == "strict-cwe-role-evidence-v3"


def test_relation_gate_preserves_reserve_variants_for_tokenizer_replacement() -> None:
    records, old_gate = _inputs()

    relation, recovery = select_relation_supply(
        old_gate,
        records,
        {"candidates": []},
        [],
        required_pairs=5,
    )

    assert relation["accepted_pair_count"] == 5
    assert relation["qualified_pair_count"] == 6
    assert relation["qualified_reserve_pair_count"] == 1
    reserve_id = relation["qualified_reserve_pair_ids"][0]
    assert relation["qualified_pair_variants"][reserve_id] == [
        "gcc-O0",
        "gcc-O2",
        "clang-O0",
        "clang-O2",
    ]
    assert recovery["accepted_pair_count"] == 0


def test_binary_review_decisions_are_hash_bound_and_may_stop_early() -> None:
    rows = [
        {
            "id": f"review-{index}",
            "operator_label_error": None,
            "operator_evidence_error": None,
            "notes": "",
        }
        for index in range(100)
    ]
    decisions = {
        "review_artifact_sha256": "fixture-sha",
        "decisions": [
            {
                "id": f"review-{index}",
                "operator_label_error": False,
                "operator_evidence_error": True,
                "notes": "target-specific evidence is absent",
            }
            for index in range(6)
        ],
    }

    updated = apply_decisions(rows, decisions, review_sha256="fixture-sha")
    summary = summarize_binary_manual_review(updated)

    assert summary["status"] == "fail_early"
    assert summary["error_count"] == 6
    assert summary["unfinished_count"] == 94
