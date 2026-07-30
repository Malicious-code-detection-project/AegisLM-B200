import pytest

from scripts.finalize_phase_f_binary_b0_review import (
    _pair_index_sha256,
    finalize_review,
)


def _entry(pair: str, compiler: str, optimization: str) -> dict[str, object]:
    return {
        "pair_id": pair,
        "compiler": compiler,
        "optimization": optimization,
        "target_cwe": "CWE-1",
        "operator_decision": "pending",
    }


def test_finalize_review_applies_variant_override() -> None:
    entries = [
        _entry("pair-a", "gcc", "O0"),
        _entry("pair-a", "gcc", "O2"),
    ]
    decisions = {
        "review_scope": "test",
        "required_target_preservation_rate": 1.0,
        "pairs": {
            "pair-a": {
                "default": "pass",
                "notes": "visible",
                "overrides": {
                    "gcc-O2": {
                        "decision": "fail",
                        "notes": "optimized away",
                    }
                },
            }
        },
    }

    finalized, summary = finalize_review(entries, decisions)

    assert [row["operator_decision"] for row in finalized] == ["pass", "fail"]
    assert summary["variant_target_preservation"]["rate"] == 0.5
    assert summary["pair_target_preservation"]["rate"] == 0.0
    assert summary["ready_for_b0_100_pair"] is False


def test_finalize_review_requires_every_pair_policy() -> None:
    with pytest.raises(ValueError, match="missing review policy"):
        finalize_review(
            [_entry("missing", "gcc", "O0")],
            {
                "review_scope": "test",
                "required_target_preservation_rate": 1.0,
                "pairs": {},
            },
        )


def test_finalize_review_accepts_compact_explicit_decisions() -> None:
    entries = [
        _entry("pair-pass", "gcc", "O0"),
        _entry("pair-fail", "clang", "O2"),
    ]
    decisions = {
        "review_scope": "test",
        "required_target_preservation_rate": 1.0,
        "pass_pair_ids": ["pair-pass"],
        "pass_notes": "reviewed across all required variants",
        "failed_pairs": {
            "pair-fail": "optimized output lost the target operation",
        },
    }

    finalized, summary = finalize_review(entries, decisions)

    assert [row["operator_decision"] for row in finalized] == ["pass", "fail"]
    assert finalized[0]["operator_evidence_notes"] == (
        "reviewed across all required variants"
    )
    assert summary["pair_target_preservation"]["passed"] == 1
    assert summary["decision"] == "fail_replace_candidates"


def test_finalize_review_rejects_compact_duplicate_decision() -> None:
    with pytest.raises(ValueError, match="both pass and fail"):
        finalize_review(
            [_entry("duplicate", "gcc", "O0")],
            {
                "review_scope": "test",
                "required_target_preservation_rate": 1.0,
                "pass_pair_ids": ["duplicate"],
                "failed_pairs": {"duplicate": "not preserved"},
            },
        )


def test_finalize_review_accepts_artifact_bound_cwe_decisions() -> None:
    entries = [
        _entry("pair-pass", "gcc", "O0"),
        _entry("pair-fail", "clang", "O2"),
    ]
    pair_index = {str(entry["pair_id"]): str(entry["target_cwe"]) for entry in entries}
    decisions = {
        "review_scope": "test",
        "required_target_preservation_rate": 1.0,
        "review_pair_count": 2,
        "review_pair_index_sha256": _pair_index_sha256(pair_index),
        "cwe_pass": ["CWE-1"],
        "cwe_fail": {},
        "pair_fail": {"pair-fail": "optimized target operation disappeared"},
    }

    finalized, summary = finalize_review(entries, decisions)

    assert [row["operator_decision"] for row in finalized] == ["pass", "fail"]
    assert summary["pair_target_preservation"]["passed"] == 1


def test_finalize_review_rejects_changed_cwe_review_set() -> None:
    entries = [_entry("pair-pass", "gcc", "O0")]
    with pytest.raises(ValueError, match="index hash mismatch"):
        finalize_review(
            entries,
            {
                "review_scope": "test",
                "required_target_preservation_rate": 1.0,
                "review_pair_count": 1,
                "review_pair_index_sha256": "0" * 64,
                "cwe_pass": ["CWE-1"],
                "cwe_fail": {},
                "pair_fail": {},
            },
        )


def test_finalize_review_rejects_missing_cwe_policy() -> None:
    entries = [_entry("pair-pass", "gcc", "O0")]
    pair_index = {"pair-pass": "CWE-1"}
    with pytest.raises(ValueError, match="missing CWE review policies"):
        finalize_review(
            entries,
            {
                "review_scope": "test",
                "required_target_preservation_rate": 1.0,
                "review_pair_count": 1,
                "review_pair_index_sha256": _pair_index_sha256(pair_index),
                "cwe_pass": [],
                "cwe_fail": {},
                "pair_fail": {},
            },
        )
