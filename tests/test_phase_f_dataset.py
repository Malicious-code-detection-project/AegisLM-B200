from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegislm.datasets.phase_f import (
    PhaseFDatasetError,
    assert_no_model_visible_leakage,
    build_raw_catalog,
    build_source_profile,
    materialize_source_record,
    read_parquet,
    write_parquet,
)
from aegislm.datasets.phase_f_raw import (
    normalize_bigvul_row,
    normalize_bigvul_rows,
    normalize_diversevul_row,
    normalize_primevul_pair,
)
from aegislm.datasets.security_builder import diversevul_to_aegislm_record
from aegislm.prompts import format_baseline_prompt


def _records() -> list[dict]:
    records = []
    for target in (0, 1):
        for index in range(100):
            code = (
                f"int sample_{target}_{index}(char *input) "
                f"{{ return input[{index}] == '\\0'; }}"
            )
            record = diversevul_to_aegislm_record(
                {"func": code, "target": target},
                index=target * 10 + index,
            )
            assert record is not None
            signals = record["input"]["signals"]
            signals.update(
                {
                    "cwe": ["CWE-125"],
                    "project": "phase-f-test",
                    "repository": "phase-f-test",
                    "commit_id": f"commit-{target}-{index}",
                    "patch_group_id": f"phase-f-test:commit-{target}-{index}",
                    "function_id": f"sample-{target}-{index}",
                }
            )
            records.append(record)
    return records


def test_catalog_records_leakage_without_storing_code() -> None:
    records = _records()

    catalog = build_raw_catalog(records)

    assert len(catalog) == len(records)
    assert all(row["disposition"] == "eligible" for row in catalog)
    assert all("signal_key:target" in row["prompt_leakage_flags"] for row in catalog)
    catalog_text = json.dumps(catalog)
    assert "int sample_" not in catalog_text
    assert all(len(row["content_sha256"]) == 64 for row in catalog)


def test_phase_f_profile_is_balanced_reproducible_and_label_blind() -> None:
    records = _records()
    catalog = build_raw_catalog(records)

    first = build_source_profile(
        records,
        catalog,
        seed=20260728,
        train_per_class=1,
        validation_per_class=1,
        test_per_class=1,
        cross_dataset_names=(),
    )
    second = build_source_profile(
        records,
        catalog,
        seed=20260728,
        train_per_class=1,
        validation_per_class=1,
        test_per_class=1,
        cross_dataset_names=(),
    )

    assert first["summary"] == second["summary"]
    assert first["manifest"] == second["manifest"]
    assert len(first["train"]) == 2
    assert len(first["validation"]) == 2
    assert len(first["challenge"]) == 2
    assert len(first["gold"]) == 2
    assert {item["is_vulnerable"] for item in first["gold"]} == {False, True}

    for record in first["train"] + first["validation"] + first["challenge"]:
        assert_no_model_visible_leakage(record)
        prompt = json.dumps(format_baseline_prompt(record), ensure_ascii=False)
        assert "DiverseVul" not in prompt
        assert '"target"' not in prompt
        assert '"label"' not in prompt

    splits_by_group: dict[str, set[str]] = {}
    for row in first["manifest"]:
        splits_by_group.setdefault(row["group_id"], set()).add(row["split"])
    assert all(len(splits) == 1 for splits in splits_by_group.values())


def test_phase_f_profile_refuses_to_fill_missing_quota() -> None:
    records = _records()[:2]
    catalog = build_raw_catalog(records)

    with pytest.raises(PhaseFDatasetError, match="not enough"):
        build_source_profile(
            records,
            catalog,
            train_per_class=1,
            validation_per_class=1,
            test_per_class=1,
            cross_dataset_names=(),
        )


def test_catalog_parquet_round_trip(tmp_path: Path) -> None:
    catalog = build_raw_catalog(_records())
    path = tmp_path / "raw_catalog.parquet"

    write_parquet(catalog, path)
    loaded = read_parquet(path)

    assert path.exists()
    assert [row["record_id"] for row in loaded] == [row["record_id"] for row in catalog]
    assert loaded[0]["prompt_leakage_flags"] == catalog[0]["prompt_leakage_flags"]


def test_conflicting_near_duplicate_labels_are_quarantined() -> None:
    records = _records()
    records[100]["input"]["context"] = records[0]["input"]["context"]

    catalog = build_raw_catalog([records[0], records[100]])

    assert {row["disposition"] for row in catalog} == {"quarantine"}
    assert {row["disposition_reason"] for row in catalog} == {
        "conflicting_exact_duplicate_labels"
    }


def test_raw_normalizers_preserve_audit_fields_without_model_materialization() -> None:
    diverse = normalize_diversevul_row(
        {
            "func": "int read_at(char *p, int i) { return p[i]; }",
            "target": 1,
            "cwe": ["CWE-125"],
            "project": "sample",
            "commit_id": "abc123",
        },
        index=7,
        original_split="train",
    )
    bigvul = normalize_bigvul_row(
        {
            "func_before": "int f(char *p) { return p[4]; }",
            "func_after": "int f(char *p) { return p ? p[0] : 0; }",
            "vul": 1,
            "CWE ID": "CWE-125",
            "CVE ID": "CVE-2099-0001",
            "project": "sample",
            "commit_id": "def456",
            "file_name": "sample.c",
            "patch": "@@ defensive test patch metadata @@",
        },
        index=8,
        original_split="test",
    )

    assert diverse["input"]["signals"]["cwe"] == ["CWE-125"]
    assert diverse["input"]["signals"]["patch_group_id"] == "sample:abc123"
    assert bigvul["input"]["signals"]["pair_changed"] is True
    assert bigvul["input"]["signals"]["paired_content_sha256"]
    assert bigvul["input"]["signals"]["pair_type"] == "vulnerable_before"


def test_leakage_check_allows_security_like_identifiers_inside_code() -> None:
    records = _records()
    catalog = build_raw_catalog(records)
    profile = build_source_profile(
        records,
        catalog,
        train_per_class=1,
        validation_per_class=1,
        test_per_class=1,
        cross_dataset_names=(),
    )
    record = profile["train"][0]
    record["input"]["context"] += (
        "\nint expected_output = 0; int target = expected_output;"
    )

    assert_no_model_visible_leakage(record)


def test_materialization_redacts_secret_like_assignments() -> None:
    record = _records()[0]
    record["input"]["context"] += "\nconst char *password=example_value;"
    catalog_row = build_raw_catalog([record])[0]

    materialized = materialize_source_record(
        record,
        catalog_row,
        split="train",
        seed=20260728,
    )

    assert "example_value" not in materialized["input"]["context"]
    assert "[REDACTED_SECRET]" in materialized["input"]["context"]
    assert "secret_like_assignments_redacted=1" in materialized["metadata"]["notes"]


def test_group_first_pools_reserve_and_cross_dataset_holdout() -> None:
    core_records = _records()
    bigvul_records: list[dict] = []
    for index in range(100):
        bigvul_records.extend(
            normalize_bigvul_rows(
                {
                    "func_before": (
                        f"int vulnerable_{index}(char *p) {{ return p[{index + 1}]; }}"
                    ),
                    "func_after": (
                        f"int fixed_{index}(char *p) {{ return p ? p[0] : 0; }}"
                    ),
                    "vul": 1,
                    "CWE ID": "CWE-125",
                    "CVE ID": f"CVE-2099-{index:04d}",
                    "project": f"cross-project-{index}",
                    "commit_id": f"cross-commit-{index}",
                    "file_name": f"cross-{index}.c",
                    "lang": "C",
                    "patch": "@@ verified defensive patch @@",
                },
                index=index,
                original_split="test",
            )
        )
    records = core_records + bigvul_records
    catalog = build_raw_catalog(records)

    profile = build_source_profile(
        records,
        catalog,
        train_per_class=1,
        validation_per_class=1,
        test_per_class=1,
        cross_dataset_names=("BigVul",),
        cross_dataset_records=2,
    )

    assert len(profile["train"]) == 2
    assert len(profile["validation"]) == 2
    assert len(profile["challenge"]) == 2
    assert len(profile["cross_dataset"]["BigVul"]["challenge"]) == 2
    assert {
        item["is_vulnerable"] for item in profile["cross_dataset"]["BigVul"]["gold"]
    } == {False, True}
    assert profile["reserve_manifest"]
    assert {row["pool"] for row in profile["eligible_manifest"]} <= {
        "train",
        "validation",
        "test",
    }
    assert all(
        row["materialization"] == "reserve" for row in profile["reserve_manifest"]
    )
    assert {row["materialization"] for row in profile["selected_manifest"]} == {
        "train",
        "validation",
        "blind_test",
        "cross_dataset_test",
    }

    pools_by_group: dict[str, set[str]] = {}
    for row in profile["eligible_manifest"]:
        pools_by_group.setdefault(row["group_id"], set()).add(row["pool"])
    assert all(len(pools) == 1 for pools in pools_by_group.values())


def test_taxonomy_excludes_language_and_quarantines_unverified_pairs() -> None:
    unverified = normalize_bigvul_row(
        {
            "func_before": "int unverified(char *p) { return p[1]; }",
            "func_after": "",
            "vul": 1,
            "CWE ID": "CWE-125",
            "project": "quarantine-project",
            "commit_id": "quarantine-commit",
            "file_name": "quarantine.c",
            "lang": "C",
            "patch": "",
        },
        index=501,
        original_split="train",
    )

    row = build_raw_catalog([unverified])[0]

    assert row["disposition"] == "quarantine"
    assert row["disposition_reason"] == "verified_before_after_pair_required"
    assert row["weakness_family"] == "memory_safety"
    assert row["source_language_audit"] == "C"
    assert "language" not in {
        "task_family",
        "weakness_family",
        "evidence_level",
        "representation",
        "pair_type",
        "length_bucket",
        "label",
        "label_confidence",
    }


def test_primevul_pair_is_verified_and_grouped_together() -> None:
    records = normalize_primevul_pair(
        [
            {
                "target": 1,
                "func": "int paired(char *p) { return p[4]; }",
                "func_hash": "before-hash",
                "project": "paired-project",
                "commit_id": "paired-commit",
                "cve": "CVE-2099-9001",
                "cwe": ["CWE-125"],
            },
            {
                "target": 0,
                "func": "int paired(char *p) { return p ? p[0] : 0; }",
                "func_hash": "after-hash",
                "project": "paired-project",
                "commit_id": "paired-commit",
                "cve": "CVE-2099-9001",
                "cwe": ["CWE-125"],
            },
        ],
        pair_index=42,
        original_split="test",
    )

    catalog = build_raw_catalog(records)

    assert len(records) == 2
    assert {row["label_value"] for row in catalog} == {
        "present",
        "not_observed",
    }
    assert {row["pair_type"] for row in catalog} == {
        "vulnerable_before",
        "fixed_after",
    }
    assert {row["disposition"] for row in catalog} == {"eligible"}
    assert len({row["group_id"] for row in catalog}) == 1


def test_primevul_pair_provenance_mismatch_is_quarantined() -> None:
    records = normalize_primevul_pair(
        [
            {
                "target": 1,
                "func": "int bad_pair(char *p) { return p[4]; }",
                "project": "project-a",
                "commit_id": "commit-a",
                "cve": "CVE-2099-9101",
                "cwe": ["CWE-125"],
            },
            {
                "target": 0,
                "func": "int unrelated(char *p) { return p ? p[0] : 0; }",
                "project": "project-b",
                "commit_id": "commit-b",
                "cve": "CVE-2099-9102",
                "cwe": ["CWE-476"],
            },
        ],
        pair_index=43,
        original_split="train",
    )

    catalog = build_raw_catalog(records)

    assert {row["disposition"] for row in catalog} == {"quarantine"}
    assert {row["label_confidence"] for row in catalog} == {"primevul_pair_mismatch"}
    assert len({row["group_id"] for row in catalog}) == 2
