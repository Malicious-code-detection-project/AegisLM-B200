from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegislm.datasets.phase_f import (
    PhaseFDatasetError,
    assert_no_model_visible_leakage,
    build_raw_catalog,
    build_source_profile,
    read_parquet,
    write_parquet,
)
from aegislm.datasets.security_builder import diversevul_to_aegislm_record
from aegislm.prompts import format_baseline_prompt


def _records() -> list[dict]:
    records = []
    for target in (0, 1):
        for index in range(3):
            code = (
                f"int sample_{target}_{index}(char *input) "
                f"{{ return input[{index}] == '\\0'; }}"
            )
            record = diversevul_to_aegislm_record(
                {"func": code, "target": target},
                index=target * 10 + index,
            )
            assert record is not None
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
    )
    second = build_source_profile(
        records,
        catalog,
        seed=20260728,
        train_per_class=1,
        validation_per_class=1,
        test_per_class=1,
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
        )


def test_catalog_parquet_round_trip(tmp_path: Path) -> None:
    catalog = build_raw_catalog(_records())
    path = tmp_path / "raw_catalog.parquet"

    write_parquet(catalog, path)
    loaded = read_parquet(path)

    assert path.exists()
    assert [row["record_id"] for row in loaded] == [row["record_id"] for row in catalog]
    assert loaded[0]["prompt_leakage_flags"] == catalog[0]["prompt_leakage_flags"]
