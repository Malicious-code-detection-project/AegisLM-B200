from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

from aegislm.datasets.archive_inventory import inventory_zip_archive
from aegislm.datasets.ember2024 import (
    audit_ember2024_elf_test,
    materialize_ember2024_elf_test,
)


def _record(index: int, *, label: int, week_id: int) -> dict:
    return {
        "sha256": hashlib.sha256(str(index).encode()).hexdigest(),
        "first_submission_date": 1,
        "last_analysis_date": 2,
        "detection_ratio": "1/2",
        "label": label,
        "file_type": "ELF",
        "family": "",
        "family_confidence": 0.0,
        "behavior": [],
        "file_property": [],
        "packer": [],
        "exploit": [],
        "group": [],
        "histogram": [0] * 256,
        "byteentropy": [0] * 256,
        "strings": {
            "printabledist": [0] * 96,
            "string_counts": {},
        },
        "general": {"start_bytes": [0] * 4},
        "header": {},
        "section": {},
        "imports": {},
        "exports": {},
        "datadirectories": {},
        "richheader": {},
        "authenticode": {},
        "pefilewarnings": [],
        "week_id": week_id,
        "caps": [],
        "ttps": [],
        "mbc": [],
    }


def _inputs(tmp_path: Path) -> tuple[Path, Path]:
    archive_path = tmp_path / "ELF_test.zip"
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for week_id in range(12):
            records = [
                _record(week_id * 2, label=0, week_id=week_id),
                _record(week_id * 2 + 1, label=1, week_id=week_id),
            ]
            archive.writestr(
                f"week-{week_id:02d}.jsonl",
                "".join(json.dumps(record) + "\n" for record in records),
            )
    inventory = inventory_zip_archive(
        archive_path,
        expected_bytes=archive_path.stat().st_size,
        expected_sha256=hashlib.sha256(archive_path.read_bytes()).hexdigest(),
        max_uncompressed_bytes=1_000_000,
    )
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_text(json.dumps(inventory), encoding="utf-8")
    return archive_path, inventory_path


def test_ember2024_elf_test_audit_passes_balanced_temporal_fixture(
    tmp_path: Path,
) -> None:
    archive, inventory = _inputs(tmp_path)

    result = audit_ember2024_elf_test(
        archive,
        inventory,
        expected_records=24,
    )

    assert result["decision"] == "benchmark_metadata_pass"
    assert result["label_counts"] == {"0": 12, "1": 12}
    assert result["summary"]["unique_sha256_count"] == 24
    assert result["checks"]["one_week_per_member"] is True
    assert result["approved_for_benchmark_materialization"] is True
    assert result["approved_for_sft_training"] is False
    assert result["safety"]["raw_executable_read_count"] == 0


def test_ember2024_elf_test_audit_rejects_duplicate_and_bad_shape(
    tmp_path: Path,
) -> None:
    archive, inventory = _inputs(tmp_path)
    with zipfile.ZipFile(archive, "r") as source:
        members = {
            name: source.read(name).decode("utf-8") for name in source.namelist()
        }
    first_name = sorted(members)[0]
    records = [json.loads(line) for line in members[first_name].splitlines()]
    records[1]["sha256"] = records[0]["sha256"]
    records[1]["histogram"] = [0]
    members[first_name] = "".join(json.dumps(record) + "\n" for record in records)
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as target:
        for name, content in members.items():
            target.writestr(name, content)
    updated_inventory = inventory_zip_archive(
        archive,
        expected_bytes=archive.stat().st_size,
        expected_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        max_uncompressed_bytes=1_000_000,
    )
    inventory.write_text(json.dumps(updated_inventory), encoding="utf-8")

    result = audit_ember2024_elf_test(
        archive,
        inventory,
        expected_records=24,
    )

    assert result["decision"] == "benchmark_metadata_fail"
    assert result["summary"]["duplicate_sha256_count"] == 1
    assert result["summary"]["within_member_duplicate_sha256_count"] == 1
    assert result["summary"]["conflicting_label_sha256_group_count"] == 1
    assert result["summary"]["conflicting_duplicate_observation_count"] == 1
    assert result["summary"]["conflicting_static_feature_observation_count"] == 1
    assert result["summary"]["invalid_feature_shape_count"] == 1


def test_ember2024_elf_test_audit_allows_consistent_cross_week_observation(
    tmp_path: Path,
) -> None:
    archive, inventory = _inputs(tmp_path)
    with zipfile.ZipFile(archive, "r") as source:
        members = {
            name: source.read(name).decode("utf-8") for name in source.namelist()
        }
    first_name, second_name = sorted(members)[:2]
    first_record = json.loads(members[first_name].splitlines()[0])
    second_records = [json.loads(line) for line in members[second_name].splitlines()]
    second_records[0]["sha256"] = first_record["sha256"]
    second_records[0]["label"] = first_record["label"]
    members[second_name] = "".join(
        json.dumps(record) + "\n" for record in second_records
    )
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as target:
        for name, content in members.items():
            target.writestr(name, content)
    updated_inventory = inventory_zip_archive(
        archive,
        expected_bytes=archive.stat().st_size,
        expected_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        max_uncompressed_bytes=1_000_000,
    )
    inventory.write_text(json.dumps(updated_inventory), encoding="utf-8")

    result = audit_ember2024_elf_test(
        archive,
        inventory,
        expected_records=24,
    )

    assert result["decision"] == "benchmark_metadata_pass"
    assert result["summary"]["duplicate_sha256_count"] == 1
    assert result["summary"]["cross_week_duplicate_sha256_group_count"] == 1
    assert result["summary"]["within_member_duplicate_sha256_count"] == 0
    assert result["summary"]["conflicting_label_sha256_group_count"] == 0


def test_ember2024_elf_test_audit_requires_identical_week_hash_dedup(
    tmp_path: Path,
) -> None:
    archive, inventory = _inputs(tmp_path)
    with zipfile.ZipFile(archive, "r") as source:
        members = {
            name: source.read(name).decode("utf-8") for name in source.namelist()
        }
    first_name = sorted(members)[0]
    first_records = [json.loads(line) for line in members[first_name].splitlines()]
    first_records.append(first_records[0])
    members[first_name] = "".join(json.dumps(record) + "\n" for record in first_records)
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as target:
        for name, content in members.items():
            target.writestr(name, content)
    updated_inventory = inventory_zip_archive(
        archive,
        expected_bytes=archive.stat().st_size,
        expected_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        max_uncompressed_bytes=1_000_000,
    )
    inventory.write_text(json.dumps(updated_inventory), encoding="utf-8")

    result = audit_ember2024_elf_test(
        archive,
        inventory,
        expected_records=25,
        expected_materialized_records=24,
    )

    assert result["decision"] == "benchmark_metadata_pass"
    assert result["summary"]["materialized_record_count"] == 24
    assert result["materialization"]["deduplication_required"] is True
    assert result["materialization"]["deduplication_key"] == [
        "week_id",
        "sha256",
    ]


def test_ember2024_elf_test_audit_allows_duplicate_label_metadata_difference(
    tmp_path: Path,
) -> None:
    archive, inventory = _inputs(tmp_path)
    with zipfile.ZipFile(archive, "r") as source:
        members = {
            name: source.read(name).decode("utf-8") for name in source.namelist()
        }
    first_name = sorted(members)[0]
    first_records = [json.loads(line) for line in members[first_name].splitlines()]
    duplicate = dict(first_records[0])
    duplicate["family"] = "additional-label"
    first_records.append(duplicate)
    members[first_name] = "".join(json.dumps(record) + "\n" for record in first_records)
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as target:
        for name, content in members.items():
            target.writestr(name, content)
    updated_inventory = inventory_zip_archive(
        archive,
        expected_bytes=archive.stat().st_size,
        expected_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        max_uncompressed_bytes=1_000_000,
    )
    inventory.write_text(json.dumps(updated_inventory), encoding="utf-8")

    result = audit_ember2024_elf_test(
        archive,
        inventory,
        expected_records=25,
        expected_materialized_records=24,
    )

    assert result["decision"] == "benchmark_metadata_pass"
    assert result["summary"]["conflicting_duplicate_observation_count"] == 1
    assert result["summary"]["conflicting_static_feature_observation_count"] == 0
    assert result["duplicate_observation_differing_field_counts"] == {"family": 1}


def test_ember2024_materialization_separates_features_and_gold(
    tmp_path: Path,
) -> None:
    archive, inventory = _inputs(tmp_path)
    audit = audit_ember2024_elf_test(
        archive,
        inventory,
        expected_records=24,
    )
    audit_path = tmp_path / "audit.json"
    audit_path.write_text(json.dumps(audit), encoding="utf-8")

    result = materialize_ember2024_elf_test(
        archive,
        inventory,
        audit_path,
        tmp_path / "materialized",
        expected_records=24,
        dataset_role="classifier_test",
    )

    features_path = Path(result["outputs"]["features_path"])
    gold_path = Path(result["outputs"]["gold_path"])
    feature_records = [
        json.loads(line)
        for line in features_path.read_text(encoding="utf-8").splitlines()
    ]
    gold_records = [
        json.loads(line) for line in gold_path.read_text(encoding="utf-8").splitlines()
    ]
    assert result["decision"] == "materialization_pass"
    assert result["summary"]["record_count"] == 24
    assert len(feature_records) == len(gold_records) == 24
    assert "label" not in feature_records[0]
    assert "sha256" not in json.dumps(feature_records[0])
    assert set(gold_records[0]) == {
        "schema_version",
        "observation_id",
        "file_sha256",
        "week_id",
        "label",
    }
    assert result["safety"]["feature_label_leakage_count"] == 0
    assert result["approved_for_classifier_benchmark"] is True
    assert result["approved_for_classifier_training"] is False
    assert result["approved_for_sft_training"] is False


def test_ember2024_materialization_is_deterministic(tmp_path: Path) -> None:
    archive, inventory = _inputs(tmp_path)
    audit = audit_ember2024_elf_test(
        archive,
        inventory,
        expected_records=24,
    )
    audit_path = tmp_path / "audit.json"
    audit_path.write_text(json.dumps(audit), encoding="utf-8")

    first = materialize_ember2024_elf_test(
        archive,
        inventory,
        audit_path,
        tmp_path / "first",
        expected_records=24,
        dataset_role="classifier_train",
    )
    second = materialize_ember2024_elf_test(
        archive,
        inventory,
        audit_path,
        tmp_path / "second",
        expected_records=24,
        dataset_role="classifier_train",
    )

    assert first["outputs"]["features_sha256"] == second["outputs"]["features_sha256"]
    assert first["outputs"]["gold_sha256"] == second["outputs"]["gold_sha256"]
    assert first["approved_for_classifier_training"] is True
    assert first["approved_for_classifier_benchmark"] is False
