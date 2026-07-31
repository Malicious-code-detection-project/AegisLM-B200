"""Streaming, non-executing audit for an EMBER2024 JSONL benchmark ZIP."""

from __future__ import annotations

import hashlib
import json
import re
import zipfile
from collections import Counter, defaultdict
from collections.abc import Mapping
from pathlib import Path
from typing import Any

EMBER2024_AUDIT_SCHEMA_VERSION = "aegislm.phase-f-ember2024-elf-test-audit.v1"
EMBER2024_FEATURE_SCHEMA_VERSION = "aegislm.ember2024-static-feature-observation.v1"
EMBER2024_GOLD_SCHEMA_VERSION = "aegislm.ember2024-malware-gold.v1"
EMBER2024_MATERIALIZATION_SCHEMA_VERSION = (
    "aegislm.phase-f-ember2024-materialization.v1"
)
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_REQUIRED_KEYS = {
    "sha256",
    "first_submission_date",
    "last_analysis_date",
    "detection_ratio",
    "label",
    "file_type",
    "family",
    "family_confidence",
    "behavior",
    "file_property",
    "packer",
    "exploit",
    "group",
    "histogram",
    "byteentropy",
    "strings",
    "general",
    "week_id",
    "caps",
    "ttps",
    "mbc",
}
_STATIC_FEATURE_FIELDS = {
    "histogram",
    "byteentropy",
    "strings",
    "general",
    "header",
    "section",
    "imports",
    "exports",
    "datadirectories",
    "richheader",
    "authenticode",
    "pefilewarnings",
}
EMBER2024_STATIC_FEATURE_FIELDS = tuple(sorted(_STATIC_FEATURE_FIELDS))


class Ember2024AuditError(ValueError):
    """Raised when EMBER2024 audit inputs violate the fixed contract."""


def materialize_ember2024_elf_test(
    archive_path: Path,
    inventory_path: Path,
    audit_path: Path,
    output_dir: Path,
    *,
    expected_records: int,
    dataset_role: str,
) -> dict[str, Any]:
    """Write label-blind features and separate gold after deterministic dedup."""
    if expected_records <= 0:
        raise Ember2024AuditError("expected materialized count must be positive")
    if dataset_role not in {"classifier_train", "classifier_test"}:
        raise Ember2024AuditError(
            "dataset role must be classifier_train or classifier_test"
        )
    if not archive_path.is_file() or not inventory_path.is_file():
        raise Ember2024AuditError("archive and inventory must exist")
    if not audit_path.is_file():
        raise Ember2024AuditError("benchmark audit must exist")

    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    _validate_inventory(inventory, archive_path)
    _validate_materialization_audit(audit, expected_records)

    features_path = output_dir / "features.jsonl"
    gold_path = output_dir / "gold.jsonl"
    manifest_path = output_dir / "materialization-manifest.json"
    output_paths = (features_path, gold_path, manifest_path)
    existing = [path for path in output_paths if path.exists()]
    if existing:
        raise Ember2024AuditError(
            f"materialization output already exists: {existing[0]}"
        )
    output_dir.mkdir(parents=True, exist_ok=True)
    features_temporary = features_path.with_suffix(".jsonl.tmp")
    gold_temporary = gold_path.with_suffix(".jsonl.tmp")
    temporary_paths = (features_temporary, gold_temporary)
    if any(path.exists() for path in temporary_paths):
        raise Ember2024AuditError("temporary materialization output exists")

    seen: dict[tuple[str, str], tuple[str, int]] = {}
    label_counts: Counter[str] = Counter()
    week_counts: Counter[str] = Counter()
    file_sha256_weeks: dict[str, set[str]] = defaultdict(set)
    try:
        with (
            zipfile.ZipFile(archive_path, "r") as archive,
            features_temporary.open(
                "x", encoding="utf-8", newline="\n"
            ) as features_stream,
            gold_temporary.open("x", encoding="utf-8", newline="\n") as gold_stream,
        ):
            member_names = sorted(
                info.filename
                for info in archive.infolist()
                if not info.is_dir() and info.filename.endswith(".jsonl")
            )
            for member_name in member_names:
                with archive.open(member_name, "r") as stream:
                    for line in stream:
                        if not line.strip():
                            continue
                        record = json.loads(line)
                        if not isinstance(record, Mapping):
                            raise Ember2024AuditError(
                                "materialization record must be an object"
                            )
                        digest, week_id, label, feature_payload = (
                            _materialization_fields(record)
                        )
                        observation_key = (week_id, digest)
                        feature_signature = _canonical_value_signature(feature_payload)
                        previous = seen.get(observation_key)
                        if previous is not None:
                            if previous != (feature_signature, label):
                                raise Ember2024AuditError(
                                    "duplicate observation has conflicting "
                                    "features or primary label"
                                )
                            continue
                        seen[observation_key] = (feature_signature, label)
                        observation_id = _observation_id(week_id, digest)
                        feature_record = {
                            "schema_version": EMBER2024_FEATURE_SCHEMA_VERSION,
                            "observation_id": observation_id,
                            "week_id": week_id,
                            "file_type": "ELF",
                            "features": feature_payload,
                        }
                        gold_record = {
                            "schema_version": EMBER2024_GOLD_SCHEMA_VERSION,
                            "observation_id": observation_id,
                            "file_sha256": digest,
                            "week_id": week_id,
                            "label": label,
                        }
                        features_stream.write(_jsonl_line(feature_record))
                        gold_stream.write(_jsonl_line(gold_record))
                        label_counts[str(label)] += 1
                        week_counts[week_id] += 1
                        file_sha256_weeks[digest].add(week_id)

        if len(seen) != expected_records:
            raise Ember2024AuditError(
                "post-dedup count mismatch: "
                f"expected={expected_records} observed={len(seen)}"
            )
        features_temporary.replace(features_path)
        gold_temporary.replace(gold_path)
    except Exception:
        for path in temporary_paths:
            path.unlink(missing_ok=True)
        raise

    manifest = {
        "schema_version": EMBER2024_MATERIALIZATION_SCHEMA_VERSION,
        "source": {
            "archive_path": str(archive_path.resolve()),
            "archive_sha256": inventory["archive"]["observed_sha256"],
            "inventory_path": str(inventory_path.resolve()),
            "inventory_sha256": _file_sha256(inventory_path),
            "audit_path": str(audit_path.resolve()),
            "audit_sha256": _file_sha256(audit_path),
        },
        "contract": {
            "dataset_role": dataset_role,
            "deduplication_key": ["week_id", "sha256"],
            "ordering": "archive_member_name_then_source_line",
            "feature_fields": list(EMBER2024_STATIC_FEATURE_FIELDS),
            "label_blind_features": True,
            "auxiliary_labels_included": False,
        },
        "summary": {
            "record_count": len(seen),
            "label_counts": dict(sorted(label_counts.items())),
            "week_counts": dict(sorted(week_counts.items())),
            "unique_file_sha256_count": len(file_sha256_weeks),
            "cross_week_file_sha256_count": sum(
                len(weeks) > 1 for weeks in file_sha256_weeks.values()
            ),
        },
        "outputs": {
            "features_path": str(features_path.resolve()),
            "features_sha256": _file_sha256(features_path),
            "gold_path": str(gold_path.resolve()),
            "gold_sha256": _file_sha256(gold_path),
        },
        "decision": "materialization_pass",
        "approved_for_classifier_benchmark": dataset_role == "classifier_test",
        "approved_for_classifier_training": dataset_role == "classifier_train",
        "approved_for_sft_training": False,
        "safety": {
            "raw_executable_read_count": 0,
            "raw_executable_execution_count": 0,
            "feature_label_leakage_count": 0,
            "auxiliary_label_export_count": 0,
        },
    }
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def audit_ember2024_elf_test(
    archive_path: Path,
    inventory_path: Path,
    *,
    expected_records: int,
    expected_materialized_records: int | None = None,
    expected_members: int = 12,
) -> dict[str, Any]:
    """Stream JSONL members and report schema/label aggregates only."""
    if expected_records <= 0 or expected_members <= 0:
        raise Ember2024AuditError("expected counts must be positive")
    if expected_materialized_records is None:
        expected_materialized_records = expected_records
    if expected_materialized_records <= 0:
        raise Ember2024AuditError("expected materialized count must be positive")
    if not archive_path.is_file() or not inventory_path.is_file():
        raise Ember2024AuditError("archive and inventory must exist")
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    _validate_inventory(inventory, archive_path)

    record_count = 0
    invalid_json_count = 0
    missing_required_key_count = 0
    schema_variant_counts: Counter[tuple[str, ...]] = Counter()
    label_counts: Counter[str] = Counter()
    file_type_counts: Counter[str] = Counter()
    member_record_counts: dict[str, int] = {}
    member_week_ids: dict[str, list[str]] = {}
    sha256_counts: Counter[str] = Counter()
    sha256_labels: dict[str, set[str]] = defaultdict(set)
    sha256_weeks: dict[str, set[str]] = defaultdict(set)
    observation_signatures: dict[tuple[str, str], set[str]] = defaultdict(set)
    first_observation_field_signatures: dict[tuple[str, str], dict[str, str]] = {}
    differing_observation_fields: set[tuple[tuple[str, str], str]] = set()
    conflicting_feature_observations: set[tuple[str, str]] = set()
    invalid_sha256_count = 0
    duplicate_sha256_count = 0
    within_member_duplicate_sha256_count = 0
    invalid_feature_shape_count = 0
    nonempty_label_counts: Counter[str] = Counter()

    with zipfile.ZipFile(archive_path, "r") as archive:
        members = [
            info
            for info in archive.infolist()
            if not info.is_dir() and info.filename.endswith(".jsonl")
        ]
        for info in members:
            member_count = 0
            week_ids: set[str] = set()
            member_sha256_values: set[str] = set()
            with archive.open(info, "r") as stream:
                for line in stream:
                    if not line.strip():
                        continue
                    record_count += 1
                    member_count += 1
                    try:
                        record = json.loads(line)
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        invalid_json_count += 1
                        continue
                    if not isinstance(record, Mapping):
                        invalid_json_count += 1
                        continue
                    keys = tuple(sorted(str(key) for key in record))
                    schema_variant_counts[keys] += 1
                    if not _REQUIRED_KEYS <= set(record):
                        missing_required_key_count += 1

                    digest = str(record.get("sha256") or "")
                    if not _SHA256_PATTERN.fullmatch(digest):
                        invalid_sha256_count += 1
                    else:
                        week_id = str(record.get("week_id"))
                        if sha256_counts[digest]:
                            duplicate_sha256_count += 1
                        if digest in member_sha256_values:
                            within_member_duplicate_sha256_count += 1
                        member_sha256_values.add(digest)
                        sha256_counts[digest] += 1
                        sha256_labels[digest].add(str(record.get("label")))
                        sha256_weeks[digest].add(week_id)
                        observation_signatures[(week_id, digest)].add(
                            _canonical_record_signature(record)
                        )
                        observation_key = (week_id, digest)
                        field_signatures = {
                            str(field): _canonical_value_signature(value)
                            for field, value in record.items()
                        }
                        first_field_signatures = first_observation_field_signatures.get(
                            observation_key
                        )
                        if first_field_signatures is None:
                            first_observation_field_signatures[observation_key] = (
                                field_signatures
                            )
                        else:
                            for field in set(first_field_signatures) | set(
                                field_signatures
                            ):
                                if first_field_signatures.get(
                                    field
                                ) != field_signatures.get(field):
                                    differing_observation_fields.add(
                                        (observation_key, field)
                                    )
                                    if field in _STATIC_FEATURE_FIELDS:
                                        conflicting_feature_observations.add(
                                            observation_key
                                        )

                    label_counts[str(record.get("label"))] += 1
                    file_type_counts[str(record.get("file_type") or "")] += 1
                    week_ids.add(str(record.get("week_id")))
                    if not _valid_feature_shapes(record):
                        invalid_feature_shape_count += 1
                    for label_field in (
                        "family",
                        "behavior",
                        "file_property",
                        "packer",
                        "exploit",
                        "group",
                        "caps",
                        "ttps",
                        "mbc",
                    ):
                        if _nonempty(record.get(label_field)):
                            nonempty_label_counts[label_field] += 1
            member_record_counts[info.filename] = member_count
            member_week_ids[info.filename] = sorted(week_ids)

    duplicate_sha256_group_count = sum(count > 1 for count in sha256_counts.values())
    cross_week_duplicate_sha256_group_count = sum(
        len(weeks) > 1 for weeks in sha256_weeks.values()
    )
    conflicting_label_sha256_group_count = sum(
        len(labels) > 1 for labels in sha256_labels.values()
    )
    conflicting_duplicate_observation_count = sum(
        len(signatures) > 1 for signatures in observation_signatures.values()
    )
    differing_observation_field_counts = Counter(
        field for _, field in differing_observation_fields
    )
    materialized_record_count = len(observation_signatures)
    checks = {
        "archive_member_count_matches": len(member_record_counts) == expected_members,
        "record_count_matches": record_count == expected_records,
        "materialized_record_count_matches": (
            materialized_record_count == expected_materialized_records
        ),
        "json_parse_complete": invalid_json_count == 0,
        "required_keys_complete": missing_required_key_count == 0,
        "single_schema_variant": len(schema_variant_counts) == 1,
        "sha256_valid": invalid_sha256_count == 0,
        "duplicate_sha256_labels_consistent": (
            conflicting_label_sha256_group_count == 0
        ),
        "duplicate_static_features_identical": (
            len(conflicting_feature_observations) == 0
        ),
        "labels_binary_and_both_present": set(label_counts) == {"0", "1"},
        "file_type_elf_only": set(file_type_counts) == {"ELF"},
        "feature_shapes_valid": invalid_feature_shape_count == 0,
        "one_week_per_member": all(
            len(week_ids) == 1 for week_ids in member_week_ids.values()
        ),
        "week_ids_unique_across_members": len(
            {week_ids[0] for week_ids in member_week_ids.values() if week_ids}
        )
        == expected_members,
        "raw_executable_absent": True,
    }
    passed = all(checks.values())
    return {
        "schema_version": EMBER2024_AUDIT_SCHEMA_VERSION,
        "summary": {
            "record_count": record_count,
            "materialized_record_count": materialized_record_count,
            "member_count": len(member_record_counts),
            "schema_variant_count": len(schema_variant_counts),
            "unique_sha256_count": len(sha256_counts),
            "invalid_json_count": invalid_json_count,
            "missing_required_key_count": missing_required_key_count,
            "invalid_sha256_count": invalid_sha256_count,
            "duplicate_sha256_count": duplicate_sha256_count,
            "duplicate_sha256_group_count": duplicate_sha256_group_count,
            "cross_week_duplicate_sha256_group_count": (
                cross_week_duplicate_sha256_group_count
            ),
            "conflicting_label_sha256_group_count": (
                conflicting_label_sha256_group_count
            ),
            "within_member_duplicate_sha256_count": (
                within_member_duplicate_sha256_count
            ),
            "conflicting_duplicate_observation_count": (
                conflicting_duplicate_observation_count
            ),
            "conflicting_static_feature_observation_count": len(
                conflicting_feature_observations
            ),
            "max_sha256_multiplicity": max(sha256_counts.values(), default=0),
            "invalid_feature_shape_count": invalid_feature_shape_count,
        },
        "label_counts": dict(sorted(label_counts.items())),
        "file_type_counts": dict(sorted(file_type_counts.items())),
        "nonempty_label_counts": dict(sorted(nonempty_label_counts.items())),
        "duplicate_observation_differing_field_counts": dict(
            sorted(differing_observation_field_counts.items())
        ),
        "member_record_counts": dict(sorted(member_record_counts.items())),
        "member_week_ids": dict(sorted(member_week_ids.items())),
        "checks": checks,
        "failure_reasons": sorted(
            name for name, passed_check in checks.items() if not passed_check
        ),
        "decision": "benchmark_metadata_pass" if passed else "benchmark_metadata_fail",
        "approved_for_benchmark_materialization": passed,
        "approved_for_sft_training": False,
        "approved_for_raw_binary_download": False,
        "materialization": {
            "deduplication_required": (materialized_record_count != record_count),
            "deduplication_key": ["week_id", "sha256"],
            "raw_record_count": record_count,
            "post_dedup_record_count": materialized_record_count,
        },
        "safety": {
            "jsonl_member_read_count": len(member_record_counts),
            "raw_executable_read_count": 0,
            "raw_executable_execution_count": 0,
            "individual_hash_export_count": 0,
            "feature_vector_export_count": 0,
        },
    }


def _validate_inventory(inventory: Mapping[str, Any], archive_path: Path) -> None:
    if inventory.get("decision") != "inventory_pass":
        raise Ember2024AuditError("archive inventory has not passed")
    archive = inventory.get("archive")
    safety = inventory.get("safety")
    if not isinstance(archive, Mapping) or not isinstance(safety, Mapping):
        raise Ember2024AuditError("archive inventory is incomplete")
    if Path(str(archive.get("path") or "")).resolve() != archive_path.resolve():
        raise Ember2024AuditError("archive path does not match inventory")
    if int(archive.get("observed_bytes") or -1) != archive_path.stat().st_size:
        raise Ember2024AuditError("archive size changed after inventory")
    if int(safety.get("member_extraction_count") or 0) != 0:
        raise Ember2024AuditError("archive was extracted before audit")


def _validate_materialization_audit(
    audit: Mapping[str, Any],
    expected_records: int,
) -> None:
    if audit.get("decision") != "benchmark_metadata_pass":
        raise Ember2024AuditError("benchmark audit has not passed")
    if audit.get("approved_for_benchmark_materialization") is not True:
        raise Ember2024AuditError("benchmark materialization is not approved")
    materialization = audit.get("materialization")
    if not isinstance(materialization, Mapping):
        raise Ember2024AuditError("benchmark audit materialization is missing")
    if materialization.get("deduplication_key") != ["week_id", "sha256"]:
        raise Ember2024AuditError("benchmark audit deduplication key changed")
    if int(materialization.get("post_dedup_record_count") or -1) != (expected_records):
        raise Ember2024AuditError("benchmark audit record count changed")


def _materialization_fields(
    record: Mapping[str, Any],
) -> tuple[str, str, int, dict[str, Any]]:
    digest = str(record.get("sha256") or "")
    if not _SHA256_PATTERN.fullmatch(digest):
        raise Ember2024AuditError("materialization record has invalid sha256")
    week_value = record.get("week_id")
    if week_value is None:
        raise Ember2024AuditError("materialization record has no week_id")
    week_id = str(week_value)
    label = record.get("label")
    if (
        not isinstance(label, int)
        or isinstance(label, bool)
        or label
        not in {
            0,
            1,
        }
    ):
        raise Ember2024AuditError("materialization label must be 0 or 1")
    if record.get("file_type") != "ELF":
        raise Ember2024AuditError("materialization file type must be ELF")
    missing_features = _STATIC_FEATURE_FIELDS - set(record)
    if missing_features:
        raise Ember2024AuditError(
            f"materialization features are missing: {sorted(missing_features)}"
        )
    feature_payload = {
        field: record[field] for field in EMBER2024_STATIC_FEATURE_FIELDS
    }
    return digest, week_id, label, feature_payload


def _observation_id(week_id: str, digest: str) -> str:
    key = f"ember2024-elf:{week_id}:{digest}".encode()
    return f"ember2024-elf-{hashlib.sha256(key).hexdigest()}"


def _jsonl_line(record: Mapping[str, Any]) -> str:
    return (
        json.dumps(
            record,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(8 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _valid_feature_shapes(record: Mapping[str, Any]) -> bool:
    strings = record.get("strings")
    general = record.get("general")
    return (
        _list_of_numbers(record.get("histogram"), 256)
        and _list_of_numbers(record.get("byteentropy"), 256)
        and isinstance(strings, Mapping)
        and _list_of_numbers(strings.get("printabledist"), 96)
        and isinstance(strings.get("string_counts"), Mapping)
        and isinstance(general, Mapping)
        and _list_of_numbers(general.get("start_bytes"), 4)
    )


def _list_of_numbers(value: Any, expected_length: int) -> bool:
    return (
        isinstance(value, list)
        and len(value) == expected_length
        and all(
            isinstance(item, int | float) and not isinstance(item, bool)
            for item in value
        )
    )


def _nonempty(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, list | Mapping):
        return bool(value)
    return value is not None


def _canonical_record_signature(record: Mapping[str, Any]) -> str:
    return _canonical_value_signature(record)


def _canonical_value_signature(value: Any) -> str:
    canonical = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(canonical).hexdigest()
