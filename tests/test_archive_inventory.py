from __future__ import annotations

import hashlib
import stat
import zipfile
from pathlib import Path

import pytest

from aegislm.datasets.archive_inventory import (
    ArchiveInventoryError,
    ArchiveRangePart,
    assemble_archive_ranges,
    extract_verified_zip_member,
    inventory_zip_archive,
)


def _digest(path: Path) -> str:
    return hashlib.md5(path.read_bytes(), usedforsecurity=False).hexdigest()


def _inventory(path: Path) -> dict:
    return inventory_zip_archive(
        path,
        expected_bytes=path.stat().st_size,
        expected_md5=_digest(path),
        max_uncompressed_bytes=1_000_000,
    )


def test_safe_zip_passes_without_extracting_payloads(tmp_path: Path) -> None:
    archive_path = tmp_path / "dataset.zip"
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("CVEfixes/CVEfixes.db", b"sqlite fixture")
        archive.writestr("CVEfixes/README.md", b"metadata")

    result = _inventory(archive_path)

    assert result["decision"] == "inventory_pass"
    assert result["approved_for_extraction"] is False
    assert result["approved_for_selective_member_review"] is True
    assert result["approved_for_processing"] is False
    assert result["approved_for_training"] is False
    assert result["inventory"]["member_count"] == 2
    assert result["inventory"]["member_suffix_counts"] == {".db": 1, ".md": 1}
    assert result["inventory"]["members"][0]["name"] == "CVEfixes/CVEfixes.db"
    assert result["inventory"]["nested_archive_members"] == []
    assert result["safety"]["member_payload_read_count"] == 0
    assert result["safety"]["member_extraction_count"] == 0


def test_inventory_rejects_unsafe_paths_encryption_symlinks_and_executables(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "unsafe.zip"
    symlink = zipfile.ZipInfo("dataset/link")
    symlink.create_system = 3
    symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("../escape.txt", b"escape")
        archive.writestr("C:\\absolute.txt", b"absolute")
        archive.writestr("dataset/payload.exe", b"MZ")
        archive.writestr(symlink, "target")

    result = _inventory(archive_path)

    assert result["decision"] == "inventory_fail"
    assert result["approved_for_extraction"] is False
    assert result["approved_for_selective_member_review"] is False
    assert set(result["failure_reasons"]) >= {
        "executable_members_absent",
        "symlink_members_absent",
        "unsafe_member_paths_absent",
    }
    assert result["inventory"]["forbidden_executable_members"] == [
        "dataset/payload.exe"
    ]


def test_inventory_rejects_hash_size_and_resource_limit_mismatches(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "large.zip"
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("dataset/data.db", b"A" * 10_000)

    result = inventory_zip_archive(
        archive_path,
        expected_bytes=archive_path.stat().st_size + 1,
        expected_md5="0" * 32,
        max_uncompressed_bytes=100,
        max_compression_ratio=2,
    )

    assert set(result["failure_reasons"]) >= {
        "archive_size_matches",
        "compression_ratio_within_limit",
        "uncompressed_size_within_limit",
        "upstream_md5_matches",
    }


def test_inventory_rejects_invalid_inputs(tmp_path: Path) -> None:
    missing = tmp_path / "missing.zip"
    with pytest.raises(ArchiveInventoryError, match="regular file"):
        inventory_zip_archive(
            missing,
            expected_bytes=1,
            expected_md5="0" * 32,
            max_uncompressed_bytes=1,
        )
    archive_path = tmp_path / "not-a-zip.zip"
    archive_path.write_bytes(b"nope")
    with pytest.raises(ArchiveInventoryError, match="expected_md5"):
        inventory_zip_archive(
            archive_path,
            expected_bytes=4,
            expected_md5="invalid",
            max_uncompressed_bytes=1,
        )


def test_inventory_reports_invalid_zip_without_extracting(tmp_path: Path) -> None:
    archive_path = tmp_path / "not-a-zip.zip"
    archive_path.write_bytes(b"nope")

    result = _inventory(archive_path)

    assert result["decision"] == "inventory_fail"
    assert result["checks"]["zip_central_directory_readable"] is False
    assert result["inventory"]["bad_zip_reason"].startswith("BadZipFile:")
    assert result["safety"]["member_extraction_count"] == 0


def test_range_assembly_requires_contiguous_exact_parts_and_verifies_hash(
    tmp_path: Path,
) -> None:
    payload = b"verified range assembly"
    first = tmp_path / "first.part"
    second = tmp_path / "second.part"
    first.write_bytes(payload[:9])
    second.write_bytes(payload[9:])
    output = tmp_path / "archive.zip"

    result = assemble_archive_ranges(
        [
            ArchiveRangePart(9, len(payload) - 1, second),
            ArchiveRangePart(0, 8, first),
        ],
        output,
        expected_bytes=len(payload),
        expected_md5=hashlib.md5(
            payload,
            usedforsecurity=False,
        ).hexdigest(),
    )

    assert result["decision"] == "assembly_pass"
    assert result["approved_for_inventory"] is True
    assert result["approved_for_extraction"] is False
    assert result["archive"]["observed_sha256"] == hashlib.sha256(payload).hexdigest()
    assert output.read_bytes() == payload


def test_range_assembly_rejects_gaps_size_errors_and_existing_output(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first.part"
    second = tmp_path / "second.part"
    first.write_bytes(b"abc")
    second.write_bytes(b"def")
    digest = hashlib.md5(b"abcdef", usedforsecurity=False).hexdigest()

    with pytest.raises(ArchiveInventoryError, match="contiguous"):
        assemble_archive_ranges(
            [
                ArchiveRangePart(0, 2, first),
                ArchiveRangePart(4, 6, second),
            ],
            tmp_path / "gap.zip",
            expected_bytes=7,
            expected_md5=digest,
        )
    with pytest.raises(ArchiveInventoryError, match="size mismatch"):
        assemble_archive_ranges(
            [
                ArchiveRangePart(0, 1, first),
                ArchiveRangePart(2, 4, second),
            ],
            tmp_path / "size.zip",
            expected_bytes=5,
            expected_md5=digest,
        )
    output = tmp_path / "exists.zip"
    output.write_bytes(b"existing")
    with pytest.raises(ArchiveInventoryError, match="already exists"):
        assemble_archive_ranges(
            [
                ArchiveRangePart(0, 2, first),
                ArchiveRangePart(3, 5, second),
            ],
            output,
            expected_bytes=6,
            expected_md5=digest,
        )


def test_selective_member_extraction_requires_passed_inventory(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "dataset.zip"
    member_name = "dataset/Data/dataset.sql.gz"
    payload = b"gzip-container-fixture"
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(member_name, payload)
        archive.writestr("dataset/Data/ignored.log.gz", b"ignored")
    inventory = _inventory(archive_path)
    output = tmp_path / "selected.sql.gz"

    result = extract_verified_zip_member(
        archive_path,
        inventory,
        member_name,
        output,
        max_output_bytes=100,
    )

    assert result["decision"] == "selective_extraction_pass"
    assert result["approved_for_schema_audit"] is True
    assert result["approved_for_processing"] is False
    assert result["approved_for_training"] is False
    assert result["safety"]["selected_member_count"] == 1
    assert result["safety"]["other_member_read_count"] == 0
    assert result["safety"]["nested_member_decompression_count"] == 0
    assert result["member"]["output_sha256"] == hashlib.sha256(payload).hexdigest()
    assert output.read_bytes() == payload

    failed_inventory = dict(inventory)
    failed_inventory["decision"] = "inventory_fail"
    with pytest.raises(ArchiveInventoryError, match="must pass"):
        extract_verified_zip_member(
            archive_path,
            failed_inventory,
            member_name,
            tmp_path / "blocked.gz",
            max_output_bytes=100,
        )


def test_selective_member_extraction_rejects_unlisted_oversize_and_existing(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "dataset.zip"
    member_name = "dataset/Data/dataset.sql.gz"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(member_name, b"12345")
    inventory = _inventory(archive_path)

    with pytest.raises(ArchiveInventoryError, match="exactly once"):
        extract_verified_zip_member(
            archive_path,
            inventory,
            "dataset/Data/missing.sql.gz",
            tmp_path / "missing.gz",
            max_output_bytes=10,
        )
    with pytest.raises(ArchiveInventoryError, match="size limit"):
        extract_verified_zip_member(
            archive_path,
            inventory,
            member_name,
            tmp_path / "oversize.gz",
            max_output_bytes=4,
        )
    output = tmp_path / "exists.gz"
    output.write_bytes(b"existing")
    with pytest.raises(ArchiveInventoryError, match="already exists"):
        extract_verified_zip_member(
            archive_path,
            inventory,
            member_name,
            output,
            max_output_bytes=10,
        )
