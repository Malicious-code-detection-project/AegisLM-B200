"""Non-extracting inventory and integrity gate for acquired dataset archives."""

from __future__ import annotations

import hashlib
import os
import stat
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

ARCHIVE_INVENTORY_SCHEMA_VERSION = "aegislm.phase-f-archive-inventory.v1"
DEFAULT_FORBIDDEN_SUFFIXES = frozenset(
    {
        ".bin",
        ".class",
        ".com",
        ".dll",
        ".dylib",
        ".elf",
        ".exe",
        ".jar",
        ".msi",
        ".o",
        ".obj",
        ".out",
        ".pyc",
        ".so",
        ".wasm",
    }
)
NESTED_ARCHIVE_SUFFIXES = frozenset(
    {".7z", ".bz2", ".gz", ".rar", ".tar", ".tgz", ".xz", ".zip"}
)
_HASH_CHUNK_BYTES = 8 * 1024 * 1024


class ArchiveInventoryError(ValueError):
    """Raised when archive inventory inputs are invalid."""


@dataclass(frozen=True)
class ArchiveRangePart:
    """One inclusive byte range and the file containing exactly that range."""

    start: int
    end: int
    path: Path


def assemble_archive_ranges(
    parts: Iterable[ArchiveRangePart],
    output_path: Path,
    *,
    expected_bytes: int,
    expected_md5: str,
) -> dict[str, Any]:
    """Assemble contiguous range files and atomically publish a verified archive."""
    if expected_bytes <= 0:
        raise ArchiveInventoryError("expected_bytes must be positive")
    normalized_md5 = _validated_md5(expected_md5)
    ordered = sorted(parts, key=lambda part: part.start)
    if not ordered:
        raise ArchiveInventoryError("at least one range part is required")
    expected_start = 0
    resolved_output = output_path.resolve()
    part_records: list[dict[str, Any]] = []
    for part in ordered:
        if part.start != expected_start or part.end < part.start:
            raise ArchiveInventoryError(
                "range parts must be contiguous from byte zero without overlap"
            )
        if not part.path.is_file():
            raise ArchiveInventoryError(f"range part is missing: {part.path}")
        if part.path.resolve() == resolved_output:
            raise ArchiveInventoryError("output path cannot also be a range part")
        expected_part_bytes = part.end - part.start + 1
        observed_part_bytes = part.path.stat().st_size
        if observed_part_bytes != expected_part_bytes:
            raise ArchiveInventoryError(
                f"range part size mismatch: {part.path} "
                f"expected={expected_part_bytes} observed={observed_part_bytes}"
            )
        part_records.append(
            {
                "start": part.start,
                "end": part.end,
                "expected_bytes": expected_part_bytes,
                "observed_bytes": observed_part_bytes,
                "path": str(part.path.resolve()),
            }
        )
        expected_start = part.end + 1
    if expected_start != expected_bytes:
        raise ArchiveInventoryError(
            f"range coverage mismatch: expected end={expected_bytes - 1}, "
            f"observed end={expected_start - 1}"
        )
    if output_path.exists():
        raise ArchiveInventoryError(f"output path already exists: {output_path}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = output_path.with_name(f".{output_path.name}.assembling")
    if temporary_path.exists():
        raise ArchiveInventoryError(
            f"temporary assembly path already exists: {temporary_path}"
        )
    md5 = hashlib.md5(usedforsecurity=False)
    sha256 = hashlib.sha256()
    observed_bytes = 0
    try:
        with temporary_path.open("xb") as target:
            for part in ordered:
                with part.path.open("rb") as source:
                    while chunk := source.read(_HASH_CHUNK_BYTES):
                        target.write(chunk)
                        md5.update(chunk)
                        sha256.update(chunk)
                        observed_bytes += len(chunk)
            target.flush()
            os.fsync(target.fileno())
        observed_md5 = md5.hexdigest()
        if observed_bytes != expected_bytes:
            raise ArchiveInventoryError(
                f"assembled size mismatch: expected={expected_bytes} "
                f"observed={observed_bytes}"
            )
        if observed_md5 != normalized_md5:
            raise ArchiveInventoryError(
                f"assembled MD5 mismatch: expected={normalized_md5} "
                f"observed={observed_md5}"
            )
        temporary_path.replace(output_path)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise

    return {
        "schema_version": "aegislm.phase-f-range-assembly.v1",
        "archive": {
            "path": str(output_path.resolve()),
            "expected_bytes": expected_bytes,
            "observed_bytes": observed_bytes,
            "expected_md5": normalized_md5,
            "observed_md5": observed_md5,
            "observed_sha256": sha256.hexdigest(),
        },
        "parts": part_records,
        "decision": "assembly_pass",
        "approved_for_inventory": True,
        "approved_for_extraction": False,
        "approved_for_processing": False,
        "approved_for_training": False,
        "safety": {
            "member_payload_read_count": 0,
            "member_extraction_count": 0,
            "object_execution_count": 0,
        },
    }


def extract_verified_zip_member(
    archive_path: Path,
    inventory: dict[str, Any],
    member_name: str,
    output_path: Path,
    *,
    max_output_bytes: int,
) -> dict[str, Any]:
    """Selectively extract one inventoried member without unpacking nested content."""
    if max_output_bytes <= 0:
        raise ArchiveInventoryError("max_output_bytes must be positive")
    if inventory.get("decision") != "inventory_pass":
        raise ArchiveInventoryError("archive inventory must pass before extraction")
    if not inventory.get("approved_for_selective_member_review"):
        raise ArchiveInventoryError("selective member review is not approved")
    inventory_archive = inventory.get("archive")
    inventory_members = inventory.get("inventory", {}).get("members")
    if not isinstance(inventory_archive, dict) or not isinstance(
        inventory_members, list
    ):
        raise ArchiveInventoryError("inventory is missing archive or member metadata")
    if Path(str(inventory_archive.get("path"))).resolve() != archive_path.resolve():
        raise ArchiveInventoryError(
            "inventory archive path does not match input archive"
        )
    expected_archive_bytes = inventory_archive.get("observed_bytes")
    if (
        not isinstance(expected_archive_bytes, int)
        or archive_path.stat().st_size != expected_archive_bytes
    ):
        raise ArchiveInventoryError("archive size changed after inventory")
    matching_members = [
        record
        for record in inventory_members
        if isinstance(record, dict) and record.get("name") == member_name
    ]
    if len(matching_members) != 1:
        raise ArchiveInventoryError(
            "selected member must occur exactly once in inventory"
        )
    selected = matching_members[0]
    if selected.get("is_directory"):
        raise ArchiveInventoryError("selected member cannot be a directory")
    expected_output_bytes = selected.get("uncompressed_bytes")
    if (
        not isinstance(expected_output_bytes, int)
        or expected_output_bytes < 0
        or expected_output_bytes > max_output_bytes
    ):
        raise ArchiveInventoryError("selected member exceeds extraction size limit")
    if output_path.exists():
        raise ArchiveInventoryError(f"output path already exists: {output_path}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = output_path.with_name(f".{output_path.name}.extracting")
    if temporary_path.exists():
        raise ArchiveInventoryError(
            f"temporary extraction path already exists: {temporary_path}"
        )
    sha256 = hashlib.sha256()
    observed_output_bytes = 0
    try:
        with (
            zipfile.ZipFile(archive_path, "r") as archive,
            archive.open(member_name, "r") as source,
            temporary_path.open("xb") as target,
        ):
            while chunk := source.read(_HASH_CHUNK_BYTES):
                target.write(chunk)
                sha256.update(chunk)
                observed_output_bytes += len(chunk)
                if observed_output_bytes > max_output_bytes:
                    raise ArchiveInventoryError(
                        "selected member exceeded extraction size limit"
                    )
            target.flush()
            os.fsync(target.fileno())
        if observed_output_bytes != expected_output_bytes:
            raise ArchiveInventoryError(
                f"selected member size mismatch: expected={expected_output_bytes} "
                f"observed={observed_output_bytes}"
            )
        temporary_path.replace(output_path)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise

    return {
        "schema_version": "aegislm.phase-f-selective-member-extraction.v1",
        "archive": {
            "path": str(archive_path.resolve()),
            "observed_bytes": expected_archive_bytes,
            "observed_sha256": str(inventory_archive.get("observed_sha256") or ""),
        },
        "member": {
            "name": member_name,
            "compressed_bytes": selected.get("compressed_bytes"),
            "expected_output_bytes": expected_output_bytes,
            "observed_output_bytes": observed_output_bytes,
            "output_path": str(output_path.resolve()),
            "output_sha256": sha256.hexdigest(),
        },
        "decision": "selective_extraction_pass",
        "approved_for_schema_audit": True,
        "approved_for_processing": False,
        "approved_for_training": False,
        "safety": {
            "selected_member_count": 1,
            "other_member_read_count": 0,
            "nested_member_decompression_count": 0,
            "object_execution_count": 0,
        },
    }


def inventory_zip_archive(
    archive_path: Path,
    *,
    expected_bytes: int,
    max_uncompressed_bytes: int,
    expected_md5: str | None = None,
    expected_sha256: str | None = None,
    max_compression_ratio: float = 100.0,
    forbidden_suffixes: Iterable[str] = DEFAULT_FORBIDDEN_SUFFIXES,
) -> dict[str, Any]:
    """Hash and inspect a ZIP archive without reading or extracting member payloads."""
    if expected_bytes <= 0:
        raise ArchiveInventoryError("expected_bytes must be positive")
    if max_uncompressed_bytes <= 0:
        raise ArchiveInventoryError("max_uncompressed_bytes must be positive")
    if max_compression_ratio < 1:
        raise ArchiveInventoryError("max_compression_ratio must be at least 1")
    if expected_md5 is None and expected_sha256 is None:
        raise ArchiveInventoryError(
            "at least one expected archive checksum is required"
        )
    normalized_md5 = _validated_md5(expected_md5) if expected_md5 is not None else None
    normalized_sha256 = (
        _validated_sha256(expected_sha256) if expected_sha256 is not None else None
    )
    suffixes = {
        suffix.lower() if suffix.startswith(".") else f".{suffix.lower()}"
        for suffix in forbidden_suffixes
    }
    if not archive_path.is_file():
        raise ArchiveInventoryError(f"archive is not a regular file: {archive_path}")

    observed_bytes = archive_path.stat().st_size
    observed_md5, observed_sha256 = _hash_file(archive_path)
    unsafe_paths: list[str] = []
    encrypted_members: list[str] = []
    symlink_members: list[str] = []
    forbidden_members: list[str] = []
    nested_archive_members: list[str] = []
    member_records: list[dict[str, Any]] = []
    member_suffix_counts: dict[str, int] = {}
    total_compressed_bytes = 0
    total_uncompressed_bytes = 0
    member_count = 0
    bad_zip = False
    bad_zip_reason: str | None = None

    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            for info in archive.infolist():
                member_count += 1
                total_compressed_bytes += info.compress_size
                total_uncompressed_bytes += info.file_size
                member_name = info.filename
                if _unsafe_member_path(member_name):
                    unsafe_paths.append(member_name)
                if info.flag_bits & 0x1:
                    encrypted_members.append(member_name)
                unix_mode = (info.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(unix_mode):
                    symlink_members.append(member_name)
                suffix = PurePosixPath(member_name.replace("\\", "/")).suffix.lower()
                if suffix:
                    member_suffix_counts[suffix] = (
                        member_suffix_counts.get(suffix, 0) + 1
                    )
                if not info.is_dir() and suffix in suffixes:
                    forbidden_members.append(member_name)
                if not info.is_dir() and suffix in NESTED_ARCHIVE_SUFFIXES:
                    nested_archive_members.append(member_name)
                member_records.append(
                    {
                        "name": member_name,
                        "is_directory": info.is_dir(),
                        "suffix": suffix,
                        "compressed_bytes": info.compress_size,
                        "uncompressed_bytes": info.file_size,
                    }
                )
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        bad_zip = True
        bad_zip_reason = f"{type(exc).__name__}: {exc}"

    compression_ratio = (
        total_uncompressed_bytes / max(total_compressed_bytes, 1)
        if member_count
        else 0.0
    )
    checks = {
        "archive_size_matches": observed_bytes == expected_bytes,
        "zip_central_directory_readable": not bad_zip,
        "archive_has_members": member_count > 0,
        "unsafe_member_paths_absent": not unsafe_paths,
        "encrypted_members_absent": not encrypted_members,
        "symlink_members_absent": not symlink_members,
        "executable_members_absent": not forbidden_members,
        "uncompressed_size_within_limit": (
            total_uncompressed_bytes <= max_uncompressed_bytes
        ),
        "compression_ratio_within_limit": compression_ratio <= max_compression_ratio,
    }
    if normalized_md5 is not None:
        checks["upstream_md5_matches"] = observed_md5 == normalized_md5
    if normalized_sha256 is not None:
        checks["upstream_sha256_matches"] = observed_sha256 == normalized_sha256
    passed = all(checks.values())
    return {
        "schema_version": ARCHIVE_INVENTORY_SCHEMA_VERSION,
        "archive": {
            "path": str(archive_path.resolve()),
            "expected_bytes": expected_bytes,
            "observed_bytes": observed_bytes,
            "expected_md5": normalized_md5,
            "expected_sha256": normalized_sha256,
            "observed_md5": observed_md5,
            "observed_sha256": observed_sha256,
        },
        "inventory": {
            "member_count": member_count,
            "total_compressed_bytes": total_compressed_bytes,
            "total_uncompressed_bytes": total_uncompressed_bytes,
            "compression_ratio": compression_ratio,
            "member_suffix_counts": dict(sorted(member_suffix_counts.items())),
            "members": member_records,
            "nested_archive_members": nested_archive_members,
            "unsafe_member_paths": unsafe_paths,
            "encrypted_members": encrypted_members,
            "symlink_members": symlink_members,
            "forbidden_executable_members": forbidden_members,
            "bad_zip_reason": bad_zip_reason,
        },
        "limits": {
            "max_uncompressed_bytes": max_uncompressed_bytes,
            "max_compression_ratio": max_compression_ratio,
            "forbidden_suffixes": sorted(suffixes),
        },
        "checks": checks,
        "failure_reasons": sorted(name for name, value in checks.items() if not value),
        "decision": "inventory_pass" if passed else "inventory_fail",
        "approved_for_extraction": False,
        "approved_for_selective_member_review": passed,
        "approved_for_processing": False,
        "approved_for_training": False,
        "safety": {
            "member_payload_read_count": 0,
            "member_extraction_count": 0,
            "object_execution_count": 0,
        },
    }


def _hash_file(path: Path) -> tuple[str, str]:
    md5 = hashlib.md5(usedforsecurity=False)
    sha256 = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(_HASH_CHUNK_BYTES):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()


def _validated_md5(value: str) -> str:
    normalized = value.removeprefix("md5:").strip().lower()
    if len(normalized) != 32 or any(
        char not in "0123456789abcdef" for char in normalized
    ):
        raise ArchiveInventoryError("expected_md5 must be a 32-character hex digest")
    return normalized


def _validated_sha256(value: str) -> str:
    normalized = value.removeprefix("sha256:").strip().lower()
    if len(normalized) != 64 or any(
        char not in "0123456789abcdef" for char in normalized
    ):
        raise ArchiveInventoryError("expected_sha256 must be a 64-character hex digest")
    return normalized


def _unsafe_member_path(member_name: str) -> bool:
    normalized = member_name.replace("\\", "/")
    path = PurePosixPath(normalized)
    return (
        path.is_absolute()
        or any(part == ".." for part in path.parts)
        or (len(normalized) >= 2 and normalized[1] == ":")
        or normalized.startswith("//")
    )
