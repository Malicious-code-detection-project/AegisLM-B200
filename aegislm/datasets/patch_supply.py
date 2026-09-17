"""Metadata-only preflight for patch-localized CWE label supplies."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse

PATCH_SUPPLY_AUDIT_SCHEMA_VERSION = "aegislm.phase-f-patch-label-supply-preflight.v1"
PATCH_SUPPLY_REQUIRED_FIELDS = (
    "cve_id",
    "cwe_ids",
    "repository",
    "fix_commit",
    "function_before",
    "function_after",
    "localized_diff",
)
PATCH_SUPPLY_FORBIDDEN_COMPONENTS = (
    "binary",
    "compiled_object",
    "executable",
    "graph_archive",
    "malware_payload",
    "poc",
    "reproducer",
)


class PatchSupplyError(ValueError):
    """Raised when a patch-supply registry violates the preflight contract."""


def audit_patch_label_supply(
    registry: Mapping[str, Any],
    *,
    available_bytes: int,
) -> dict[str, Any]:
    """Evaluate immutable metadata and storage gates without downloading data."""
    if available_bytes <= 0:
        raise PatchSupplyError("available_bytes must be positive")
    multiplier = float(registry["storage"]["minimum_archive_multiplier"])
    if multiplier < 1:
        raise PatchSupplyError("minimum_archive_multiplier must be at least 1")
    sources = registry.get("sources")
    if not isinstance(sources, list) or not sources:
        raise PatchSupplyError("registry must contain at least one source")

    audited: list[dict[str, Any]] = []
    ready_sources: list[str] = []
    for raw_source in sources:
        if not isinstance(raw_source, Mapping):
            raise PatchSupplyError("each source must be an object")
        source = dict(raw_source)
        source_id = _required_text(source, "source_id")
        artifact = source.get("artifact")
        licenses = source.get("licenses")
        field_evidence = source.get("required_field_evidence")
        if not isinstance(artifact, Mapping):
            raise PatchSupplyError(f"{source_id}: artifact must be an object")
        if not isinstance(licenses, Mapping):
            raise PatchSupplyError(f"{source_id}: licenses must be an object")
        if not isinstance(field_evidence, Mapping):
            raise PatchSupplyError(
                f"{source_id}: required_field_evidence must be an object"
            )

        components = {
            str(value).strip().lower()
            for value in source.get("selected_components", [])
        }
        forbidden_components = sorted(
            component
            for component in components
            if any(marker in component for marker in PATCH_SUPPLY_FORBIDDEN_COMPONENTS)
        )
        archive_bytes = artifact.get("archive_bytes")
        size_known = isinstance(archive_bytes, int) and archive_bytes > 0
        required_storage_bytes: int | None = None
        if isinstance(archive_bytes, int) and archive_bytes > 0:
            required_storage_bytes = int(archive_bytes * multiplier)
        storage_pass = bool(
            required_storage_bytes is not None
            and available_bytes >= required_storage_bytes
        )
        artifact_url = str(artifact.get("url") or "")
        artifact_url_https = _https_url(artifact_url)
        checksum = str(artifact.get("upstream_checksum") or "")
        checksum_available = checksum.startswith(("md5:", "sha256:"))
        dataset_license = str(licenses.get("dataset") or "").strip()
        required_fields = {
            field: bool(field_evidence.get(field))
            for field in PATCH_SUPPLY_REQUIRED_FIELDS
        }

        checks = {
            "dataset_role_is_label_supply": source.get("dataset_role")
            == "patch_localized_cwe_label_supply",
            "immutable_release": bool(source.get("immutable_release")),
            "artifact_url_https": artifact_url_https,
            "archive_size_known": size_known,
            "upstream_checksum_available": checksum_available,
            "post_download_sha256_required": bool(
                artifact.get("post_download_sha256_required")
            ),
            "dataset_license_known": bool(dataset_license)
            and dataset_license.lower() not in {"unknown", "unverified"},
            "required_fields_present": all(required_fields.values()),
            "selected_components_payload_free": not forbidden_components,
            "storage_headroom": storage_pass,
        }
        ready = all(checks.values())
        if ready:
            ready_sources.append(source_id)
        audited.append(
            {
                "source_id": source_id,
                "version": str(source.get("version") or ""),
                "dataset_role": str(source.get("dataset_role") or ""),
                "checks": checks,
                "required_field_evidence": required_fields,
                "selected_components": sorted(components),
                "forbidden_components": forbidden_components,
                "storage": {
                    "archive_bytes": archive_bytes if size_known else None,
                    "required_bytes": required_storage_bytes,
                    "available_bytes": available_bytes,
                    "minimum_archive_multiplier": multiplier,
                },
                "decision": "acquisition_ready" if ready else "metadata_hold",
                "approved_for_training": False,
                "failure_reasons": sorted(
                    name for name, passed in checks.items() if not passed
                ),
            }
        )

    return {
        "schema_version": PATCH_SUPPLY_AUDIT_SCHEMA_VERSION,
        "profile": str(registry.get("profile") or ""),
        "observed_at": str(registry.get("observed_at") or ""),
        "storage": {
            "available_bytes": available_bytes,
            "minimum_archive_multiplier": multiplier,
        },
        "safety": {
            "metadata_only": True,
            "archive_download_count": 0,
            "source_code_read_count": 0,
            "raw_payload_read_count": 0,
            "poc_read_count": 0,
            "reproducer_execution_count": 0,
            "object_execution_count": 0,
            "docker_image_pull_count": 0,
        },
        "ready_source_ids": ready_sources,
        "sources": audited,
        "approved_for_training": False,
        "decision": (
            "acquisition_candidate_ready"
            if ready_sources
            else "no_acquisition_candidate"
        ),
    }


def _required_text(source: Mapping[str, Any], field: str) -> str:
    value = str(source.get(field) or "").strip()
    if not value:
        raise PatchSupplyError(f"source is missing {field}")
    return value


def _https_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme == "https" and bool(parsed.hostname)
