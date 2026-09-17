"""Metadata-only preflight for source-binary representation alignment supplies."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse

ALIGNMENT_SUPPLY_AUDIT_SCHEMA_VERSION = (
    "aegislm.phase-f-binary-alignment-supply-preflight.v1"
)
_REVISION_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_CHECKSUM_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_FORBIDDEN_COMPONENT_MARKERS = {
    "executable",
    "raw_binary",
    "malware",
    "poc",
    "reproducer",
}


class AlignmentSupplyError(ValueError):
    """Raised when an alignment-supply registry violates the contract."""


def audit_alignment_supply(
    registry: Mapping[str, Any],
    *,
    available_bytes: int,
) -> dict[str, Any]:
    """Audit fixed artifacts and role boundaries without downloading payloads."""
    if available_bytes <= 0:
        raise AlignmentSupplyError("available_bytes must be positive")
    multiplier = float(registry["storage"]["minimum_artifact_multiplier"])
    if multiplier < 1:
        raise AlignmentSupplyError("minimum_artifact_multiplier must be at least 1")
    sources = registry.get("sources")
    if not isinstance(sources, list) or not sources:
        raise AlignmentSupplyError("registry must contain at least one source")

    audited: list[dict[str, Any]] = []
    acquisition_ready: list[str] = []
    for raw_source in sources:
        if not isinstance(raw_source, Mapping):
            raise AlignmentSupplyError("each source must be an object")
        source = dict(raw_source)
        source_id = _required_text(source, "source_id")
        artifact = source.get("artifact")
        fields = source.get("field_evidence")
        if not isinstance(artifact, Mapping):
            raise AlignmentSupplyError(f"{source_id}: artifact must be an object")
        if not isinstance(fields, Mapping):
            raise AlignmentSupplyError(f"{source_id}: field_evidence must be an object")

        revision = str(source.get("revision") or "")
        artifact_url = str(artifact.get("url") or "")
        artifact_bytes = artifact.get("bytes")
        artifact_sha256 = str(artifact.get("sha256") or "")
        selected_components = {
            str(component).strip().lower()
            for component in source.get("selected_components", [])
        }
        forbidden_components = sorted(
            component
            for component in selected_components
            if any(marker in component for marker in _FORBIDDEN_COMPONENT_MARKERS)
        )
        required_fields = [str(field) for field in source.get("required_fields", [])]
        missing_fields = sorted(
            field for field in required_fields if not bool(fields.get(field))
        )
        size_known = isinstance(artifact_bytes, int) and artifact_bytes > 0
        required_bytes: int | None = None
        if isinstance(artifact_bytes, int) and artifact_bytes > 0:
            required_bytes = int(artifact_bytes * multiplier)
        storage_pass = bool(
            required_bytes is not None and available_bytes >= required_bytes
        )
        license_name = str(source.get("dataset_license") or "").strip()
        license_declared = bool(license_name) and license_name.lower() not in {
            "unknown",
            "unverified",
        }
        requested_scope = str(source.get("requested_scope") or "")
        acquire_now = bool(source.get("acquire_now"))
        checks = {
            "immutable_revision": bool(_REVISION_PATTERN.fullmatch(revision)),
            "public_and_ungated": source.get("public") is True
            and source.get("gated") is False,
            "artifact_url_https": _https_url(artifact_url),
            "artifact_url_pins_revision": revision in artifact_url,
            "artifact_size_known": size_known,
            "artifact_sha256_known": bool(
                _CHECKSUM_PATTERN.fullmatch(f"sha256:{artifact_sha256}")
            ),
            "dataset_license_declared": license_declared,
            "required_fields_present": not missing_fields,
            "selected_components_payload_free": not forbidden_components,
            "storage_headroom": storage_pass,
            "training_not_requested": source.get("training_requested") is False,
        }
        metadata_pass = all(checks.values())
        if metadata_pass and acquire_now:
            decision = "acquisition_ready"
            acquisition_ready.append(source_id)
        elif metadata_pass and requested_scope == "reserved_benchmark":
            decision = "benchmark_reserved"
        elif metadata_pass:
            decision = "metadata_ready_not_selected"
        else:
            decision = "metadata_hold"
        audited.append(
            {
                "source_id": source_id,
                "dataset_role": str(source.get("dataset_role") or ""),
                "requested_scope": requested_scope,
                "revision": revision,
                "dataset_license": license_name,
                "checks": checks,
                "required_fields": required_fields,
                "missing_fields": missing_fields,
                "selected_components": sorted(selected_components),
                "forbidden_components": forbidden_components,
                "storage": {
                    "artifact_bytes": artifact_bytes if size_known else None,
                    "required_bytes": required_bytes,
                    "available_bytes": available_bytes,
                    "minimum_artifact_multiplier": multiplier,
                },
                "decision": decision,
                "failure_reasons": sorted(
                    name for name, passed in checks.items() if not passed
                ),
                "approved_for_download": decision == "acquisition_ready",
                "approved_for_schema_inventory": decision == "acquisition_ready",
                "approved_for_code_execution": False,
                "approved_for_training": False,
            }
        )

    return {
        "schema_version": ALIGNMENT_SUPPLY_AUDIT_SCHEMA_VERSION,
        "profile": str(registry.get("profile") or ""),
        "observed_at": str(registry.get("observed_at") or ""),
        "storage": {
            "available_bytes": available_bytes,
            "minimum_artifact_multiplier": multiplier,
        },
        "acquisition_ready_source_ids": acquisition_ready,
        "sources": audited,
        "decision": (
            "single_alignment_candidate_ready"
            if len(acquisition_ready) == 1
            else "alignment_preflight_requires_decision"
        ),
        "approved_for_training": False,
        "safety": {
            "metadata_only": True,
            "artifact_download_count": 0,
            "source_code_read_count": 0,
            "assembly_read_count": 0,
            "raw_binary_read_count": 0,
            "executable_execution_count": 0,
            "test_execution_count": 0,
            "docker_pull_count": 0,
        },
    }


def _required_text(source: Mapping[str, Any], field: str) -> str:
    value = str(source.get(field) or "").strip()
    if not value:
        raise AlignmentSupplyError(f"source is missing {field}")
    return value


def _https_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme == "https" and bool(parsed.hostname)
