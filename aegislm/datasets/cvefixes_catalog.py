"""Deterministic metadata-only feasibility catalog for CVEfixes."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Any

from aegislm.datasets.cvefixes_supply import (
    CVEFIXES_SUPPLY_AUDIT_SCHEMA_VERSION,
)

CVEFIXES_FEASIBILITY_CATALOG_SCHEMA_VERSION = (
    "aegislm.phase-f-cvefixes-feasibility-catalog.v1"
)
_FORBIDDEN_PAYLOAD_KEYS = {
    "code",
    "code_after",
    "code_before",
    "diff",
    "diff_parsed",
    "patch",
    "payload",
}
_ACTIONABLE_CWE_PATTERN = re.compile(r"^CWE-[1-9][0-9]*$")


class CvefixesCatalogError(ValueError):
    """Raised when the feasibility catalog cannot be built safely."""


def build_cvefixes_feasibility_catalog(
    database_path: Path,
    supply_audit_path: Path,
    *,
    selection_seed: int = 20_260_731,
    sample_size: int = 200,
    language_quotas: dict[str, int] | None = None,
    max_per_cwe: int = 20,
) -> dict[str, Any]:
    """Select a group-separated metadata catalog without reading code or diffs."""
    quotas = language_quotas or {"C": 150, "C++": 50}
    _validate_inputs(
        database_path,
        supply_audit_path,
        selection_seed=selection_seed,
        sample_size=sample_size,
        language_quotas=quotas,
        max_per_cwe=max_per_cwe,
    )
    supply_audit = json.loads(supply_audit_path.read_text(encoding="utf-8"))
    _validate_supply_audit(supply_audit)

    connection = _open_read_only(database_path)
    try:
        candidates = _candidate_metadata(connection)
    finally:
        connection.close()

    selected = _select_candidates(
        candidates,
        selection_seed=selection_seed,
        language_quotas=quotas,
        max_per_cwe=max_per_cwe,
    )
    language_counts = Counter(str(row["programming_language"]) for row in selected)
    cwe_counts = Counter(str(row["target_cwe"]) for row in selected)
    candidate_ids = [str(row["candidate_id"]) for row in selected]
    group_ids = [str(row["commit_group_id"]) for row in selected]
    payload_key_hits = sorted(_find_forbidden_payload_keys(selected))
    checks = {
        "prior_supply_inventory_pass": True,
        "selected_count_exact": len(selected) == sample_size,
        "language_quotas_exact": dict(sorted(language_counts.items()))
        == dict(sorted(quotas.items())),
        "candidate_ids_unique": len(candidate_ids) == len(set(candidate_ids)),
        "commit_groups_unique": len(group_ids) == len(set(group_ids)),
        "cwe_cap_respected": max(cwe_counts.values(), default=0) <= max_per_cwe,
        "target_cwes_actionable": all(
            _ACTIONABLE_CWE_PATTERN.fullmatch(cwe) for cwe in cwe_counts
        ),
        "raw_payload_keys_absent": not payload_key_hits,
        "repository_license_verified": False,
        "code_change_verified": False,
    }
    gate_checks = {
        key: value
        for key, value in checks.items()
        if key not in {"repository_license_verified", "code_change_verified"}
    }
    passed = all(gate_checks.values())
    return {
        "schema_version": CVEFIXES_FEASIBILITY_CATALOG_SCHEMA_VERSION,
        "profile": "phase-f-cvefixes-feasibility-catalog-v1",
        "dataset": {
            "name": "CVEfixes",
            "version": "1.0.8",
            "record_id": "13118970",
            "database_license": "CC-BY-4.0",
            "collector_license": "MIT",
            "repository_code_license_status": "unverified",
        },
        "selection": {
            "seed": selection_seed,
            "sample_size": sample_size,
            "language_quotas": dict(sorted(quotas.items())),
            "max_per_cwe": max_per_cwe,
            "max_per_commit_group": 1,
            "strategy": "deterministic_hash_rank_with_group_and_cwe_caps",
        },
        "source_artifacts": {
            "database_bytes": database_path.stat().st_size,
            "supply_audit_sha256": _sha256_file(supply_audit_path),
        },
        "candidate_pool": {
            "rows": len(candidates),
            "language_counts": dict(
                sorted(
                    Counter(
                        str(row["programming_language"]) for row in candidates
                    ).items()
                )
            ),
            "distinct_cwes": len({str(row["target_cwe"]) for row in candidates}),
        },
        "selected_summary": {
            "rows": len(selected),
            "language_counts": dict(sorted(language_counts.items())),
            "cwe_counts": dict(sorted(cwe_counts.items())),
            "distinct_cwes": len(cwe_counts),
            "distinct_commit_groups": len(set(group_ids)),
        },
        "candidates": selected,
        "checks": checks,
        "failure_reasons": sorted(
            key for key, value in gate_checks.items() if not value
        ),
        "forbidden_payload_key_hits": payload_key_hits,
        "decision": "manual_evidence_gate_ready" if passed else "catalog_fail",
        "approved_for_metadata_catalog": passed,
        "approved_for_selective_review_materialization": passed,
        "approved_for_bulk_materialization": False,
        "approved_for_processing": False,
        "approved_for_training": False,
        "safety": {
            "database_write_count": 0,
            "raw_code_read_count": 0,
            "raw_diff_read_count": 0,
            "raw_payload_return_count": 0,
            "source_code_execution_count": 0,
            "object_execution_count": 0,
        },
    }


def _validate_inputs(
    database_path: Path,
    supply_audit_path: Path,
    *,
    selection_seed: int,
    sample_size: int,
    language_quotas: dict[str, int],
    max_per_cwe: int,
) -> None:
    if not database_path.is_file():
        raise CvefixesCatalogError(f"database is not a regular file: {database_path}")
    if not supply_audit_path.is_file():
        raise CvefixesCatalogError(
            f"supply audit is not a regular file: {supply_audit_path}"
        )
    if selection_seed < 0:
        raise CvefixesCatalogError("selection_seed must be non-negative")
    if sample_size <= 0 or max_per_cwe <= 0:
        raise CvefixesCatalogError("sample_size and max_per_cwe must be positive")
    if set(language_quotas) != {"C", "C++"}:
        raise CvefixesCatalogError("language_quotas must contain C and C++")
    if any(value <= 0 for value in language_quotas.values()):
        raise CvefixesCatalogError("language quotas must be positive")
    if sum(language_quotas.values()) != sample_size:
        raise CvefixesCatalogError("language quota sum must equal sample_size")


def _validate_supply_audit(audit: dict[str, Any]) -> None:
    if audit.get("schema_version") != CVEFIXES_SUPPLY_AUDIT_SCHEMA_VERSION:
        raise CvefixesCatalogError("unsupported supply audit schema")
    if audit.get("decision") != "supply_inventory_pass":
        raise CvefixesCatalogError("supply inventory has not passed")
    if audit.get("approved_for_metadata_catalog") is not True:
        raise CvefixesCatalogError("metadata catalog is not approved")
    safety = audit.get("safety", {})
    for key in (
        "database_write_count",
        "raw_code_return_count",
        "raw_diff_return_count",
        "source_code_execution_count",
        "object_execution_count",
    ):
        if safety.get(key) != 0:
            raise CvefixesCatalogError(f"unsafe supply audit count: {key}")


def _open_read_only(database_path: Path) -> sqlite3.Connection:
    uri = f"{database_path.resolve().as_uri()}?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True)
    connection.execute("PRAGMA query_only=ON")
    connection.execute("PRAGMA trusted_schema=OFF")
    return connection


def _candidate_metadata(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    file_changes = {
        int(file_change_id): {
            "commit_hash": str(commit_hash),
            "programming_language": str(language or ""),
            "change_type": str(change_type or ""),
            "has_file_diff": bool(has_file_diff),
        }
        for file_change_id, commit_hash, language, change_type, has_file_diff in (
            connection.execute(
                "SELECT file_change_id, hash, programming_language, change_type, "
                "CASE WHEN diff IS NOT NULL AND length(diff) > 0 THEN 1 ELSE 0 END "
                "FROM file_change"
            )
        )
    }
    repositories = {
        str(commit_hash): str(repo_url or "")
        for commit_hash, repo_url in connection.execute(
            "SELECT hash, repo_url FROM commits"
        )
    }
    cves_by_commit: dict[str, set[str]] = {}
    for commit_hash, cve_id in connection.execute("SELECT hash, cve_id FROM fixes"):
        cves_by_commit.setdefault(str(commit_hash), set()).add(str(cve_id))
    cwes_by_cve: dict[str, set[str]] = {}
    for cve_id, cwe_id in connection.execute(
        "SELECT cve_id, cwe_id FROM cwe_classification"
    ):
        cwes_by_cve.setdefault(str(cve_id), set()).add(str(cwe_id))

    method_groups: dict[tuple[int, str, str], dict[str, list[int] | bool]] = {}
    method_rows = connection.execute(
        "SELECT method_change_id, file_change_id, name, signature, "
        "before_change, "
        "CASE WHEN code IS NOT NULL AND length(code) > 0 THEN 1 ELSE 0 END "
        "FROM method_change "
        "WHERE name IS NOT NULL AND length(name) > 0 "
        "AND signature IS NOT NULL AND length(signature) > 0"
    )
    for (
        method_id,
        file_change_id,
        name,
        signature,
        before_change,
        has_code,
    ) in method_rows:
        key = (int(file_change_id), str(name), str(signature))
        group = method_groups.setdefault(
            key, {"before_ids": [], "after_ids": [], "both_code": True}
        )
        before = str(before_change).lower() in {"1", "true"}
        id_key = "before_ids" if before else "after_ids"
        ids = group[id_key]
        assert isinstance(ids, list)
        ids.append(int(method_id))
        group["both_code"] = bool(group["both_code"]) and bool(has_code)

    candidates: list[dict[str, Any]] = []
    for (file_change_id, name, signature), group in method_groups.items():
        before_ids = group["before_ids"]
        after_ids = group["after_ids"]
        assert isinstance(before_ids, list)
        assert isinstance(after_ids, list)
        if len(before_ids) != 1 or len(after_ids) != 1 or not bool(group["both_code"]):
            continue
        file_record = file_changes.get(file_change_id)
        if file_record is None:
            continue
        language = str(file_record["programming_language"])
        change_type = str(file_record["change_type"]).rsplit(".", 1)[-1].upper()
        if (
            language not in {"C", "C++"}
            or change_type != "MODIFY"
            or not bool(file_record["has_file_diff"])
        ):
            continue
        commit_hash = str(file_record["commit_hash"])
        cve_ids = sorted(cves_by_commit.get(commit_hash, set()))
        cwes = {cwe for cve_id in cve_ids for cwe in cwes_by_cve.get(cve_id, set())}
        if len(cwes) != 1:
            continue
        target_cwe = next(iter(cwes))
        if _ACTIONABLE_CWE_PATTERN.fullmatch(target_cwe) is None:
            continue
        repository_url = repositories.get(commit_hash, "")
        if not repository_url:
            continue
        method_identity = _sha256_text(
            f"{repository_url}\0{commit_hash}\0{file_change_id}\0{name}\0{signature}"
        )
        commit_group_id = _sha256_text(f"{repository_url}\0{commit_hash}")
        candidates.append(
            {
                "candidate_id": f"cvefixes-{method_identity[:16]}",
                "commit_group_id": commit_group_id,
                "repository_url": repository_url,
                "commit_hash": commit_hash,
                "file_change_id": file_change_id,
                "before_method_change_id": before_ids[0],
                "after_method_change_id": after_ids[0],
                "method_identity_sha256": method_identity,
                "programming_language": language,
                "cve_ids": cve_ids,
                "target_cwe": target_cwe,
                "repository_license_status": "unverified",
                "disposition": "quarantine_pending_manual_evidence",
            }
        )
    return candidates


def _select_candidates(
    candidates: list[dict[str, Any]],
    *,
    selection_seed: int,
    language_quotas: dict[str, int],
    max_per_cwe: int,
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    used_groups: set[str] = set()
    cwe_counts: Counter[str] = Counter()
    for language, quota in sorted(language_quotas.items()):
        ranked = sorted(
            (row for row in candidates if row["programming_language"] == language),
            key=lambda row: _sha256_text(f"{selection_seed}\0{row['candidate_id']}"),
        )
        for row in ranked:
            group_id = str(row["commit_group_id"])
            cwe = str(row["target_cwe"])
            if group_id in used_groups or cwe_counts[cwe] >= max_per_cwe:
                continue
            selected.append(row)
            used_groups.add(group_id)
            cwe_counts[cwe] += 1
            if (
                sum(item["programming_language"] == language for item in selected)
                == quota
            ):
                break
        selected_for_language = sum(
            item["programming_language"] == language for item in selected
        )
        if selected_for_language != quota:
            raise CvefixesCatalogError(
                f"unable to satisfy {language} quota: {selected_for_language}/{quota}"
            )
    return sorted(selected, key=lambda row: str(row["candidate_id"]))


def _find_forbidden_payload_keys(value: Any) -> set[str]:
    hits: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower() in _FORBIDDEN_PAYLOAD_KEYS:
                hits.add(str(key))
            hits.update(_find_forbidden_payload_keys(child))
    elif isinstance(value, list):
        for child in value:
            hits.update(_find_forbidden_payload_keys(child))
    return hits


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
