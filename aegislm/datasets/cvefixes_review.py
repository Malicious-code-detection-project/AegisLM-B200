"""Selective, non-executing CVEfixes function-pair review materialization."""

from __future__ import annotations

import difflib
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from aegislm.datasets.cvefixes_catalog import (
    CVEFIXES_FEASIBILITY_CATALOG_SCHEMA_VERSION,
)

CVEFIXES_REVIEW_QUEUE_SCHEMA_VERSION = "aegislm.phase-f-cvefixes-manual-review-queue.v1"


class CvefixesReviewError(ValueError):
    """Raised when selective review materialization is unsafe or incomplete."""


def materialize_cvefixes_review_queue(
    database_path: Path,
    catalog_path: Path,
    *,
    max_code_chars: int = 100_000,
    max_diff_chars: int = 100_000,
) -> dict[str, Any]:
    """Read only the selected function pairs and create a non-model review queue."""
    if not database_path.is_file():
        raise CvefixesReviewError(f"database is not a regular file: {database_path}")
    if not catalog_path.is_file():
        raise CvefixesReviewError(f"catalog is not a regular file: {catalog_path}")
    if max_code_chars <= 0 or max_diff_chars <= 0:
        raise CvefixesReviewError("size limits must be positive")
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    _validate_catalog(catalog)

    connection = _open_read_only(database_path)
    try:
        methods = _selected_method_rows(connection, catalog["candidates"])
        records = [
            _materialize_candidate(
                methods,
                candidate,
                max_code_chars=max_code_chars,
                max_diff_chars=max_diff_chars,
            )
            for candidate in catalog["candidates"]
        ]
    finally:
        connection.close()

    error_records = [record for record in records if record["materialization_errors"]]
    identical_pairs = [
        record["candidate_id"]
        for record in records
        if record["before_code_sha256"] == record["after_code_sha256"]
    ]
    checks = {
        "catalog_gate_pass": True,
        "selected_count_exact": len(records)
        == int(catalog["selection"]["sample_size"]),
        "all_records_materialized": not error_records,
        "before_after_code_changed": not identical_pairs,
        "operator_decisions_complete": False,
        "repository_license_verified": False,
    }
    automatic_checks = {
        key: value
        for key, value in checks.items()
        if key
        not in {
            "operator_decisions_complete",
            "repository_license_verified",
        }
    }
    passed = all(automatic_checks.values())
    return {
        "schema_version": CVEFIXES_REVIEW_QUEUE_SCHEMA_VERSION,
        "profile": "phase-f-cvefixes-manual-review-v1",
        "model_visible": False,
        "source_artifacts": {
            "catalog_sha256": _sha256_file(catalog_path),
            "database_bytes": database_path.stat().st_size,
        },
        "limits": {
            "max_code_chars": max_code_chars,
            "max_diff_chars": max_diff_chars,
        },
        "summary": {
            "requested_records": int(catalog["selection"]["sample_size"]),
            "materialized_records": len(records) - len(error_records),
            "error_records": len(error_records),
            "identical_before_after_pairs": len(identical_pairs),
            "unfinished_operator_decisions": len(records),
        },
        "checks": checks,
        "failure_reasons": sorted(
            key for key, value in automatic_checks.items() if not value
        ),
        "error_candidate_ids": [record["candidate_id"] for record in error_records],
        "identical_candidate_ids": identical_pairs,
        "records": records,
        "decision": "manual_review_ready" if passed else "materialization_fail",
        "approved_for_manual_review": passed,
        "approved_for_processing": False,
        "approved_for_training": False,
        "safety": {
            "database_write_count": 0,
            "selected_function_code_read_count": len(records) * 2,
            "whole_file_diff_read_count": 0,
            "poc_read_count": 0,
            "source_code_execution_count": 0,
            "object_execution_count": 0,
            "docker_pull_count": 0,
        },
    }


def _validate_catalog(catalog: dict[str, Any]) -> None:
    if catalog.get("schema_version") != CVEFIXES_FEASIBILITY_CATALOG_SCHEMA_VERSION:
        raise CvefixesReviewError("unsupported catalog schema")
    if catalog.get("decision") != "manual_evidence_gate_ready":
        raise CvefixesReviewError("catalog gate has not passed")
    if catalog.get("approved_for_selective_review_materialization") is not True:
        raise CvefixesReviewError("selective review materialization is not approved")
    if catalog.get("approved_for_training") is not False:
        raise CvefixesReviewError("catalog training approval must remain false")
    if not isinstance(catalog.get("candidates"), list):
        raise CvefixesReviewError("catalog candidates must be a list")


def _open_read_only(database_path: Path) -> sqlite3.Connection:
    uri = f"{database_path.resolve().as_uri()}?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True)
    connection.execute("PRAGMA query_only=ON")
    connection.execute("PRAGMA trusted_schema=OFF")
    return connection


def _materialize_candidate(
    methods: dict[int, dict[str, Any]],
    candidate: dict[str, Any],
    *,
    max_code_chars: int,
    max_diff_chars: int,
) -> dict[str, Any]:
    errors: list[str] = []
    before = _method_row(
        methods,
        int(candidate["before_method_change_id"]),
        expected_file_change_id=int(candidate["file_change_id"]),
        expected_before=True,
    )
    after = _method_row(
        methods,
        int(candidate["after_method_change_id"]),
        expected_file_change_id=int(candidate["file_change_id"]),
        expected_before=False,
    )
    before_code = before["code"]
    after_code = after["code"]
    if len(before_code) > max_code_chars:
        errors.append("before_code_exceeds_limit")
    if len(after_code) > max_code_chars:
        errors.append("after_code_exceeds_limit")
    if "\x00" in before_code or "\x00" in after_code:
        errors.append("nul_byte_in_code")
    function_diff = "".join(
        difflib.unified_diff(
            before_code.splitlines(keepends=True),
            after_code.splitlines(keepends=True),
            fromfile="before_function",
            tofile="after_function",
            n=3,
        )
    )
    if len(function_diff) > max_diff_chars:
        errors.append("function_diff_exceeds_limit")

    if errors:
        before_visible = ""
        after_visible = ""
        diff_visible = ""
    else:
        before_visible = before_code
        after_visible = after_code
        diff_visible = function_diff
    return {
        "candidate_id": str(candidate["candidate_id"]),
        "repository_url": str(candidate["repository_url"]),
        "commit_hash": str(candidate["commit_hash"]),
        "file_change_id": int(candidate["file_change_id"]),
        "before_method_change_id": int(candidate["before_method_change_id"]),
        "after_method_change_id": int(candidate["after_method_change_id"]),
        "programming_language": str(candidate["programming_language"]),
        "cve_ids": list(candidate["cve_ids"]),
        "target_cwe": str(candidate["target_cwe"]),
        "repository_license_status": "unverified",
        "before_code": before_visible,
        "after_code": after_visible,
        "function_diff": diff_visible,
        "before_code_sha256": _sha256_text(before_code),
        "after_code_sha256": _sha256_text(after_code),
        "materialization_errors": errors,
        "operator_patch_related": None,
        "operator_cwe_supported": None,
        "operator_pair_quality": None,
        "operator_notes": "",
        "disposition": "pending_manual_review",
    }


def _selected_method_rows(
    connection: sqlite3.Connection,
    candidates: list[dict[str, Any]],
) -> dict[int, dict[str, Any]]:
    selected_ids = sorted(
        {
            int(candidate[key])
            for candidate in candidates
            for key in ("before_method_change_id", "after_method_change_id")
        }
    )
    if not selected_ids:
        raise CvefixesReviewError("catalog contains no selected method ids")
    placeholders = ",".join("?" for _ in selected_ids)
    rows = connection.execute(
        "SELECT method_change_id, file_change_id, code, before_change "
        f"FROM method_change WHERE method_change_id IN ({placeholders})",
        selected_ids,
    )
    methods = {
        int(method_id): {
            "file_change_id": int(file_change_id),
            "code": code,
            "before_change": before_change,
        }
        for method_id, file_change_id, code, before_change in rows
    }
    if len(methods) != len(selected_ids):
        missing = sorted(set(selected_ids) - set(methods))
        raise CvefixesReviewError(f"selected method rows missing: {missing}")
    return methods


def _method_row(
    methods: dict[int, dict[str, Any]],
    method_change_id: int,
    *,
    expected_file_change_id: int,
    expected_before: bool,
) -> dict[str, Any]:
    row = methods.get(method_change_id)
    if row is None:
        raise CvefixesReviewError(f"method_change row not found: {method_change_id}")
    if int(row["file_change_id"]) != expected_file_change_id:
        raise CvefixesReviewError(f"method_change file mismatch: {method_change_id}")
    observed_before = str(row["before_change"]).lower() in {"1", "true"}
    if observed_before is not expected_before:
        raise CvefixesReviewError(
            f"method_change before/after mismatch: {method_change_id}"
        )
    code = row["code"]
    if not isinstance(code, str) or not code:
        raise CvefixesReviewError(f"empty method code: {method_change_id}")
    return {"code": code}


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
