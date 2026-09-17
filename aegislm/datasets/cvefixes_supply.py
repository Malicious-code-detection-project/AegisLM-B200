"""Read-only supply inventory for the imported CVEfixes database."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any

from aegislm.datasets.sql_dump import DEFAULT_REQUIRED_TABLES

CVEFIXES_SUPPLY_AUDIT_SCHEMA_VERSION = "aegislm.phase-f-cvefixes-supply-audit.v1"
EXPECTED_MINIMUM_ROWS = {
    "commits": 12_000,
    "cve": 11_000,
    "cwe": 250,
    "cwe_classification": 12_000,
    "file_change": 50_000,
    "fixes": 12_000,
    "method_change": 270_000,
    "repository": 4_000,
}
_DENIED_READ_ONLY_ACTION_NAMES = (
    "SQLITE_ALTER_TABLE",
    "SQLITE_ANALYZE",
    "SQLITE_ATTACH",
    "SQLITE_CREATE_INDEX",
    "SQLITE_CREATE_TABLE",
    "SQLITE_CREATE_TEMP_INDEX",
    "SQLITE_CREATE_TEMP_TABLE",
    "SQLITE_CREATE_TEMP_TRIGGER",
    "SQLITE_CREATE_TEMP_VIEW",
    "SQLITE_CREATE_TRIGGER",
    "SQLITE_CREATE_VIEW",
    "SQLITE_CREATE_VTABLE",
    "SQLITE_DELETE",
    "SQLITE_DETACH",
    "SQLITE_DROP_INDEX",
    "SQLITE_DROP_TABLE",
    "SQLITE_DROP_TEMP_INDEX",
    "SQLITE_DROP_TEMP_TABLE",
    "SQLITE_DROP_TEMP_TRIGGER",
    "SQLITE_DROP_TEMP_VIEW",
    "SQLITE_DROP_TRIGGER",
    "SQLITE_DROP_VIEW",
    "SQLITE_DROP_VTABLE",
    "SQLITE_INSERT",
    "SQLITE_REINDEX",
    "SQLITE_TRANSACTION",
    "SQLITE_UPDATE",
)
_DENIED_READ_ONLY_ACTIONS = {
    value
    for name in _DENIED_READ_ONLY_ACTION_NAMES
    if isinstance((value := getattr(sqlite3, name, None)), int)
}


class CvefixesSupplyError(ValueError):
    """Raised when the imported CVEfixes database violates the audit contract."""


def audit_cvefixes_supply(
    database_path: Path,
    *,
    minimum_binary_pairs: int = 2_000,
) -> dict[str, Any]:
    """Audit pairing and CWE supply without returning code or diff payloads."""
    if not database_path.is_file():
        raise CvefixesSupplyError(f"database is not a regular file: {database_path}")
    if minimum_binary_pairs <= 0:
        raise CvefixesSupplyError("minimum_binary_pairs must be positive")

    started = time.monotonic()
    connection = _open_read_only(database_path)
    try:
        table_names = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        missing_tables = sorted(DEFAULT_REQUIRED_TABLES - table_names)
        row_counts = {
            table: int(
                connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
            )
            for table in sorted(DEFAULT_REQUIRED_TABLES & table_names)
        }
        method_balance = [
            {
                "before_change": row[0],
                "rows": int(row[1]),
                "nonempty_code_rows": int(row[2]),
            }
            for row in connection.execute(
                "SELECT before_change, COUNT(*), "
                "SUM(CASE WHEN code IS NOT NULL AND length(code) > 0 THEN 1 ELSE 0 END) "
                "FROM method_change GROUP BY before_change ORDER BY before_change"
            )
        ]
        language_distribution = [
            {
                "programming_language": str(row[0] or "<NULL>"),
                "file_change_rows": int(row[1]),
                "method_change_rows": int(row[2]),
            }
            for row in connection.execute(
                "SELECT fc.programming_language, "
                "COUNT(DISTINCT fc.file_change_id), COUNT(mc.method_change_id) "
                "FROM file_change AS fc "
                "LEFT JOIN method_change AS mc "
                "ON mc.file_change_id = fc.file_change_id "
                "GROUP BY fc.programming_language "
                "ORDER BY COUNT(mc.method_change_id) DESC"
            )
        ]
        change_type_distribution = [
            {
                "change_type": str(row[0] or "<NULL>"),
                "file_change_rows": int(row[1]),
            }
            for row in connection.execute(
                "SELECT change_type, COUNT(*) FROM file_change "
                "GROUP BY change_type ORDER BY COUNT(*) DESC"
            )
        ]
        pairing = _pairing_summary(connection)
    finally:
        connection.close()

    minimum_rows_pass = all(
        row_counts.get(table, 0) >= minimum
        for table, minimum in EXPECTED_MINIMUM_ROWS.items()
    )
    binary_candidate_pairs = int(pairing["binary_candidate_pairs"])
    checks = {
        "required_tables_present": not missing_tables,
        "official_scale_minimums_met": minimum_rows_pass,
        "before_after_labels_present": _before_after_labels_present(method_balance),
        "paired_methods_present": int(pairing["exact_method_pairs"]) > 0,
        "binary_pair_supply_minimum_met": binary_candidate_pairs
        >= minimum_binary_pairs,
        "raw_code_returned": False,
        "raw_diff_returned": False,
    }
    passed = (
        all(
            value
            for name, value in checks.items()
            if name not in {"raw_code_returned", "raw_diff_returned"}
        )
        and not checks["raw_code_returned"]
        and not checks["raw_diff_returned"]
    )
    return {
        "schema_version": CVEFIXES_SUPPLY_AUDIT_SCHEMA_VERSION,
        "database": {
            "path": str(database_path.resolve()),
            "bytes": database_path.stat().st_size,
            "read_only": True,
            "immutable": True,
        },
        "table_names": sorted(table_names),
        "missing_tables": missing_tables,
        "row_counts": row_counts,
        "method_balance": method_balance,
        "language_distribution": language_distribution,
        "change_type_distribution": change_type_distribution,
        "pairing": pairing,
        "minimum_binary_pairs": minimum_binary_pairs,
        "checks": checks,
        "failure_reasons": sorted(
            name
            for name, value in checks.items()
            if (name in {"raw_code_returned", "raw_diff_returned"} and value)
            or (name not in {"raw_code_returned", "raw_diff_returned"} and not value)
        ),
        "elapsed_seconds": time.monotonic() - started,
        "decision": "supply_inventory_pass" if passed else "supply_inventory_fail",
        "approved_for_metadata_catalog": passed,
        "approved_for_code_materialization": False,
        "approved_for_processing": False,
        "approved_for_training": False,
        "safety": {
            "database_write_count": 0,
            "raw_code_return_count": 0,
            "raw_diff_return_count": 0,
            "source_code_execution_count": 0,
            "object_execution_count": 0,
        },
    }


def _open_read_only(database_path: Path) -> sqlite3.Connection:
    uri = f"{database_path.resolve().as_uri()}?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True)
    connection.execute("PRAGMA temp_store=MEMORY")
    connection.execute("PRAGMA cache_size=-4194304")
    connection.execute("PRAGMA mmap_size=8589934592")
    connection.execute("PRAGMA threads=8")
    connection.execute("PRAGMA query_only=ON")
    connection.execute("PRAGMA trusted_schema=OFF")
    connection.set_authorizer(_read_only_authorizer)
    return connection


def _read_only_authorizer(
    action_code: int,
    arg1: str | None,
    arg2: str | None,
    database_name: str | None,
    trigger_name: str | None,
) -> int:
    del arg1, arg2, database_name, trigger_name
    if action_code in _DENIED_READ_ONLY_ACTIONS:
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


def _pairing_summary(connection: sqlite3.Connection) -> dict[str, Any]:
    file_changes = {
        int(file_change_id): {
            "hash": str(commit_hash),
            "language": str(language or ""),
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

    summary: dict[str, Any] = {
        "exact_method_pairs": 0,
        "pairs_with_both_code": 0,
        "pairs_with_file_diff": 0,
        "pairs_with_single_cwe": 0,
        "binary_candidate_pairs": 0,
        "distinct_repositories": 0,
        "distinct_fix_commits": 0,
        "code_change_verification": "deferred_to_materialization_gate",
    }
    binary_language_counts = {"C": 0, "C++": 0}
    binary_repositories: set[str] = set()
    binary_commits: set[str] = set()
    pair_rows = connection.execute(
        """
        SELECT
            file_change_id,
            COUNT(*) AS method_rows,
            SUM(
                CASE WHEN CAST(before_change AS TEXT) IN ('1', 'True', 'true')
                THEN 1 ELSE 0 END
            ) AS before_rows,
            SUM(
                CASE WHEN CAST(before_change AS TEXT) IN ('0', 'False', 'false')
                THEN 1 ELSE 0 END
            ) AS after_rows,
            SUM(CASE WHEN code IS NOT NULL AND length(code) > 0 THEN 1 ELSE 0 END)
                AS nonempty_code_rows
        FROM method_change
        WHERE name IS NOT NULL
          AND length(name) > 0
          AND signature IS NOT NULL
          AND length(signature) > 0
        GROUP BY file_change_id, name, signature
        HAVING method_rows = 2
           AND before_rows = 1
           AND after_rows = 1
        """
    )
    for file_change_id, _, _, _, nonempty_code_rows in pair_rows:
        summary["exact_method_pairs"] += 1
        has_both_code = int(nonempty_code_rows or 0) == 2
        if has_both_code:
            summary["pairs_with_both_code"] += 1
        file_record = file_changes.get(int(file_change_id))
        if file_record is None:
            continue
        if file_record["has_file_diff"]:
            summary["pairs_with_file_diff"] += 1
        commit_hash = str(file_record["hash"])
        cwes = {
            cwe
            for cve in cves_by_commit.get(commit_hash, set())
            for cwe in cwes_by_cve.get(cve, set())
        }
        if len(cwes) == 1:
            summary["pairs_with_single_cwe"] += 1
        language = str(file_record["language"])
        normalized_change_type = str(file_record["change_type"]).rsplit(".", 1)[-1]
        is_binary_candidate = (
            language in binary_language_counts
            and normalized_change_type.upper() == "MODIFY"
            and has_both_code
            and bool(file_record["has_file_diff"])
            and len(cwes) == 1
        )
        if is_binary_candidate:
            summary["binary_candidate_pairs"] += 1
            binary_language_counts[language] += 1
            binary_commits.add(commit_hash)
            repository = repositories.get(commit_hash, "")
            if repository:
                binary_repositories.add(repository)

    summary["distinct_repositories"] = len(binary_repositories)
    summary["distinct_fix_commits"] = len(binary_commits)
    summary["binary_language_breakdown"] = [
        {"programming_language": language, "candidate_pairs": count}
        for language, count in sorted(binary_language_counts.items())
        if count
    ]
    return summary


def _before_after_labels_present(rows: list[dict[str, Any]]) -> bool:
    values = {str(row["before_change"]).lower() for row in rows if row["rows"] > 0}
    return bool(values & {"1", "true"}) and bool(values & {"0", "false"})
