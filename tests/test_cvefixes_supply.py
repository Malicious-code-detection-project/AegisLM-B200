from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from aegislm.datasets.cvefixes_supply import (
    CvefixesSupplyError,
    audit_cvefixes_supply,
)


def _database(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE fixes (cve_id TEXT, hash TEXT, repo_url TEXT);
            CREATE TABLE commits (hash TEXT, repo_url TEXT);
            CREATE TABLE repository (repo_url TEXT);
            CREATE TABLE cve (cve_id TEXT);
            CREATE TABLE cwe (cwe_id TEXT);
            CREATE TABLE cwe_classification (cve_id TEXT, cwe_id TEXT);
            CREATE TABLE file_change (
                file_change_id INTEGER,
                hash TEXT,
                diff TEXT,
                programming_language TEXT,
                change_type TEXT
            );
            CREATE TABLE method_change (
                method_change_id INTEGER,
                file_change_id INTEGER,
                name TEXT,
                signature TEXT,
                code TEXT,
                before_change INTEGER
            );
            INSERT INTO repository VALUES ('https://example.test/repo');
            INSERT INTO cve VALUES ('CVE-1');
            INSERT INTO cwe VALUES ('CWE-122');
            INSERT INTO cwe_classification VALUES ('CVE-1', 'CWE-122');
            INSERT INTO fixes VALUES (
                'CVE-1', 'abc', 'https://example.test/repo'
            );
            INSERT INTO commits VALUES ('abc', 'https://example.test/repo');
            INSERT INTO file_change VALUES (
                1, 'abc', 'diff', 'C', 'MODIFY'
            );
            INSERT INTO method_change VALUES (
                1, 1, 'f', 'void f()', 'before', 1
            );
            INSERT INTO method_change VALUES (
                2, 1, 'f', 'void f()', 'after', 0
            );
            """
        )


def _set_change_type(path: Path, value: str) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE file_change SET change_type = ?", (value,))


def test_cvefixes_supply_audit_finds_exact_pairs_without_returning_code(
    tmp_path: Path,
) -> None:
    database = tmp_path / "cvefixes.db"
    _database(database)

    result = audit_cvefixes_supply(database, minimum_binary_pairs=1)

    assert result["pairing"]["exact_method_pairs"] == 1
    assert result["pairing"]["binary_candidate_pairs"] == 1
    assert result["pairing"]["binary_language_breakdown"] == [
        {"programming_language": "C", "candidate_pairs": 1}
    ]
    assert (
        result["pairing"]["code_change_verification"]
        == "deferred_to_materialization_gate"
    )
    assert result["checks"]["raw_code_returned"] is False
    assert result["checks"]["raw_diff_returned"] is False
    assert result["safety"]["database_write_count"] == 0
    assert result["safety"]["raw_code_return_count"] == 0
    assert result["approved_for_code_materialization"] is False
    assert result["approved_for_training"] is False
    assert result["decision"] == "supply_inventory_fail"
    assert "official_scale_minimums_met" in result["failure_reasons"]


def test_cvefixes_supply_normalizes_pydriller_change_type(tmp_path: Path) -> None:
    database = tmp_path / "cvefixes.db"
    _database(database)
    _set_change_type(database, "ModificationType.MODIFY")

    result = audit_cvefixes_supply(database, minimum_binary_pairs=1)

    assert result["pairing"]["binary_candidate_pairs"] == 1
    assert result["change_type_distribution"] == [
        {"change_type": "ModificationType.MODIFY", "file_change_rows": 1}
    ]


def test_cvefixes_supply_audit_requires_database_and_positive_target(
    tmp_path: Path,
) -> None:
    with pytest.raises(CvefixesSupplyError, match="regular file"):
        audit_cvefixes_supply(tmp_path / "missing.db")
    database = tmp_path / "cvefixes.db"
    _database(database)
    with pytest.raises(CvefixesSupplyError, match="positive"):
        audit_cvefixes_supply(database, minimum_binary_pairs=0)
