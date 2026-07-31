from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from aegislm.datasets.cvefixes_catalog import (
    CvefixesCatalogError,
    build_cvefixes_feasibility_catalog,
)
from aegislm.datasets.cvefixes_supply import (
    CVEFIXES_SUPPLY_AUDIT_SCHEMA_VERSION,
)


def _database(path: Path, rows_per_language: int = 4) -> None:
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE fixes (cve_id TEXT, hash TEXT, repo_url TEXT);
            CREATE TABLE commits (hash TEXT, repo_url TEXT);
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
                before_change TEXT
            );
            """
        )
        method_id = 1
        file_id = 1
        for language in ("C", "C++"):
            for index in range(rows_per_language):
                commit_hash = f"{language}-{index}"
                repo_url = f"https://example.test/{language}/{index}"
                cve_id = f"CVE-{language}-{index}"
                cwe_id = f"CWE-{100 + index}"
                connection.execute(
                    "INSERT INTO commits VALUES (?, ?)",
                    (commit_hash, repo_url),
                )
                connection.execute(
                    "INSERT INTO fixes VALUES (?, ?, ?)",
                    (cve_id, commit_hash, repo_url),
                )
                connection.execute(
                    "INSERT INTO cwe_classification VALUES (?, ?)",
                    (cve_id, cwe_id),
                )
                connection.execute(
                    "INSERT INTO file_change VALUES (?, ?, ?, ?, ?)",
                    (
                        file_id,
                        commit_hash,
                        "not selected by the query",
                        language,
                        "ModificationType.MODIFY",
                    ),
                )
                for before_change, code in (
                    ("True", "before"),
                    ("False", "after"),
                ):
                    connection.execute(
                        "INSERT INTO method_change VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            method_id,
                            file_id,
                            f"function_{index}",
                            f"void function_{index}()",
                            code,
                            before_change,
                        ),
                    )
                    method_id += 1
                file_id += 1


def _add_non_actionable_candidate(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute(
            "INSERT INTO commits VALUES (?, ?)",
            ("non-actionable", "https://example.test/non-actionable"),
        )
        connection.execute(
            "INSERT INTO fixes VALUES (?, ?, ?)",
            (
                "CVE-NOINFO",
                "non-actionable",
                "https://example.test/non-actionable",
            ),
        )
        connection.execute(
            "INSERT INTO cwe_classification VALUES (?, ?)",
            ("CVE-NOINFO", "NVD-CWE-noinfo"),
        )
        connection.execute(
            "INSERT INTO file_change VALUES (?, ?, ?, ?, ?)",
            (
                999,
                "non-actionable",
                "not selected by the query",
                "C",
                "ModificationType.MODIFY",
            ),
        )
        connection.execute(
            "INSERT INTO method_change VALUES (?, ?, ?, ?, ?, ?)",
            (999, 999, "f", "void f()", "before", "True"),
        )
        connection.execute(
            "INSERT INTO method_change VALUES (?, ?, ?, ?, ?, ?)",
            (1000, 999, "f", "void f()", "after", "False"),
        )


def _supply_audit(path: Path, *, passed: bool = True) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": CVEFIXES_SUPPLY_AUDIT_SCHEMA_VERSION,
                "decision": (
                    "supply_inventory_pass" if passed else "supply_inventory_fail"
                ),
                "approved_for_metadata_catalog": passed,
                "safety": {
                    "database_write_count": 0,
                    "raw_code_return_count": 0,
                    "raw_diff_return_count": 0,
                    "source_code_execution_count": 0,
                    "object_execution_count": 0,
                },
            }
        ),
        encoding="utf-8",
    )


def test_catalog_is_deterministic_grouped_and_payload_free(
    tmp_path: Path,
) -> None:
    database = tmp_path / "cvefixes.db"
    audit = tmp_path / "supply-audit.json"
    _database(database)
    _add_non_actionable_candidate(database)
    _supply_audit(audit)

    first = build_cvefixes_feasibility_catalog(
        database,
        audit,
        selection_seed=7,
        sample_size=4,
        language_quotas={"C": 2, "C++": 2},
        max_per_cwe=1,
    )
    second = build_cvefixes_feasibility_catalog(
        database,
        audit,
        selection_seed=7,
        sample_size=4,
        language_quotas={"C": 2, "C++": 2},
        max_per_cwe=1,
    )

    assert first["candidates"] == second["candidates"]
    assert first["decision"] == "manual_evidence_gate_ready"
    assert first["selected_summary"]["language_counts"] == {"C": 2, "C++": 2}
    assert first["selected_summary"]["distinct_commit_groups"] == 4
    assert first["checks"]["target_cwes_actionable"] is True
    assert first["candidate_pool"]["rows"] == 8
    assert first["forbidden_payload_key_hits"] == []
    assert first["safety"]["raw_code_read_count"] == 0
    assert first["safety"]["raw_diff_read_count"] == 0
    assert first["approved_for_selective_review_materialization"] is True
    assert first["approved_for_bulk_materialization"] is False
    assert first["approved_for_training"] is False
    serialized = json.dumps(first["candidates"])
    assert "not selected by the query" not in serialized
    assert '"code"' not in serialized
    assert '"diff"' not in serialized


def test_catalog_rejects_failed_supply_gate(tmp_path: Path) -> None:
    database = tmp_path / "cvefixes.db"
    audit = tmp_path / "supply-audit.json"
    _database(database)
    _supply_audit(audit, passed=False)

    with pytest.raises(CvefixesCatalogError, match="has not passed"):
        build_cvefixes_feasibility_catalog(
            database,
            audit,
            sample_size=2,
            language_quotas={"C": 1, "C++": 1},
        )


def test_catalog_rejects_invalid_quota_contract(tmp_path: Path) -> None:
    database = tmp_path / "cvefixes.db"
    audit = tmp_path / "supply-audit.json"
    _database(database)
    _supply_audit(audit)

    with pytest.raises(CvefixesCatalogError, match="quota sum"):
        build_cvefixes_feasibility_catalog(
            database,
            audit,
            sample_size=3,
            language_quotas={"C": 1, "C++": 1},
        )
