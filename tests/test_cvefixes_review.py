from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from aegislm.datasets.cvefixes_catalog import (
    CVEFIXES_FEASIBILITY_CATALOG_SCHEMA_VERSION,
)
from aegislm.datasets.cvefixes_review import (
    CvefixesReviewError,
    materialize_cvefixes_review_queue,
)


def _database(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE method_change (
                method_change_id INTEGER,
                file_change_id INTEGER,
                code TEXT,
                before_change TEXT
            );
            INSERT INTO method_change VALUES (
                1, 10, 'void f() { unsafe(); }', 'True'
            );
            INSERT INTO method_change VALUES (
                2, 10, 'void f() { safe(); }', 'False'
            );
            """
        )


def _catalog(path: Path, *, passed: bool = True) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": CVEFIXES_FEASIBILITY_CATALOG_SCHEMA_VERSION,
                "decision": (
                    "manual_evidence_gate_ready" if passed else "catalog_fail"
                ),
                "approved_for_selective_review_materialization": passed,
                "approved_for_training": False,
                "selection": {"sample_size": 1},
                "candidates": [
                    {
                        "candidate_id": "cvefixes-test",
                        "repository_url": "https://example.test/repo",
                        "commit_hash": "abc",
                        "file_change_id": 10,
                        "before_method_change_id": 1,
                        "after_method_change_id": 2,
                        "programming_language": "C",
                        "cve_ids": ["CVE-1"],
                        "target_cwe": "CWE-122",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def test_review_queue_materializes_only_selected_function_pair(
    tmp_path: Path,
) -> None:
    database = tmp_path / "cvefixes.db"
    catalog = tmp_path / "catalog.json"
    _database(database)
    _catalog(catalog)

    result = materialize_cvefixes_review_queue(database, catalog)

    assert result["decision"] == "manual_review_ready"
    assert result["summary"]["materialized_records"] == 1
    assert result["summary"]["unfinished_operator_decisions"] == 1
    assert result["checks"]["operator_decisions_complete"] is False
    assert result["records"][0]["before_code"] == "void f() { unsafe(); }"
    assert result["records"][0]["after_code"] == "void f() { safe(); }"
    assert "-void f() { unsafe(); }" in result["records"][0]["function_diff"]
    assert result["safety"]["selected_function_code_read_count"] == 2
    assert result["safety"]["whole_file_diff_read_count"] == 0
    assert result["safety"]["source_code_execution_count"] == 0
    assert result["approved_for_training"] is False


def test_review_queue_rejects_failed_catalog(tmp_path: Path) -> None:
    database = tmp_path / "cvefixes.db"
    catalog = tmp_path / "catalog.json"
    _database(database)
    _catalog(catalog, passed=False)

    with pytest.raises(CvefixesReviewError, match="has not passed"):
        materialize_cvefixes_review_queue(database, catalog)


def test_review_queue_quarantines_oversized_code(tmp_path: Path) -> None:
    database = tmp_path / "cvefixes.db"
    catalog = tmp_path / "catalog.json"
    _database(database)
    _catalog(catalog)

    result = materialize_cvefixes_review_queue(
        database,
        catalog,
        max_code_chars=5,
    )

    assert result["decision"] == "materialization_fail"
    assert result["summary"]["error_records"] == 1
    assert result["records"][0]["before_code"] == ""
    assert result["records"][0]["after_code"] == ""
    assert "before_code_exceeds_limit" in result["records"][0]["materialization_errors"]
