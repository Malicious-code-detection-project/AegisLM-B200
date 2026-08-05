from __future__ import annotations

import gzip
from pathlib import Path

import pytest

from aegislm.datasets.sql_dump import (
    SqlDumpAuditError,
    audit_gzip_sqlite_dump,
    audit_sqlite_dump_lines,
)

REQUIRED = {"fixes", "method_change"}


def _safe_dump() -> bytes:
    return b"".join(
        [
            b"PRAGMA foreign_keys=OFF;\n",
            b"BEGIN TRANSACTION;\n",
            b'CREATE TABLE IF NOT EXISTS "fixes" (\n',
            b'"cve_id" TEXT\n',
            b");\n",
            b"INSERT INTO fixes VALUES('CVE-1');\n",
            b'CREATE TABLE IF NOT EXISTS "method_change" (\n',
            b'"code" TEXT\n',
            b");\n",
            b"INSERT INTO method_change VALUES('safe source');\n",
            b"COMMIT;\n",
        ]
    )


def test_sql_dump_static_audit_passes_expected_structure_without_execution() -> None:
    payload = _safe_dump()
    result = audit_sqlite_dump_lines(
        payload.splitlines(keepends=True),
        required_tables=REQUIRED,
    )

    assert result["decision"] == "sql_static_audit_pass"
    assert result["table_names"] == ["fixes", "method_change"]
    assert result["statements"]["insert_lines"] == 2
    assert result["dangerous_statement_start_count"] == 0
    assert result["approved_for_isolated_import"] is True
    assert result["approved_for_processing"] is False
    assert result["approved_for_training"] is False
    assert result["safety"]["sql_execution_count"] == 0
    assert result["stream"]["uncompressed_bytes"] == len(payload)


def test_sql_dump_static_audit_fails_dangerous_commands_and_missing_tables() -> None:
    payload = b"".join(
        [
            b"PRAGMA writable_schema=ON;\n",
            b"ATTACH DATABASE '/tmp/other.db' AS other;\n",
            b"CREATE TRIGGER unsafe AFTER INSERT ON fixes BEGIN SELECT 1; END;\n",
        ]
    )
    result = audit_sqlite_dump_lines(
        payload.splitlines(keepends=True),
        required_tables=REQUIRED,
    )

    assert result["decision"] == "sql_static_audit_fail"
    assert result["dangerous_statement_start_count"] == 3
    assert result["statements"]["other_pragma_lines"] == 1
    assert result["approved_for_isolated_import"] is False
    assert set(result["failure_reasons"]) >= {
        "dangerous_statement_starts_absent",
        "required_tables_present",
    }


def test_gzip_sql_dump_audit_reads_stream_without_persisting_sql(
    tmp_path: Path,
) -> None:
    input_path = tmp_path / "dataset.sql.gz"
    with gzip.open(input_path, "wb") as stream:
        stream.write(_safe_dump())

    result = audit_gzip_sqlite_dump(input_path, required_tables=REQUIRED)

    assert result["decision"] == "sql_static_audit_pass"
    assert result["input"]["path"] == str(input_path.resolve())
    assert result["safety"]["decompressed_output_write_count"] == 0
    assert list(tmp_path.iterdir()) == [input_path]


def test_sql_dump_audit_rejects_invalid_inputs(tmp_path: Path) -> None:
    with pytest.raises(SqlDumpAuditError, match="regular file"):
        audit_gzip_sqlite_dump(
            tmp_path / "missing.gz",
            required_tables=REQUIRED,
        )
    with pytest.raises(SqlDumpAuditError, match="required table"):
        audit_sqlite_dump_lines([], required_tables=[])
    with pytest.raises(SqlDumpAuditError, match="must be bytes"):
        audit_sqlite_dump_lines(["SELECT 1;\n"], required_tables=REQUIRED)  # type: ignore[list-item]
