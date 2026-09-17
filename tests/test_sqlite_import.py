from __future__ import annotations

import gzip
import json
import sqlite3
from pathlib import Path

import pytest

from aegislm.datasets.sql_dump import audit_gzip_sqlite_dump
from aegislm.datasets.sqlite_import import (
    SqliteImportError,
    import_audited_sqlite_dump,
)

REQUIRED = frozenset({"fixes", "method_change"})


def _write_dump(path: Path, *, dangerous: bool = False) -> None:
    statements = [
        "PRAGMA foreign_keys=OFF;",
        "BEGIN TRANSACTION;",
        'CREATE TABLE IF NOT EXISTS "fixes" ("cve_id" TEXT);',
        "INSERT INTO fixes VALUES('CVE-1');",
        'CREATE TABLE IF NOT EXISTS "method_change" ("code" TEXT);',
        "INSERT INTO method_change VALUES('static source only');",
    ]
    if dangerous:
        statements.append("ATTACH DATABASE '/tmp/other.db' AS other;")
    statements.append("COMMIT;")
    with gzip.open(path, "wt", encoding="utf-8") as stream:
        stream.write("\n".join(statements) + "\n")


def _audit(path: Path, output: Path) -> None:
    audit = audit_gzip_sqlite_dump(path, required_tables=REQUIRED)
    output.write_text(json.dumps(audit), encoding="utf-8")


def test_defensive_import_publishes_verified_database(tmp_path: Path) -> None:
    dump = tmp_path / "safe.sql.gz"
    audit = tmp_path / "audit.json"
    database = tmp_path / "safe.db"
    _write_dump(dump)
    _audit(dump, audit)

    result = import_audited_sqlite_dump(
        dump,
        audit,
        database,
        required_tables=REQUIRED,
        progress_every=1,
    )

    assert result["decision"] == "defensive_import_pass"
    assert result["database"]["quick_check"] == ["ok"]
    assert result["database"]["row_counts"] == {"fixes": 1, "method_change": 1}
    assert result["approved_for_read_only_supply_audit"] is True
    assert result["approved_for_processing"] is False
    assert result["approved_for_training"] is False
    assert result["safety"]["source_code_execution_count"] == 0
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM fixes").fetchone()[0] == 1


def test_defensive_import_rejects_failed_static_audit(tmp_path: Path) -> None:
    dump = tmp_path / "dangerous.sql.gz"
    audit = tmp_path / "audit.json"
    database = tmp_path / "blocked.db"
    _write_dump(dump, dangerous=True)
    _audit(dump, audit)

    with pytest.raises(SqliteImportError, match="must pass"):
        import_audited_sqlite_dump(
            dump,
            audit,
            database,
            required_tables=REQUIRED,
        )
    assert not database.exists()


def test_defensive_import_rejects_output_and_audit_mismatch(tmp_path: Path) -> None:
    dump = tmp_path / "safe.sql.gz"
    audit = tmp_path / "audit.json"
    _write_dump(dump)
    _audit(dump, audit)
    existing = tmp_path / "existing.db"
    existing.write_bytes(b"preserve")
    with pytest.raises(SqliteImportError, match="already exists"):
        import_audited_sqlite_dump(
            dump,
            audit,
            existing,
            required_tables=REQUIRED,
        )
    assert existing.read_bytes() == b"preserve"

    audit_data = json.loads(audit.read_text(encoding="utf-8"))
    audit_data["input"]["path"] = str(tmp_path / "other.sql.gz")
    audit.write_text(json.dumps(audit_data), encoding="utf-8")
    with pytest.raises(SqliteImportError, match="path does not match"):
        import_audited_sqlite_dump(
            dump,
            audit,
            tmp_path / "mismatch.db",
            required_tables=REQUIRED,
        )
