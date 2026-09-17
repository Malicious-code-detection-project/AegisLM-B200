"""Defensive importer for an audited, gzip-compressed SQLite dump."""

from __future__ import annotations

import gzip
import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from aegislm.datasets.sql_dump import DEFAULT_REQUIRED_TABLES

SQLITE_IMPORT_SCHEMA_VERSION = "aegislm.phase-f-defensive-sqlite-import.v1"
_HASH_CHUNK_BYTES = 8 * 1024 * 1024
_DENIED_ACTION_NAMES = (
    "SQLITE_ALTER_TABLE",
    "SQLITE_ATTACH",
    "SQLITE_CREATE_TRIGGER",
    "SQLITE_CREATE_VTABLE",
    "SQLITE_DETACH",
    "SQLITE_DROP_TRIGGER",
    "SQLITE_DROP_VTABLE",
)
_DENIED_ACTIONS = {
    value
    for name in _DENIED_ACTION_NAMES
    if isinstance((value := getattr(sqlite3, name, None)), int)
}


class SqliteImportError(ValueError):
    """Raised when an audited dump cannot be imported within the safety contract."""


def import_audited_sqlite_dump(
    input_path: Path,
    static_audit_path: Path,
    output_path: Path,
    *,
    required_tables: frozenset[str] = DEFAULT_REQUIRED_TABLES,
    max_statement_chars: int = 256 * 1024 * 1024,
    progress_every: int = 10_000,
) -> dict[str, Any]:
    """Import a dump into a temporary DB with an authorizer and atomic publication."""
    if not input_path.is_file():
        raise SqliteImportError(f"input gzip is not a regular file: {input_path}")
    if not static_audit_path.is_file():
        raise SqliteImportError(
            f"static audit is not a regular file: {static_audit_path}"
        )
    if output_path.exists():
        raise SqliteImportError(f"output path already exists: {output_path}")
    if max_statement_chars <= 0 or progress_every <= 0:
        raise SqliteImportError("import limits must be positive")
    static_audit = json.loads(static_audit_path.read_text(encoding="utf-8"))
    _validate_static_audit(static_audit, input_path, required_tables)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = output_path.with_name(f".{output_path.name}.importing")
    if temporary_path.exists():
        raise SqliteImportError(
            f"temporary import path already exists: {temporary_path}"
        )

    started_at = time.monotonic()
    statement_count = 0
    max_observed_statement_chars = 0
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(temporary_path)
        connection.enable_load_extension(False)
        _configure_import_connection(connection)
        connection.set_authorizer(_defensive_authorizer)
        statement_buffer: list[str] = []
        statement_chars = 0
        with gzip.open(input_path, "rt", encoding="utf-8", errors="strict") as stream:
            for line in stream:
                statement_buffer.append(line)
                statement_chars += len(line)
                if statement_chars > max_statement_chars:
                    raise SqliteImportError(
                        "SQL statement exceeded max_statement_chars"
                    )
                if ";" not in line:
                    continue
                statement = "".join(statement_buffer)
                if not sqlite3.complete_statement(statement):
                    continue
                if statement.strip():
                    connection.execute(statement)
                    statement_count += 1
                    max_observed_statement_chars = max(
                        max_observed_statement_chars,
                        statement_chars,
                    )
                    if statement_count % progress_every == 0:
                        print(
                            "Phase F CVEfixes import progress: "
                            f"statements={statement_count}",
                            flush=True,
                        )
                statement_buffer.clear()
                statement_chars = 0
        if statement_buffer and "".join(statement_buffer).strip():
            raise SqliteImportError("SQL dump ended with an incomplete statement")
        if connection.in_transaction:
            raise SqliteImportError("SQL dump ended with an open transaction")

        quick_check_rows = connection.execute("PRAGMA quick_check").fetchall()
        quick_check = [str(row[0]) for row in quick_check_rows]
        if quick_check != ["ok"]:
            raise SqliteImportError(f"SQLite quick_check failed: {quick_check}")
        table_names = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        missing_tables = sorted(required_tables - table_names)
        if missing_tables:
            raise SqliteImportError(
                f"imported database is missing tables: {missing_tables}"
            )
        row_counts = {
            table: int(
                connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
            )
            for table in sorted(required_tables)
        }
        connection.close()
        connection = None
        with temporary_path.open("rb") as stream:
            sha256 = hashlib.sha256()
            while chunk := stream.read(_HASH_CHUNK_BYTES):
                sha256.update(chunk)
        database_bytes = temporary_path.stat().st_size
        temporary_path.replace(output_path)
    except Exception:
        if connection is not None:
            connection.close()
        temporary_path.unlink(missing_ok=True)
        raise

    return {
        "schema_version": SQLITE_IMPORT_SCHEMA_VERSION,
        "input": {
            "path": str(input_path.resolve()),
            "compressed_bytes": input_path.stat().st_size,
            "static_audit_path": str(static_audit_path.resolve()),
            "uncompressed_sha256": static_audit["stream"]["uncompressed_sha256"],
        },
        "database": {
            "path": str(output_path.resolve()),
            "bytes": database_bytes,
            "sha256": sha256.hexdigest(),
            "table_names": sorted(table_names),
            "row_counts": row_counts,
            "quick_check": quick_check,
        },
        "import": {
            "statement_count": statement_count,
            "max_statement_chars": max_observed_statement_chars,
            "elapsed_seconds": time.monotonic() - started_at,
            "authorizer_enabled": True,
            "extension_loading_enabled": False,
        },
        "decision": "defensive_import_pass",
        "approved_for_read_only_supply_audit": True,
        "approved_for_processing": False,
        "approved_for_training": False,
        "safety": {
            "source_code_execution_count": 0,
            "object_execution_count": 0,
            "external_database_attach_count": 0,
            "extension_load_count": 0,
        },
    }


def _validate_static_audit(
    static_audit: dict[str, Any],
    input_path: Path,
    required_tables: frozenset[str],
) -> None:
    if static_audit.get("decision") != "sql_static_audit_pass":
        raise SqliteImportError("SQL static audit must pass before import")
    if not static_audit.get("approved_for_isolated_import"):
        raise SqliteImportError("isolated import is not approved")
    audited_input = static_audit.get("input")
    if not isinstance(audited_input, dict):
        raise SqliteImportError("static audit is missing input metadata")
    if Path(str(audited_input.get("path"))).resolve() != input_path.resolve():
        raise SqliteImportError("static audit input path does not match dump")
    if audited_input.get("compressed_bytes") != input_path.stat().st_size:
        raise SqliteImportError("input size changed after static audit")
    audited_tables = {str(value) for value in static_audit.get("table_names", [])}
    if not required_tables.issubset(audited_tables):
        raise SqliteImportError("static audit is missing required tables")
    if static_audit.get("dangerous_statement_start_count") != 0:
        raise SqliteImportError("static audit contains dangerous statements")


def _configure_import_connection(connection: sqlite3.Connection) -> None:
    connection.execute("PRAGMA journal_mode=OFF")
    connection.execute("PRAGMA synchronous=OFF")
    connection.execute("PRAGMA temp_store=MEMORY")
    connection.execute("PRAGMA cache_size=-2097152")
    connection.execute("PRAGMA trusted_schema=OFF")
    defensive = getattr(sqlite3, "SQLITE_DBCONFIG_DEFENSIVE", None)
    if isinstance(defensive, int) and hasattr(connection, "setconfig"):
        connection.setconfig(defensive, True)


def _defensive_authorizer(
    action_code: int,
    arg1: str | None,
    arg2: str | None,
    database_name: str | None,
    trigger_name: str | None,
) -> int:
    del database_name, trigger_name
    if action_code in _DENIED_ACTIONS:
        return sqlite3.SQLITE_DENY
    if action_code == sqlite3.SQLITE_PRAGMA:
        pragma_name = (arg1 or "").lower()
        pragma_value = (arg2 or "").lower()
        if pragma_name == "foreign_keys" and pragma_value in {"0", "off"}:
            return sqlite3.SQLITE_OK
        if pragma_name == "quick_check" and not pragma_value:
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY
    if action_code == sqlite3.SQLITE_FUNCTION:
        function_name = (arg2 or arg1 or "").lower()
        if function_name == "load_extension":
            return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK
