"""Static, non-executing audit for trusted SQLite dump streams."""

from __future__ import annotations

import gzip
import hashlib
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

SQL_DUMP_AUDIT_SCHEMA_VERSION = "aegislm.phase-f-sqlite-dump-audit.v1"
DEFAULT_REQUIRED_TABLES = frozenset(
    {
        "commits",
        "cve",
        "cwe",
        "cwe_classification",
        "file_change",
        "fixes",
        "method_change",
        "repository",
    }
)
_CREATE_TABLE = re.compile(
    rb'^CREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?\s+"?([A-Za-z_][A-Za-z0-9_]*)"?',
    re.IGNORECASE,
)
_CREATE_INDEX = re.compile(rb"^CREATE\s+(?:UNIQUE\s+)?INDEX\b", re.IGNORECASE)
_INSERT = re.compile(rb"^INSERT\s+INTO\b", re.IGNORECASE)
_DANGEROUS_STARTS = (
    re.compile(rb"^\s*ATTACH\b", re.IGNORECASE),
    re.compile(rb"^\s*DETACH\b", re.IGNORECASE),
    re.compile(rb"^\s*ALTER\s+TABLE\b", re.IGNORECASE),
    re.compile(rb"^\s*CREATE\s+TRIGGER\b", re.IGNORECASE),
    re.compile(rb"^\s*CREATE\s+VIRTUAL\s+TABLE\b", re.IGNORECASE),
    re.compile(rb"^\s*DROP\b", re.IGNORECASE),
    re.compile(rb"^\s*REINDEX\b", re.IGNORECASE),
    re.compile(rb"^\s*SELECT\s+load_extension\s*\(", re.IGNORECASE),
    re.compile(rb"^\s*VACUUM\b", re.IGNORECASE),
    re.compile(rb"^\s*\.(?:load|shell|system)\b", re.IGNORECASE),
)
_ALLOWED_PRAGMA = re.compile(
    rb"^\s*PRAGMA\s+foreign_keys\s*=\s*OFF\s*;\s*$",
    re.IGNORECASE,
)
_ANY_PRAGMA = re.compile(rb"^\s*PRAGMA\b", re.IGNORECASE)


class SqlDumpAuditError(ValueError):
    """Raised when SQL dump audit inputs are invalid."""


def audit_gzip_sqlite_dump(
    input_path: Path,
    *,
    required_tables: Iterable[str] = DEFAULT_REQUIRED_TABLES,
    max_dangerous_examples: int = 100,
) -> dict[str, Any]:
    """Decompress and classify a SQLite dump without executing or persisting SQL."""
    if not input_path.is_file():
        raise SqlDumpAuditError(f"input gzip is not a regular file: {input_path}")
    required = {str(table).strip() for table in required_tables if str(table).strip()}
    if not required:
        raise SqlDumpAuditError("at least one required table is needed")
    if max_dangerous_examples <= 0:
        raise SqlDumpAuditError("max_dangerous_examples must be positive")

    with gzip.open(input_path, "rb") as stream:
        audit = audit_sqlite_dump_lines(
            stream,
            required_tables=required,
            max_dangerous_examples=max_dangerous_examples,
        )
    audit["input"] = {
        "path": str(input_path.resolve()),
        "compressed_bytes": input_path.stat().st_size,
    }
    return audit


def audit_sqlite_dump_lines(
    lines: Iterable[bytes],
    *,
    required_tables: Iterable[str] = DEFAULT_REQUIRED_TABLES,
    max_dangerous_examples: int = 100,
) -> dict[str, Any]:
    """Classify statement-start lines while retaining no source-code payload."""
    required = {str(table).strip() for table in required_tables if str(table).strip()}
    if not required:
        raise SqlDumpAuditError("at least one required table is needed")
    if max_dangerous_examples <= 0:
        raise SqlDumpAuditError("max_dangerous_examples must be positive")

    sha256 = hashlib.sha256()
    uncompressed_bytes = 0
    line_count = 0
    table_names: set[str] = set()
    dangerous_count = 0
    dangerous_examples: list[dict[str, Any]] = []
    counts = {
        "allowed_pragma_lines": 0,
        "begin_transaction_lines": 0,
        "commit_lines": 0,
        "create_index_lines": 0,
        "create_table_lines": 0,
        "insert_lines": 0,
        "other_pragma_lines": 0,
    }
    for raw_line in lines:
        if not isinstance(raw_line, bytes):
            raise SqlDumpAuditError("SQL dump lines must be bytes")
        sha256.update(raw_line)
        uncompressed_bytes += len(raw_line)
        line_count += 1
        stripped = raw_line.lstrip()
        table_match = _CREATE_TABLE.match(stripped)
        if table_match:
            counts["create_table_lines"] += 1
            table_names.add(table_match.group(1).decode("ascii"))
        elif _CREATE_INDEX.match(stripped):
            counts["create_index_lines"] += 1
        elif _INSERT.match(stripped):
            counts["insert_lines"] += 1
        elif stripped.upper().startswith(b"BEGIN TRANSACTION"):
            counts["begin_transaction_lines"] += 1
        elif stripped.upper().startswith(b"COMMIT"):
            counts["commit_lines"] += 1

        dangerous_reason: str | None = None
        if _ALLOWED_PRAGMA.match(raw_line):
            counts["allowed_pragma_lines"] += 1
        elif _ANY_PRAGMA.match(raw_line):
            counts["other_pragma_lines"] += 1
            dangerous_reason = "unapproved_pragma"
        else:
            for pattern in _DANGEROUS_STARTS:
                if pattern.match(raw_line):
                    dangerous_reason = "dangerous_statement_start"
                    break
        if dangerous_reason is not None:
            dangerous_count += 1
            if len(dangerous_examples) < max_dangerous_examples:
                dangerous_examples.append(
                    {
                        "line_number": line_count,
                        "reason": dangerous_reason,
                        "line_prefix": raw_line[:160].decode(
                            "utf-8",
                            errors="backslashreplace",
                        ),
                    }
                )

    missing_tables = sorted(required - table_names)
    checks = {
        "required_tables_present": not missing_tables,
        "create_table_statements_present": counts["create_table_lines"] > 0,
        "insert_statements_present": counts["insert_lines"] > 0,
        "transaction_boundary_present": (
            counts["begin_transaction_lines"] > 0 and counts["commit_lines"] > 0
        ),
        "dangerous_statement_starts_absent": dangerous_count == 0,
    }
    passed = all(checks.values())
    return {
        "schema_version": SQL_DUMP_AUDIT_SCHEMA_VERSION,
        "stream": {
            "uncompressed_bytes": uncompressed_bytes,
            "line_count": line_count,
            "uncompressed_sha256": sha256.hexdigest(),
        },
        "statements": counts,
        "table_names": sorted(table_names),
        "required_tables": sorted(required),
        "missing_tables": missing_tables,
        "dangerous_statement_start_count": dangerous_count,
        "dangerous_examples": dangerous_examples,
        "checks": checks,
        "failure_reasons": sorted(name for name, value in checks.items() if not value),
        "decision": "sql_static_audit_pass" if passed else "sql_static_audit_fail",
        "approved_for_isolated_import": passed,
        "approved_for_processing": False,
        "approved_for_training": False,
        "safety": {
            "sql_execution_count": 0,
            "decompressed_output_write_count": 0,
            "source_payload_retained_count": 0,
            "object_execution_count": 0,
        },
    }
