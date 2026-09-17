"""Inventory an Assemblage DuckDB schema without reading source or binary values."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.datasets.assemblage_metadata import (  # noqa: E402
    build_schema_inventory,
    schema_field_candidates,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    try:
        import duckdb  # type: ignore[import-not-found]
    except ImportError as exc:
        raise SystemExit(
            "duckdb is required; run with `uv run --with duckdb ...`"
        ) from exc

    database_sha256 = _sha256(args.database)
    connection = duckdb.connect(str(args.database), read_only=True)
    try:
        schema_rows = connection.execute(
            """
            SELECT table_name, column_name, data_type, ordinal_position, is_nullable
            FROM information_schema.columns
            WHERE table_schema = 'main'
            ORDER BY table_name, ordinal_position
            """
        ).fetchall()
        table_rows = connection.execute(
            """
            SELECT table_name, estimated_size
            FROM duckdb_tables()
            WHERE internal = false
            ORDER BY table_name
            """
        ).fetchall()
        constraint_rows = connection.execute(
            """
            SELECT table_name, constraint_type, constraint_text,
                   referenced_table
            FROM duckdb_constraints()
            WHERE database_name = current_database()
            ORDER BY table_name, constraint_index
            """
        ).fetchall()
    finally:
        connection.close()

    result: dict[str, Any] = build_schema_inventory(
        database_path=args.database,
        database_sha256=database_sha256,
        schema_rows=schema_rows,
        table_rows=table_rows,
        constraint_rows=constraint_rows,
    )
    result["field_candidates"] = schema_field_candidates(result)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Assemblage schema inventory: "
        f"decision={result['decision']}, tables={len(result['tables'])}"
    )
    if result["decision"] != "schema_inventory_pass":
        raise SystemExit(1)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(16 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    main()
