"""Statically audit the CVEfixes SQLite dump without executing SQL."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.datasets.sql_dump import audit_gzip_sqlite_dump  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    started = time.monotonic()
    result = audit_gzip_sqlite_dump(args.input)
    result["elapsed_seconds"] = time.monotonic() - started
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Phase F CVEfixes SQL static audit: "
        f"decision={result['decision']}, "
        f"tables={len(result['table_names'])}, "
        f"dangerous={result['dangerous_statement_start_count']}, "
        f"sql_executions={result['safety']['sql_execution_count']}"
    )
    if result["decision"] != "sql_static_audit_pass":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
