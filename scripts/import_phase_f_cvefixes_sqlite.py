"""Defensively import the statically audited CVEfixes SQLite dump."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.datasets.sqlite_import import (  # noqa: E402
    import_audited_sqlite_dump,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--static-audit", type=Path, required=True)
    parser.add_argument("--output-database", type=Path, required=True)
    parser.add_argument("--output-report", type=Path, required=True)
    args = parser.parse_args()
    result = import_audited_sqlite_dump(
        args.input,
        args.static_audit,
        args.output_database,
    )
    args.output_report.parent.mkdir(parents=True, exist_ok=True)
    args.output_report.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Phase F CVEfixes defensive import: "
        f"decision={result['decision']}, "
        f"statements={result['import']['statement_count']}, "
        f"bytes={result['database']['bytes']}"
    )


if __name__ == "__main__":
    main()
