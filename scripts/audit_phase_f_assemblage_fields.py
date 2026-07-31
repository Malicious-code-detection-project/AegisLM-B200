"""Audit Assemblage binary metadata coverage without reading source or binaries."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.datasets.assemblage_metadata import (  # noqa: E402
    build_field_audit,
)

_NONEMPTY = "{field} IS NOT NULL AND trim(cast({field} AS VARCHAR)) <> ''"
_ACTIONABLE_LICENSE = (
    "license IS NOT NULL AND lower(trim(license)) NOT IN ('', 'other', 'unknown')"
)
_COMPILER = "toolset_version IN ('gcc', 'clang')"
_OPTIMIZATION = "optimization IN ('-O0', '-O1', '-O2', '-O3', '-Os', '-Oz')"
_ARCHITECTURE = (
    "platform IS NOT NULL AND trim(platform) NOT IN ('', 'linux', '0') "
    "AND platform NOT LIKE '*unknown%'"
)
_BINARY_FORMAT = "binary_format IN ('ELF', 'PE')"
_REPO_COMMIT = _NONEMPTY.format(field="repo_commit")
_BUILD_MODE = _NONEMPTY.format(field="build_mode")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--expected-binary-rows", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    try:
        import duckdb  # type: ignore[import-not-found]
    except ImportError as exc:
        raise SystemExit(
            "duckdb is required; run with `uv run --with duckdb==1.5.5 ...`"
        ) from exc

    connection = duckdb.connect(str(args.database), read_only=True)
    try:
        total_rows = _scalar(connection, "SELECT count(*) FROM binaries")
        predicates = {
            "repository": _NONEMPTY.format(field="github_url"),
            "license_declared": _NONEMPTY.format(field="license"),
            "license_actionable": _ACTIONABLE_LICENSE,
            "compiler": _COMPILER,
            "optimization": _OPTIMIZATION,
            "architecture": _ARCHITECTURE,
            "binary_format": _BINARY_FORMAT,
            "repo_commit": _REPO_COMMIT,
            "build_mode": _BUILD_MODE,
            "binary_pointer": _NONEMPTY.format(field="path"),
            "binary_hash": _NONEMPTY.format(field="hash"),
        }
        coverage_counts = {
            name: _scalar(
                connection,
                f"SELECT count(*) FROM binaries WHERE {predicate}",
            )
            for name, predicate in predicates.items()
        }
        distinct_counts = {
            "repositories": _scalar(
                connection,
                "SELECT count(DISTINCT github_url) FROM binaries",
            ),
            "repository_commits": _scalar(
                connection,
                "SELECT count(DISTINCT repo_commit) FROM binaries "
                f"WHERE {_REPO_COMMIT}",
            ),
            "binary_hashes": _scalar(
                connection,
                "SELECT count(DISTINCT hash) FROM binaries",
            ),
            "binary_pointers": _scalar(
                connection,
                "SELECT count(DISTINCT path) FROM binaries",
            ),
        }
        strict_predicate = " AND ".join(
            predicates[name]
            for name in (
                "repository",
                "license_actionable",
                "compiler",
                "optimization",
                "architecture",
                "binary_format",
                "repo_commit",
                "build_mode",
                "binary_pointer",
                "binary_hash",
            )
        )
        trace_without_architecture = " AND ".join(
            predicates[name]
            for name in (
                "repository",
                "license_actionable",
                "compiler",
                "optimization",
                "binary_format",
                "repo_commit",
                "build_mode",
                "binary_pointer",
                "binary_hash",
            )
        )
        architecture_without_trace = " AND ".join(
            predicates[name]
            for name in (
                "repository",
                "license_actionable",
                "compiler",
                "optimization",
                "architecture",
                "binary_pointer",
                "binary_hash",
            )
        )
        distributions = {
            field: connection.execute(
                f"""
                SELECT {field}, count(*) AS row_count
                FROM binaries
                GROUP BY {field}
                ORDER BY row_count DESC, {field}
                """
            ).fetchall()
            for field in (
                "platform",
                "binary_format",
                "optimization",
                "toolset_version",
                "build_mode",
                "license",
            )
        }
        result: dict[str, Any] = build_field_audit(
            total_rows=total_rows,
            expected_rows=args.expected_binary_rows,
            coverage_counts=coverage_counts,
            distinct_counts=distinct_counts,
            strict_complete_rows=_scalar(
                connection,
                f"SELECT count(*) FROM binaries WHERE {strict_predicate}",
            ),
            trace_without_architecture_rows=_scalar(
                connection,
                f"SELECT count(*) FROM binaries WHERE {trace_without_architecture}",
            ),
            architecture_without_trace_rows=_scalar(
                connection,
                f"SELECT count(*) FROM binaries WHERE {architecture_without_trace}",
            ),
            distributions=distributions,
        )
    finally:
        connection.close()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Assemblage metadata field audit: "
        f"decision={result['decision']}, "
        f"strict_complete={result['summary']['strict_complete_rows']}"
    )
    if result["decision"] != "metadata_quality_pass":
        raise SystemExit(1)


def _scalar(connection: Any, query: str) -> int:
    row = connection.execute(query).fetchone()
    if row is None:
        raise RuntimeError("aggregate query returned no row")
    return int(row[0])


if __name__ == "__main__":
    main()
