"""Safe metadata-only audit helpers for the ARVO vulnerability dataset."""

from __future__ import annotations

import hashlib
import sqlite3
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ARVO_AUDIT_SCHEMA_VERSION = "aegislm.phase-f-arvo-metadata-audit.v1"
ARVO_DEFAULT_SEED = 20260731
ARVO_DEFAULT_FAMILY_QUOTA = 50
ARVO_FAMILY_CWE = {
    "heap_buffer_read": "CWE-126",
    "heap_buffer_write": "CWE-122",
    "stack_buffer_read": "CWE-126",
    "stack_buffer_write": "CWE-121",
}
ARVO_QUERIED_COLUMNS = (
    "localId",
    "project",
    "reproduced",
    "patch_located",
    "patch_url",
    "sanitizer",
    "crash_type",
    "severity",
    "fix_commit",
    "language",
    "repo_addr",
)


def audit_arvo_metadata(
    database: Path,
    *,
    seed: int = ARVO_DEFAULT_SEED,
    family_quota: int = ARVO_DEFAULT_FAMILY_QUOTA,
) -> dict[str, Any]:
    """Audit ARVO metadata without reading PoCs, reports, or crash output."""
    if family_quota <= 0:
        raise ValueError("family_quota must be positive")
    rows = _load_safe_rows(database)
    eligible: dict[str, list[dict[str, Any]]] = defaultdict(list)
    family_counts: Counter[str] = Counter()
    for row in rows:
        family = _crash_family(str(row["crash_type"]))
        if family is None:
            continue
        family_counts[family] += 1
        if not _metadata_candidate_eligible(row):
            continue
        candidate = {
            "candidate_cwe": ARVO_FAMILY_CWE[family],
            "crash_family": family,
            "crash_type": str(row["crash_type"]),
            "disposition": "quarantine",
            "disposition_reason": "manual_patch_and_cwe_mapping_required",
            "fix_commit": str(row["fix_commit"]),
            "language": str(row["language"]).lower(),
            "local_id": int(row["localId"]),
            "patch_url": str(row["patch_url"]),
            "project": str(row["project"]),
            "repo_addr": str(row["repo_addr"]),
            "sanitizer": str(row["sanitizer"]),
            "severity": str(row["severity"] or ""),
        }
        eligible[family].append(candidate)

    selected: list[dict[str, Any]] = []
    selected_counts: dict[str, int] = {}
    for family in sorted(ARVO_FAMILY_CWE):
        family_rows = _select_project_diverse(
            eligible.get(family, []),
            seed=seed,
            family=family,
            quota=family_quota,
        )
        selected.extend(family_rows)
        selected_counts[family] = len(family_rows)

    return {
        "schema_version": ARVO_AUDIT_SCHEMA_VERSION,
        "source": {
            "database_path": str(database),
            "database_sha256": _sha256(database),
        },
        "selection": {
            "seed": seed,
            "family_quota": family_quota,
            "selected_count": len(selected),
            "selected_family_counts": selected_counts,
        },
        "inventory": {
            "total_record_count": len(rows),
            "family_record_counts": dict(sorted(family_counts.items())),
            "eligible_family_counts": {
                family: len(eligible.get(family, []))
                for family in sorted(ARVO_FAMILY_CWE)
            },
        },
        "safety": {
            "queried_columns": list(ARVO_QUERIED_COLUMNS),
            "raw_payload_read_count": 0,
            "reproducer_execution_count": 0,
            "object_execution_count": 0,
            "docker_image_pull_count": 0,
        },
        "decision": (
            "manual_feasibility_ready"
            if all(count == family_quota for count in selected_counts.values())
            else "insufficient_metadata_supply"
        ),
        "approved_for_training": False,
        "selected_candidates": selected,
    }


def _load_safe_rows(database: Path) -> list[dict[str, Any]]:
    uri = f"{database.resolve().as_uri()}?mode=ro"
    query = f"SELECT {', '.join(ARVO_QUERIED_COLUMNS)} FROM arvo"  # noqa: S608
    with sqlite3.connect(uri, uri=True) as connection:
        connection.row_factory = sqlite3.Row
        return [dict(row) for row in connection.execute(query)]


def _metadata_candidate_eligible(row: Mapping[str, Any]) -> bool:
    return (
        bool(row["reproduced"])
        and bool(row["patch_located"])
        and str(row["language"]).lower() in {"c", "c++"}
        and all(
            str(row[field] or "").strip()
            for field in ("patch_url", "fix_commit", "repo_addr")
        )
    )


def _crash_family(crash_type: str) -> str | None:
    normalized = crash_type.lower()
    for prefix, family in (
        ("heap-buffer-overflow read", "heap_buffer_read"),
        ("heap-buffer-overflow write", "heap_buffer_write"),
        ("stack-buffer-overflow read", "stack_buffer_read"),
        ("stack-buffer-overflow write", "stack_buffer_write"),
    ):
        if normalized.startswith(prefix):
            return family
    return None


def _select_project_diverse(
    rows: Sequence[dict[str, Any]],
    *,
    seed: int,
    family: str,
    quota: int,
) -> list[dict[str, Any]]:
    by_project: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_project[str(row["project"])].append(row)
    ranked_projects = sorted(
        by_project,
        key=lambda project: _rank(seed, family, project),
    )
    for project in ranked_projects:
        by_project[project].sort(
            key=lambda row: _rank(seed, family, project, str(row["local_id"]))
        )

    selected: list[dict[str, Any]] = []
    round_index = 0
    while len(selected) < quota:
        added = False
        for project in ranked_projects:
            project_rows = by_project[project]
            if round_index < len(project_rows):
                selected.append(project_rows[round_index])
                added = True
                if len(selected) == quota:
                    break
        if not added:
            break
        round_index += 1
    return selected


def _rank(seed: int, *parts: str) -> str:
    material = ":".join((str(seed), *parts)).encode()
    return hashlib.sha256(material).hexdigest()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
