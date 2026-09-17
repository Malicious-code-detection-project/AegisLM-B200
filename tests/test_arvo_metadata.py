from __future__ import annotations

import sqlite3
from pathlib import Path

from aegislm.datasets.arvo import audit_arvo_metadata


def _database(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE arvo (
                localId INTEGER PRIMARY KEY,
                project TEXT NOT NULL,
                reproduced BOOLEAN NOT NULL,
                reproducer_vul TEXT,
                reproducer_fix TEXT,
                patch_located BOOLEAN,
                patch_url TEXT,
                verified BOOLEAN,
                fuzz_target TEXT,
                fuzz_engine TEXT,
                sanitizer TEXT,
                crash_type TEXT,
                crash_output TEXT,
                severity TEXT,
                report TEXT,
                fix_commit TEXT,
                language TEXT,
                repo_addr TEXT,
                submodule_bug BOOLEAN
            )
            """
        )
        families = [
            "Heap-buffer-overflow READ 1",
            "Heap-buffer-overflow WRITE 1",
            "Stack-buffer-overflow READ 1",
            "Stack-buffer-overflow WRITE 1",
        ]
        local_id = 1
        for family in families:
            for project in ("alpha", "beta"):
                connection.execute(
                    """
                    INSERT INTO arvo VALUES (
                        ?, ?, 1, 'do-not-read', 'do-not-read', 1,
                        ?, 0, 'target', 'engine', 'asan', ?,
                        'do-not-read', 'HIGH', 'do-not-read', ?,
                        'c++', ?, 0
                    )
                    """,
                    (
                        local_id,
                        project,
                        f"https://example.test/{local_id}.patch",
                        family,
                        f"commit-{local_id}",
                        f"https://example.test/{project}.git",
                    ),
                )
                local_id += 1


def test_arvo_metadata_audit_is_safe_deterministic_and_quarantined(
    tmp_path: Path,
) -> None:
    database = tmp_path / "arvo.db"
    _database(database)

    first = audit_arvo_metadata(database, seed=7, family_quota=1)
    second = audit_arvo_metadata(database, seed=7, family_quota=1)

    assert first == second
    assert first["decision"] == "manual_feasibility_ready"
    assert first["selection"]["selected_count"] == 4
    assert first["approved_for_training"] is False
    assert first["safety"]["raw_payload_read_count"] == 0
    assert "crash_output" not in first["safety"]["queried_columns"]
    assert "reproducer_vul" not in first["safety"]["queried_columns"]
    assert all(
        row["disposition"] == "quarantine" for row in first["selected_candidates"]
    )
    assert {row["candidate_cwe"] for row in first["selected_candidates"]} == {
        "CWE-121",
        "CWE-122",
        "CWE-126",
    }
