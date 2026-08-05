from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from aegislm.datasets.arvo_patch import (
    ArvoPatchError,
    apply_arvo_patch_manual_decisions,
    collect_arvo_patch_review,
    github_patch_download_url,
    refresh_arvo_patch_review,
    render_arvo_patch_manual_review,
    summarize_arvo_patch_manual_review,
    summarize_patch,
)


def _github_database(path: Path) -> None:
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
            for _ in range(2):
                commit = f"{local_id:040x}"
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
                        f"project-{local_id}",
                        f"https://github.com/example/project-{local_id}/commit/{commit}",
                        family,
                        commit,
                        f"https://github.com/example/project-{local_id}",
                    ),
                )
                local_id += 1


def _patch(_: str, __: int) -> bytes:
    return b"""From 0000000000000000000000000000000000000001 Mon Sep 17 00:00:00 2001
diff --git a/sample.c b/sample.c
index 1111111..2222222 100644
--- a/sample.c
+++ b/sample.c
@@ -1,2 +1,3 @@
-memcpy(dst, src, size);
+if (size <= capacity)
+    memcpy(dst, src, size);
"""


def test_collect_arvo_patch_review_is_unique_balanced_and_payload_free(
    tmp_path: Path,
) -> None:
    database = tmp_path / "arvo.db"
    _github_database(database)

    result = collect_arvo_patch_review(
        database,
        tmp_path / "patches",
        fetcher=_patch,
        seed=7,
        family_quota=1,
    )

    assert result["selection"]["selected_count"] == 4
    assert result["selection"]["unique_patch_identity_count"] == 4
    assert result["gate"]["supply_pass"]
    assert result["gate"]["approved_for_training"] is False
    assert result["safety"]["raw_payload_read_count"] == 0
    assert result["safety"]["poc_read_count"] == 0
    assert all(
        row["patch_summary"]["automated_disposition"] == "manual_relation_review_ready"
        for row in result["review_records"]
    )
    assert len(list((tmp_path / "patches").glob("*.patch"))) == 4
    assert {row["patch_source"] for row in result["review_records"]} == {"network"}

    cached = collect_arvo_patch_review(
        database,
        tmp_path / "patches",
        fetcher=lambda _url, _limit: pytest.fail("cache should prevent refetch"),
        seed=7,
        family_quota=1,
    )
    assert {row["patch_source"] for row in cached["review_records"]} == {"cache"}
    refreshed = refresh_arvo_patch_review(cached)
    assert refreshed["review_records"][0]["patch_summary"]["hunk_count"] == 1

    patch_path = Path(refreshed["review_records"][0]["patch_path"])
    patch_path.write_bytes(_patch("", 1) + b"\n")
    with pytest.raises(ArvoPatchError, match="hash mismatch"):
        refresh_arvo_patch_review(refreshed)


def test_github_patch_url_rejects_mismatch_and_non_github() -> None:
    candidate = {
        "patch_url": "https://github.com/owner/repo/commit/abcdef1",
        "fix_commit": "abcdef123456",
    }
    assert github_patch_download_url(candidate).endswith("abcdef1.patch")
    with pytest.raises(ArvoPatchError, match="does not match"):
        github_patch_download_url({**candidate, "fix_commit": "1234567"})
    with pytest.raises(ArvoPatchError, match="only HTTPS"):
        github_patch_download_url(
            {
                **candidate,
                "patch_url": "https://example.test/owner/repo/commit/abcdef1",
            }
        )


def test_patch_summary_contains_only_bounded_review_evidence() -> None:
    summary = summarize_patch(_patch("", 1))
    assert summary["changed_file_count"] == 1
    assert summary["source_file_count"] == 1
    assert summary["hunk_count"] == 1
    assert "memcpy" in summary["review_excerpt"]
    assert len(summary["review_excerpt"]) <= 8000
    assert "@@ -1,2 +1,3 @@" in summary["review_excerpt"]


def test_collection_rejects_binary_or_non_source_patch_and_uses_reserve(
    tmp_path: Path,
) -> None:
    database = tmp_path / "arvo.db"
    _github_database(database)
    calls = 0

    def fetch(_url: str, _limit: int) -> bytes:
        nonlocal calls
        calls += 1
        if calls == 1:
            return b"""diff --git a/report.pdf b/report.pdf
new file mode 100644
GIT binary patch
literal 1
abc
"""
        return _patch("", 1)

    result = collect_arvo_patch_review(
        database,
        tmp_path / "patches",
        fetcher=fetch,
        seed=7,
        family_quota=1,
    )
    assert result["gate"]["supply_pass"]
    assert any(
        attempt["status"] == "fetch_or_validation_failed"
        and "binary diff" in attempt["detail"]
        for attempt in result["attempts"]
    )
    assert result["safety"]["git_binary_patch_count"] == 0


def test_arvo_patch_review_renderer_exposes_complete_rubric() -> None:
    summary = summarize_patch(_patch("", 1))
    rendered = render_arvo_patch_manual_review(
        [
            {
                "local_id": 1,
                "crash_family": "heap_buffer_write",
                "project": "example",
                "candidate_cwe": "CWE-122",
                "crash_type": "Heap-buffer-overflow WRITE 1",
                "patch_url": "https://github.com/example/repo/commit/abc",
                "patch_sha256": "abc",
                "patch_summary": summary,
            }
        ]
    )
    assert "operator_family_match" in rendered
    assert "operator_patch_evidence_error" in rendered
    assert "memcpy" in rendered


def test_arvo_patch_manual_gate_requires_booleans_and_applies_five_percent() -> None:
    unfinished = [
        {
            "local_id": 1,
            "operator_family_match": None,
            "operator_patch_evidence_error": None,
        }
    ]
    with pytest.raises(ArvoPatchError, match="unfinished boolean"):
        summarize_arvo_patch_manual_review(unfinished, required_count=1)

    passing = [
        {
            "local_id": index,
            "operator_family_match": True,
            "operator_patch_evidence_error": index == 0,
        }
        for index in range(20)
    ]
    summary = summarize_arvo_patch_manual_review(passing, required_count=20)
    assert summary["minimum_error_rate"] == 0.05
    assert summary["pass"]

    passing[1]["operator_family_match"] = False
    assert not summarize_arvo_patch_manual_review(
        passing,
        required_count=20,
    )["pass"]


def test_arvo_patch_manual_gate_can_fail_early_after_error_budget() -> None:
    records = [
        {
            "local_id": index,
            "operator_family_match": None,
            "operator_patch_evidence_error": None,
        }
        for index in range(20)
    ]
    decisions = [
        {
            "local_id": 0,
            "operator_family_match": False,
            "operator_patch_evidence_error": True,
            "operator_notes": "first confirmed error",
        },
        {
            "local_id": 1,
            "operator_family_match": False,
            "operator_patch_evidence_error": True,
            "operator_notes": "second confirmed error",
        },
    ]
    updated = apply_arvo_patch_manual_decisions(records, decisions)
    result = summarize_arvo_patch_manual_review(updated, required_count=20)
    assert result["status"] == "fail_early"
    assert result["reviewed_count"] == 2
    assert result["unfinished_count"] == 18
    assert result["error_budget"] == 1
    assert result["minimum_error_rate"] == 0.1
    assert not result["pass"]


def test_arvo_patch_manual_decisions_reject_duplicates_and_partial_values() -> None:
    records = [
        {
            "local_id": 1,
            "operator_family_match": None,
            "operator_patch_evidence_error": None,
        }
    ]
    invalid = [
        {
            "local_id": 1,
            "operator_family_match": True,
            "operator_patch_evidence_error": None,
        }
    ]
    with pytest.raises(ArvoPatchError, match="requires booleans"):
        apply_arvo_patch_manual_decisions(records, invalid)
    duplicate = [
        {
            "local_id": 1,
            "operator_family_match": True,
            "operator_patch_evidence_error": False,
        },
        {
            "local_id": 1,
            "operator_family_match": True,
            "operator_patch_evidence_error": False,
        },
    ]
    with pytest.raises(ArvoPatchError, match="duplicate"):
        apply_arvo_patch_manual_decisions(records, duplicate)
