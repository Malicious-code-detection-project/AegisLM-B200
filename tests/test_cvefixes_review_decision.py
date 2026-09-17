from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegislm.datasets.cvefixes_review import (
    CVEFIXES_REVIEW_QUEUE_SCHEMA_VERSION,
)
from aegislm.datasets.cvefixes_review_decision import (
    CVEFIXES_REVIEW_UPDATES_SCHEMA_VERSION,
    CvefixesReviewDecisionError,
    apply_cvefixes_review_updates,
    build_cvefixes_review_decision_template,
    evaluate_cvefixes_review_decisions,
    render_cvefixes_review_packets,
)


def _queue(path: Path, count: int = 3) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": CVEFIXES_REVIEW_QUEUE_SCHEMA_VERSION,
                "decision": "manual_review_ready",
                "approved_for_manual_review": True,
                "approved_for_training": False,
                "records": [
                    {
                        "candidate_id": f"candidate-{index}",
                        "target_cwe": f"CWE-{120 + index}",
                        "cve_ids": [f"CVE-{index}"],
                        "programming_language": "C",
                        "repository_url": "https://example.test/repo",
                        "commit_hash": f"commit-{index}",
                        "function_diff": "-unsafe();\n+safe();\n",
                        "before_code": "void f() { unsafe(); }",
                        "after_code": "void f() { safe(); }",
                    }
                    for index in range(count)
                ],
            }
        ),
        encoding="utf-8",
    )


def _write_decisions(path: Path, decisions: dict[str, object]) -> None:
    path.write_text(json.dumps(decisions), encoding="utf-8")


def test_review_packet_and_template_are_hash_bound(tmp_path: Path) -> None:
    queue = tmp_path / "queue.json"
    packet_dir = tmp_path / "packets"
    _queue(queue)

    packet_result = render_cvefixes_review_packets(
        queue,
        packet_dir,
        batch_size=2,
    )
    decisions = build_cvefixes_review_decision_template(queue)

    assert packet_result["records"] == 3
    assert packet_result["packet_count"] == 2
    assert (packet_dir / "index.md").is_file()
    packet = (packet_dir / "review-batch-01.md").read_text(encoding="utf-8")
    assert "candidate-0" in packet
    assert "Function diff" in packet
    assert decisions["queue_sha256"] == packet_result["queue_sha256"]
    assert len(decisions["records"]) == 3
    assert decisions["records"][0]["operator_pair_quality"] is None


def test_review_evaluator_passes_only_complete_in_budget_decisions(
    tmp_path: Path,
) -> None:
    queue = tmp_path / "queue.json"
    decisions_path = tmp_path / "decisions.json"
    _queue(queue)
    decisions = build_cvefixes_review_decision_template(queue, error_budget=1)
    for record in decisions["records"]:
        record["operator_patch_related"] = True
        record["operator_cwe_supported"] = True
        record["operator_pair_quality"] = "pass"
    decisions["records"][0]["operator_cwe_supported"] = False
    decisions["records"][0]["operator_pair_quality"] = "fail"
    decisions["records"][0]["error_kinds"] = ["cwe_mismatch"]
    _write_decisions(decisions_path, decisions)

    result = evaluate_cvefixes_review_decisions(queue, decisions_path)

    assert result["decision"] == "manual_review_pass"
    assert result["summary"]["finished_records"] == 3
    assert result["summary"]["error_records"] == 1
    assert result["approved_for_label_quality"] is True
    assert result["approved_for_repository_license_review"] is True
    assert result["approved_for_training"] is False
    assert result["safety"]["raw_code_return_count"] == 0


def test_review_evaluator_fails_early_before_all_records_finish(
    tmp_path: Path,
) -> None:
    queue = tmp_path / "queue.json"
    decisions_path = tmp_path / "decisions.json"
    _queue(queue, count=4)
    decisions = build_cvefixes_review_decision_template(queue, error_budget=1)
    for record in decisions["records"][:2]:
        record["operator_patch_related"] = False
        record["operator_cwe_supported"] = False
        record["operator_pair_quality"] = "fail"
        record["error_kinds"] = ["patch_unrelated_to_cwe"]
    _write_decisions(decisions_path, decisions)

    result = evaluate_cvefixes_review_decisions(queue, decisions_path)

    assert result["decision"] == "manual_review_fail_early"
    assert result["summary"]["finished_records"] == 2
    assert result["summary"]["error_records"] == 2
    assert result["summary"]["unfinished_records"] == 2
    assert result["approved_for_label_quality"] is False
    assert result["approved_for_training"] is False


def test_review_evaluator_rejects_partial_and_hash_mismatch(
    tmp_path: Path,
) -> None:
    queue = tmp_path / "queue.json"
    decisions_path = tmp_path / "decisions.json"
    _queue(queue)
    decisions = build_cvefixes_review_decision_template(queue)
    decisions["records"][0]["operator_patch_related"] = True
    _write_decisions(decisions_path, decisions)

    with pytest.raises(CvefixesReviewDecisionError, match="partially finished"):
        evaluate_cvefixes_review_decisions(queue, decisions_path)

    decisions["records"][0]["operator_patch_related"] = None
    decisions["queue_sha256"] = "0" * 64
    _write_decisions(decisions_path, decisions)
    with pytest.raises(CvefixesReviewDecisionError, match="hash mismatch"):
        evaluate_cvefixes_review_decisions(queue, decisions_path)


def test_review_updates_apply_atomically_and_refuse_overwrite(
    tmp_path: Path,
) -> None:
    queue = tmp_path / "queue.json"
    decisions_path = tmp_path / "decisions.json"
    updates_path = tmp_path / "updates.json"
    _queue(queue)
    decisions = build_cvefixes_review_decision_template(queue)
    _write_decisions(decisions_path, decisions)
    update = {
        "candidate_id": "candidate-0",
        "operator_patch_related": True,
        "operator_cwe_supported": True,
        "operator_pair_quality": "pass",
        "error_kinds": [],
        "operator_notes": "Direct guard and matching CWE.",
    }
    updates = {
        "schema_version": CVEFIXES_REVIEW_UPDATES_SCHEMA_VERSION,
        "queue_sha256": decisions["queue_sha256"],
        "records": [update],
    }
    _write_decisions(updates_path, updates)

    first = apply_cvefixes_review_updates(decisions_path, updates_path)
    second = apply_cvefixes_review_updates(decisions_path, updates_path)

    assert first["applied_records"] == 1
    assert second["unchanged_records"] == 1
    changed = dict(update)
    changed["operator_notes"] = "Conflicting replacement."
    updates["records"] = [changed]
    _write_decisions(updates_path, updates)
    with pytest.raises(CvefixesReviewDecisionError, match="refusing to overwrite"):
        apply_cvefixes_review_updates(decisions_path, updates_path)
