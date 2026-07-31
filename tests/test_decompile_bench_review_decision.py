from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegislm.datasets.decompile_bench_review import (
    DECOMPILE_BENCH_REVIEW_QUEUE_SCHEMA_VERSION,
)
from aegislm.datasets.decompile_bench_review_decision import (
    DECOMPILE_BENCH_REVIEW_UPDATES_SCHEMA_VERSION,
    DecompileBenchReviewDecisionError,
    apply_decompile_bench_review_updates,
    build_decompile_bench_review_decision_template,
    evaluate_decompile_bench_review_decisions,
    render_decompile_bench_review_packets,
)


def _queue(path: Path, count: int = 3) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": DECOMPILE_BENCH_REVIEW_QUEUE_SCHEMA_VERSION,
                "decision": "manual_alignment_review_ready",
                "approved_for_manual_alignment_review": True,
                "approved_for_training": False,
                "records": [
                    {
                        "candidate_id": f"candidate-{index}",
                        "function_name": f"f{index}",
                        "source_code": f"int f{index}() {{ return {index}; }}",
                        "assembly": f"mov eax, {index}",
                        "source_chars": 22,
                        "assembly_chars": 10,
                    }
                    for index in range(count)
                ],
            }
        ),
        encoding="utf-8",
    )


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def _pass(record: dict[str, object]) -> None:
    record["operator_same_function"] = True
    record["operator_source_complete"] = True
    record["operator_semantic_alignment"] = "pass"


def test_packets_and_template_are_hash_bound(tmp_path: Path) -> None:
    queue = tmp_path / "queue.json"
    packet_dir = tmp_path / "packets"
    _queue(queue)

    packets = render_decompile_bench_review_packets(
        queue,
        packet_dir,
        batch_size=2,
    )
    decisions = build_decompile_bench_review_decision_template(queue)

    assert packets["records"] == 3
    assert packets["packet_count"] == 2
    assert decisions["queue_sha256"] == packets["queue_sha256"]
    assert "candidate-0" in (packet_dir / "review-batch-01.md").read_text(
        encoding="utf-8"
    )
    assert decisions["error_budget"] == 5


def test_complete_review_passes_with_errors_inside_budget(tmp_path: Path) -> None:
    queue = tmp_path / "queue.json"
    decisions_path = tmp_path / "decisions.json"
    _queue(queue)
    decisions = build_decompile_bench_review_decision_template(
        queue,
        error_budget=1,
    )
    for record in decisions["records"]:
        _pass(record)
    decisions["records"][0]["operator_semantic_alignment"] = "uncertain"
    decisions["records"][0]["error_kinds"] = ["insufficient_context"]
    _write(decisions_path, decisions)

    result = evaluate_decompile_bench_review_decisions(queue, decisions_path)

    assert result["decision"] == "manual_alignment_review_pass"
    assert result["summary"]["error_records"] == 1
    assert result["approved_for_alignment_quality"] is True
    assert result["approved_for_processing"] is False
    assert result["safety"]["raw_binary_read_count"] == 0


def test_sixth_error_fails_before_review_completion(tmp_path: Path) -> None:
    queue = tmp_path / "queue.json"
    decisions_path = tmp_path / "decisions.json"
    _queue(queue, count=10)
    decisions = build_decompile_bench_review_decision_template(queue)
    for record in decisions["records"][:6]:
        record["operator_same_function"] = False
        record["operator_source_complete"] = True
        record["operator_semantic_alignment"] = "fail"
        record["error_kinds"] = ["different_function"]
    _write(decisions_path, decisions)

    result = evaluate_decompile_bench_review_decisions(queue, decisions_path)

    assert result["decision"] == "manual_alignment_review_fail_early"
    assert result["summary"]["finished_records"] == 6
    assert result["summary"]["error_records"] == 6
    assert result["summary"]["unfinished_records"] == 4


def test_partial_decision_and_hash_mismatch_are_rejected(tmp_path: Path) -> None:
    queue = tmp_path / "queue.json"
    decisions_path = tmp_path / "decisions.json"
    _queue(queue)
    decisions = build_decompile_bench_review_decision_template(queue)
    decisions["records"][0]["operator_same_function"] = True
    _write(decisions_path, decisions)

    with pytest.raises(
        DecompileBenchReviewDecisionError,
        match="partially finished",
    ):
        evaluate_decompile_bench_review_decisions(queue, decisions_path)

    decisions["records"][0]["operator_same_function"] = None
    decisions["queue_sha256"] = "0" * 64
    _write(decisions_path, decisions)
    with pytest.raises(DecompileBenchReviewDecisionError, match="hash mismatch"):
        evaluate_decompile_bench_review_decisions(queue, decisions_path)


def test_updates_are_atomic_and_refuse_conflicting_overwrite(
    tmp_path: Path,
) -> None:
    queue = tmp_path / "queue.json"
    decisions_path = tmp_path / "decisions.json"
    updates_path = tmp_path / "updates.json"
    _queue(queue)
    decisions = build_decompile_bench_review_decision_template(queue)
    _write(decisions_path, decisions)
    update = dict(decisions["records"][0])
    _pass(update)
    updates = {
        "schema_version": DECOMPILE_BENCH_REVIEW_UPDATES_SCHEMA_VERSION,
        "queue_sha256": decisions["queue_sha256"],
        "records": [update],
    }
    _write(updates_path, updates)

    first = apply_decompile_bench_review_updates(decisions_path, updates_path)
    second = apply_decompile_bench_review_updates(decisions_path, updates_path)

    assert first["applied_records"] == 1
    assert second["unchanged_records"] == 1
    update["operator_notes"] = "conflicting replacement"
    updates["records"] = [update]
    _write(updates_path, updates)
    with pytest.raises(
        DecompileBenchReviewDecisionError,
        match="refusing to overwrite",
    ):
        apply_decompile_bench_review_updates(decisions_path, updates_path)
