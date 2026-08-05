"""Human-readable Decompile-Bench alignment review and fail-early decisions."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from aegislm.datasets.decompile_bench_review import (
    DECOMPILE_BENCH_REVIEW_QUEUE_SCHEMA_VERSION,
)

DECOMPILE_BENCH_REVIEW_DECISIONS_SCHEMA_VERSION = (
    "aegislm.phase-f-decompile-bench-alignment-review-decisions.v1"
)
DECOMPILE_BENCH_REVIEW_UPDATES_SCHEMA_VERSION = (
    "aegislm.phase-f-decompile-bench-alignment-review-updates.v1"
)
DECOMPILE_BENCH_REVIEW_RESULT_SCHEMA_VERSION = (
    "aegislm.phase-f-decompile-bench-alignment-review-result.v1"
)
ALIGNMENT_VALUES = {"pass", "uncertain", "fail"}
ERROR_KINDS = {
    "different_function",
    "source_incomplete",
    "assembly_truncated",
    "semantic_mismatch",
    "insufficient_context",
    "other",
}


class DecompileBenchReviewDecisionError(ValueError):
    """Raised when alignment review inputs or decisions are invalid."""


def render_decompile_bench_review_packets(
    queue_path: Path,
    output_dir: Path,
    *,
    batch_size: int = 10,
) -> dict[str, Any]:
    """Render fixed source-assembly batches for operator review."""
    queue = _load_review_queue(queue_path)
    if batch_size <= 0:
        raise DecompileBenchReviewDecisionError("batch_size must be positive")
    records = queue["records"]
    output_dir.mkdir(parents=True, exist_ok=True)
    packet_paths: list[Path] = []
    queue_sha256 = _sha256_file(queue_path)
    for offset in range(0, len(records), batch_size):
        batch = records[offset : offset + batch_size]
        number = (offset // batch_size) + 1
        path = output_dir / f"review-batch-{number:02d}.md"
        path.write_text(
            _render_batch(
                batch,
                packet_number=number,
                start_index=offset + 1,
                queue_sha256=queue_sha256,
            ),
            encoding="utf-8",
        )
        packet_paths.append(path)

    index_path = output_dir / "index.md"
    lines = [
        "# Decompile-Bench Source–Assembly Alignment Review",
        "",
        f"- queue SHA-256: `{queue_sha256}`",
        f"- records: `{len(records)}`",
        f"- batch size: `{batch_size}`",
        f"- packets: `{len(packet_paths)}`",
        "- error budget: `5 / 100`; the sixth error stops the review",
        "- `uncertain` counts as an error",
        "- model visible: `false`",
        "",
        "Judge whether each source and assembly pair describes the same complete "
        "function and preserves its major control flow, calls, and state changes.",
        "",
    ]
    lines.extend(f"- [{path.stem}]({path.name})" for path in packet_paths)
    index_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {
        "queue_sha256": queue_sha256,
        "records": len(records),
        "batch_size": batch_size,
        "packet_count": len(packet_paths),
        "index_path": str(index_path.resolve()),
        "packet_paths": [str(path.resolve()) for path in packet_paths],
    }


def build_decompile_bench_review_decision_template(
    queue_path: Path,
    *,
    error_budget: int = 5,
) -> dict[str, Any]:
    """Create a code-free, queue-hash-bound operator decision template."""
    queue = _load_review_queue(queue_path)
    if error_budget < 0:
        raise DecompileBenchReviewDecisionError("error_budget must be non-negative")
    return {
        "schema_version": DECOMPILE_BENCH_REVIEW_DECISIONS_SCHEMA_VERSION,
        "queue_sha256": _sha256_file(queue_path),
        "error_budget": error_budget,
        "review_policy": {
            "uncertain_counts_as_error": True,
            "fail_early_when_errors_exceed_budget": True,
            "review_order_is_queue_order": True,
        },
        "records": [
            {
                "candidate_id": str(record["candidate_id"]),
                "operator_same_function": None,
                "operator_source_complete": None,
                "operator_semantic_alignment": None,
                "error_kinds": [],
                "operator_notes": "",
            }
            for record in queue["records"]
        ],
    }


def apply_decompile_bench_review_updates(
    decisions_path: Path,
    updates_path: Path,
) -> dict[str, Any]:
    """Apply complete decisions atomically and refuse conflicting overwrites."""
    decisions = _load_json_file(decisions_path, "decisions")
    updates = _load_json_file(updates_path, "updates")
    if (
        decisions.get("schema_version")
        != DECOMPILE_BENCH_REVIEW_DECISIONS_SCHEMA_VERSION
    ):
        raise DecompileBenchReviewDecisionError("unsupported decisions schema")
    if updates.get("schema_version") != DECOMPILE_BENCH_REVIEW_UPDATES_SCHEMA_VERSION:
        raise DecompileBenchReviewDecisionError("unsupported updates schema")
    if updates.get("queue_sha256") != decisions.get("queue_sha256"):
        raise DecompileBenchReviewDecisionError("update queue hash mismatch")
    records = updates.get("records")
    if not isinstance(records, list) or not records:
        raise DecompileBenchReviewDecisionError("update records are empty")
    update_ids = [str(record.get("candidate_id", "")) for record in records]
    if len(update_ids) != len(set(update_ids)):
        raise DecompileBenchReviewDecisionError("update candidate ids repeat")

    decision_by_id = {
        str(record["candidate_id"]): record for record in decisions["records"]
    }
    applied = 0
    unchanged = 0
    for update in records:
        _validate_decision_record(update)
        candidate_id = str(update["candidate_id"])
        if candidate_id not in decision_by_id:
            raise DecompileBenchReviewDecisionError(
                f"unknown update candidate id: {candidate_id}"
            )
        if not _decision_is_finished(update):
            raise DecompileBenchReviewDecisionError(
                f"{candidate_id}: update must be finished"
            )
        current = decision_by_id[candidate_id]
        if _decision_is_finished(current):
            if current != update:
                raise DecompileBenchReviewDecisionError(
                    f"{candidate_id}: refusing to overwrite existing decision"
                )
            unchanged += 1
            continue
        current.update(update)
        applied += 1

    _atomic_write_json(decisions_path, decisions)
    return {
        "queue_sha256": decisions["queue_sha256"],
        "applied_records": applied,
        "unchanged_records": unchanged,
        "decisions_sha256": _sha256_file(decisions_path),
    }


def evaluate_decompile_bench_review_decisions(
    queue_path: Path,
    decisions_path: Path,
) -> dict[str, Any]:
    """Enforce the fixed 5/100 alignment error budget."""
    queue = _load_review_queue(queue_path)
    decisions = _load_json_file(decisions_path, "decisions")
    _validate_decisions_document(queue_path, queue, decisions)

    queue_ids = [str(record["candidate_id"]) for record in queue["records"]]
    decision_by_id = {
        str(record["candidate_id"]): record for record in decisions["records"]
    }
    ordered = [decision_by_id[candidate_id] for candidate_id in queue_ids]
    finished = [record for record in ordered if _decision_is_finished(record)]
    unfinished = [
        str(record["candidate_id"])
        for record in ordered
        if not _decision_is_finished(record)
    ]
    errors = [record for record in finished if _decision_is_error(record)]
    passes = [record for record in finished if not _decision_is_error(record)]
    error_budget = int(decisions["error_budget"])
    fail_early = len(errors) > error_budget
    if fail_early:
        decision = "manual_alignment_review_fail_early"
    elif not unfinished:
        decision = "manual_alignment_review_pass"
    else:
        decision = "manual_alignment_review_in_progress"

    error_kind_counts: Counter[str] = Counter(
        str(kind) for record in errors for kind in record.get("error_kinds", [])
    )
    return {
        "schema_version": DECOMPILE_BENCH_REVIEW_RESULT_SCHEMA_VERSION,
        "source_artifacts": {
            "queue_sha256": _sha256_file(queue_path),
            "decisions_sha256": _sha256_file(decisions_path),
        },
        "policy": {
            "error_budget": error_budget,
            "uncertain_counts_as_error": True,
            "fail_early_when_errors_exceed_budget": True,
        },
        "summary": {
            "total_records": len(queue_ids),
            "finished_records": len(finished),
            "unfinished_records": len(unfinished),
            "passed_records": len(passes),
            "error_records": len(errors),
            "remaining_error_budget": max(0, error_budget - len(errors)),
            "error_kind_counts": dict(sorted(error_kind_counts.items())),
        },
        "unfinished_candidate_ids": unfinished,
        "records": [
            {
                "candidate_id": str(record["candidate_id"]),
                "operator_same_function": record["operator_same_function"],
                "operator_source_complete": record["operator_source_complete"],
                "operator_semantic_alignment": record["operator_semantic_alignment"],
                "error_kinds": list(record.get("error_kinds", [])),
                "operator_notes": str(record.get("operator_notes", "")),
                "counts_as_error": _decision_is_error(record),
            }
            for record in finished
        ],
        "decision": decision,
        "approved_for_alignment_quality": (decision == "manual_alignment_review_pass"),
        "approved_for_provenance_review": (decision == "manual_alignment_review_pass"),
        "approved_for_processing": False,
        "approved_for_training": False,
        "safety": {
            "raw_source_return_count": 0,
            "raw_assembly_return_count": 0,
            "raw_binary_read_count": 0,
            "source_code_execution_count": 0,
            "assembly_execution_count": 0,
        },
    }


def _load_review_queue(queue_path: Path) -> dict[str, Any]:
    queue = _load_json_file(queue_path, "review queue")
    if queue.get("schema_version") != DECOMPILE_BENCH_REVIEW_QUEUE_SCHEMA_VERSION:
        raise DecompileBenchReviewDecisionError("unsupported review queue schema")
    if queue.get("decision") != "manual_alignment_review_ready":
        raise DecompileBenchReviewDecisionError("review queue is not ready")
    if queue.get("approved_for_manual_alignment_review") is not True:
        raise DecompileBenchReviewDecisionError(
            "manual alignment review is not approved"
        )
    if queue.get("approved_for_training") is not False:
        raise DecompileBenchReviewDecisionError(
            "review queue training approval must remain false"
        )
    records = queue.get("records")
    if not isinstance(records, list) or not records:
        raise DecompileBenchReviewDecisionError("review queue records are empty")
    ids = [str(record["candidate_id"]) for record in records]
    if len(ids) != len(set(ids)):
        raise DecompileBenchReviewDecisionError("review queue candidate ids repeat")
    return queue


def _validate_decisions_document(
    queue_path: Path,
    queue: dict[str, Any],
    decisions: dict[str, Any],
) -> None:
    if (
        decisions.get("schema_version")
        != DECOMPILE_BENCH_REVIEW_DECISIONS_SCHEMA_VERSION
    ):
        raise DecompileBenchReviewDecisionError("unsupported decisions schema")
    if decisions.get("queue_sha256") != _sha256_file(queue_path):
        raise DecompileBenchReviewDecisionError("decision queue hash mismatch")
    error_budget = decisions.get("error_budget")
    if not isinstance(error_budget, int) or error_budget < 0:
        raise DecompileBenchReviewDecisionError("invalid error budget")
    records = decisions.get("records")
    if not isinstance(records, list):
        raise DecompileBenchReviewDecisionError("decision records must be a list")
    queue_ids = {str(record["candidate_id"]) for record in queue["records"]}
    decision_ids = [str(record.get("candidate_id", "")) for record in records]
    if len(decision_ids) != len(set(decision_ids)):
        raise DecompileBenchReviewDecisionError("decision candidate ids repeat")
    if set(decision_ids) != queue_ids:
        raise DecompileBenchReviewDecisionError(
            "decision candidate ids do not match the review queue"
        )
    for record in records:
        _validate_decision_record(record)


def _validate_decision_record(record: dict[str, Any]) -> None:
    candidate_id = str(record.get("candidate_id", ""))
    same_function = record.get("operator_same_function")
    source_complete = record.get("operator_source_complete")
    alignment = record.get("operator_semantic_alignment")
    error_kinds = record.get("error_kinds", [])
    notes = record.get("operator_notes", "")
    if same_function not in {True, False, None}:
        raise DecompileBenchReviewDecisionError(
            f"{candidate_id}: invalid operator_same_function"
        )
    if source_complete not in {True, False, None}:
        raise DecompileBenchReviewDecisionError(
            f"{candidate_id}: invalid operator_source_complete"
        )
    if alignment not in ALIGNMENT_VALUES | {None}:
        raise DecompileBenchReviewDecisionError(
            f"{candidate_id}: invalid operator_semantic_alignment"
        )
    if not isinstance(error_kinds, list) or any(
        kind not in ERROR_KINDS for kind in error_kinds
    ):
        raise DecompileBenchReviewDecisionError(f"{candidate_id}: invalid error_kinds")
    if len(error_kinds) != len(set(error_kinds)):
        raise DecompileBenchReviewDecisionError(
            f"{candidate_id}: duplicate error_kinds"
        )
    if not isinstance(notes, str):
        raise DecompileBenchReviewDecisionError(
            f"{candidate_id}: operator_notes must be a string"
        )
    values = (same_function, source_complete, alignment)
    partial = any(value is not None for value in values)
    finished = all(value is not None for value in values)
    if partial and not finished:
        raise DecompileBenchReviewDecisionError(
            f"{candidate_id}: partially finished decision"
        )
    if finished:
        is_error = _decision_is_error(record)
        if is_error and not error_kinds:
            raise DecompileBenchReviewDecisionError(
                f"{candidate_id}: error decision requires error_kinds"
            )
        if not is_error and error_kinds:
            raise DecompileBenchReviewDecisionError(
                f"{candidate_id}: passing decision cannot have error_kinds"
            )


def _decision_is_finished(record: dict[str, Any]) -> bool:
    return (
        record.get("operator_same_function") is not None
        and record.get("operator_source_complete") is not None
        and record.get("operator_semantic_alignment") is not None
    )


def _decision_is_error(record: dict[str, Any]) -> bool:
    return (
        record.get("operator_same_function") is not True
        or record.get("operator_source_complete") is not True
        or record.get("operator_semantic_alignment") != "pass"
    )


def _render_batch(
    records: list[dict[str, Any]],
    *,
    packet_number: int,
    start_index: int,
    queue_sha256: str,
) -> str:
    lines = [
        f"# Decompile-Bench Alignment Review Batch {packet_number:02d}",
        "",
        f"- queue SHA-256: `{queue_sha256}`",
        f"- records: `{start_index}`–`{start_index + len(records) - 1}`",
        "- `uncertain` counts as an error.",
        "- Do not execute source or assembly; this is static paired-text review.",
        "",
    ]
    for index, record in enumerate(records, start=start_index):
        lines.extend(
            [
                f"## {index}. `{record['candidate_id']}`",
                "",
                f"- function: `{record['function_name']}`",
                f"- source chars: `{record['source_chars']}`",
                f"- assembly chars: `{record['assembly_chars']}`",
                "",
                "### Source",
                "",
                "````cpp",
                str(record["source_code"]).rstrip(),
                "````",
                "",
                "### Assembly",
                "",
                "````asm",
                str(record["assembly"]).rstrip(),
                "````",
                "",
                "Decision: `same_function=? / source_complete=? / "
                "semantic_alignment=?`",
                "",
            ]
        )
    return "\n".join(lines) + "\n"


def _load_json_file(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        raise DecompileBenchReviewDecisionError(
            f"{label} is not a regular file: {path}"
        )
    result = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(result, dict):
        raise DecompileBenchReviewDecisionError(f"{label} must be a JSON object")
    return result


def _atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    serialized = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(serialized, encoding="utf-8")
    temporary.replace(path)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
