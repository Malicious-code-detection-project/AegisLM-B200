"""Human-readable CVEfixes review packets and decision finalization."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from aegislm.datasets.cvefixes_review import (
    CVEFIXES_REVIEW_QUEUE_SCHEMA_VERSION,
)

CVEFIXES_REVIEW_DECISIONS_SCHEMA_VERSION = (
    "aegislm.phase-f-cvefixes-manual-review-decisions.v1"
)
CVEFIXES_REVIEW_RESULT_SCHEMA_VERSION = (
    "aegislm.phase-f-cvefixes-manual-review-result.v1"
)
CVEFIXES_REVIEW_UPDATES_SCHEMA_VERSION = (
    "aegislm.phase-f-cvefixes-manual-review-updates.v1"
)
PAIR_QUALITY_VALUES = {"pass", "uncertain", "fail"}
ERROR_KINDS = {
    "different_function_pair",
    "patch_unrelated_to_cwe",
    "cwe_too_broad",
    "cwe_mismatch",
    "insufficient_context",
    "malformed_code_or_diff",
    "other",
}


class CvefixesReviewDecisionError(ValueError):
    """Raised when the review packet or operator decisions are invalid."""


def render_cvefixes_review_packets(
    queue_path: Path,
    output_dir: Path,
    *,
    batch_size: int = 20,
) -> dict[str, Any]:
    """Render fixed batches without changing or copying the source queue."""
    queue = _load_review_queue(queue_path)
    if batch_size <= 0:
        raise CvefixesReviewDecisionError("batch_size must be positive")
    records = queue["records"]
    output_dir.mkdir(parents=True, exist_ok=True)
    packet_paths: list[Path] = []
    for offset in range(0, len(records), batch_size):
        batch = records[offset : offset + batch_size]
        packet_number = (offset // batch_size) + 1
        packet_path = output_dir / f"review-batch-{packet_number:02d}.md"
        packet_path.write_text(
            _render_batch(
                batch,
                packet_number=packet_number,
                start_index=offset + 1,
                queue_sha256=_sha256_file(queue_path),
            ),
            encoding="utf-8",
        )
        packet_paths.append(packet_path)

    index_path = output_dir / "index.md"
    index_lines = [
        "# CVEfixes Manual Review Packets",
        "",
        f"- queue SHA-256: `{_sha256_file(queue_path)}`",
        f"- records: `{len(records)}`",
        f"- batch size: `{batch_size}`",
        f"- packets: `{len(packet_paths)}`",
        "- model visible: `false`",
        "",
        "각 packet에서 같은 기능 pair인지, patch가 target CWE를 직접",
        "뒷받침하는지, 문맥이 충분한지를 판단합니다.",
        "",
    ]
    for packet_path in packet_paths:
        index_lines.append(f"- [{packet_path.stem}]({packet_path.name})")
    index_path.write_text("\n".join(index_lines) + "\n", encoding="utf-8")
    return {
        "queue_sha256": _sha256_file(queue_path),
        "records": len(records),
        "batch_size": batch_size,
        "packet_count": len(packet_paths),
        "index_path": str(index_path.resolve()),
        "packet_paths": [str(path.resolve()) for path in packet_paths],
    }


def build_cvefixes_review_decision_template(
    queue_path: Path,
    *,
    error_budget: int = 10,
) -> dict[str, Any]:
    """Create a code-free decision template bound to the review queue hash."""
    queue = _load_review_queue(queue_path)
    if error_budget < 0:
        raise CvefixesReviewDecisionError("error_budget must be non-negative")
    return {
        "schema_version": CVEFIXES_REVIEW_DECISIONS_SCHEMA_VERSION,
        "queue_sha256": _sha256_file(queue_path),
        "error_budget": error_budget,
        "review_policy": {
            "uncertain_counts_as_error": True,
            "fail_early_when_errors_exceed_budget": True,
            "repository_license_review_is_separate": True,
        },
        "records": [
            {
                "candidate_id": str(record["candidate_id"]),
                "operator_patch_related": None,
                "operator_cwe_supported": None,
                "operator_pair_quality": None,
                "error_kinds": [],
                "operator_notes": "",
            }
            for record in queue["records"]
        ],
    }


def evaluate_cvefixes_review_decisions(
    queue_path: Path,
    decisions_path: Path,
) -> dict[str, Any]:
    """Validate decisions and enforce the fixed fail-early error budget."""
    queue = _load_review_queue(queue_path)
    decisions = json.loads(decisions_path.read_text(encoding="utf-8"))
    _validate_decisions_document(queue_path, queue, decisions)

    queue_ids = [str(record["candidate_id"]) for record in queue["records"]]
    decision_by_id = {
        str(record["candidate_id"]): record for record in decisions["records"]
    }
    ordered_decisions = [decision_by_id[candidate_id] for candidate_id in queue_ids]
    finished = [record for record in ordered_decisions if _decision_is_finished(record)]
    unfinished = [
        str(record["candidate_id"])
        for record in ordered_decisions
        if not _decision_is_finished(record)
    ]
    error_records = [record for record in finished if _decision_is_error(record)]
    passed_records = [record for record in finished if not _decision_is_error(record)]
    error_budget = int(decisions["error_budget"])
    fail_early = len(error_records) > error_budget
    complete = not unfinished
    if fail_early:
        decision = "manual_review_fail_early"
    elif complete:
        decision = "manual_review_pass"
    else:
        decision = "manual_review_in_progress"

    error_kind_counts: Counter[str] = Counter(
        str(kind) for record in error_records for kind in record.get("error_kinds", [])
    )
    result_records = [
        {
            "candidate_id": str(record["candidate_id"]),
            "operator_patch_related": record["operator_patch_related"],
            "operator_cwe_supported": record["operator_cwe_supported"],
            "operator_pair_quality": record["operator_pair_quality"],
            "error_kinds": list(record.get("error_kinds", [])),
            "operator_notes": str(record.get("operator_notes", "")),
            "counts_as_error": _decision_is_error(record),
        }
        for record in finished
    ]
    return {
        "schema_version": CVEFIXES_REVIEW_RESULT_SCHEMA_VERSION,
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
            "passed_records": len(passed_records),
            "error_records": len(error_records),
            "remaining_error_budget": max(0, error_budget - len(error_records)),
            "error_kind_counts": dict(sorted(error_kind_counts.items())),
        },
        "unfinished_candidate_ids": unfinished,
        "records": result_records,
        "decision": decision,
        "approved_for_label_quality": decision == "manual_review_pass",
        "approved_for_repository_license_review": (decision == "manual_review_pass"),
        "approved_for_processing": False,
        "approved_for_training": False,
        "safety": {
            "raw_code_return_count": 0,
            "raw_diff_return_count": 0,
            "source_code_execution_count": 0,
            "object_execution_count": 0,
        },
    }


def apply_cvefixes_review_updates(
    decisions_path: Path,
    updates_path: Path,
) -> dict[str, Any]:
    """Apply full-record decisions atomically without overwriting disagreements."""
    if not decisions_path.is_file():
        raise CvefixesReviewDecisionError(
            f"decisions are not a regular file: {decisions_path}"
        )
    if not updates_path.is_file():
        raise CvefixesReviewDecisionError(
            f"updates are not a regular file: {updates_path}"
        )
    decisions = json.loads(decisions_path.read_text(encoding="utf-8"))
    updates = json.loads(updates_path.read_text(encoding="utf-8"))
    if decisions.get("schema_version") != CVEFIXES_REVIEW_DECISIONS_SCHEMA_VERSION:
        raise CvefixesReviewDecisionError("unsupported decisions schema")
    if updates.get("schema_version") != CVEFIXES_REVIEW_UPDATES_SCHEMA_VERSION:
        raise CvefixesReviewDecisionError("unsupported updates schema")
    if updates.get("queue_sha256") != decisions.get("queue_sha256"):
        raise CvefixesReviewDecisionError("update queue hash mismatch")
    update_records = updates.get("records")
    if not isinstance(update_records, list) or not update_records:
        raise CvefixesReviewDecisionError("update records are empty")
    update_ids = [str(record.get("candidate_id", "")) for record in update_records]
    if len(update_ids) != len(set(update_ids)):
        raise CvefixesReviewDecisionError("update candidate ids repeat")

    decision_by_id = {
        str(record["candidate_id"]): record for record in decisions["records"]
    }
    applied = 0
    unchanged = 0
    for update in update_records:
        _validate_decision_record(update)
        candidate_id = str(update["candidate_id"])
        if candidate_id not in decision_by_id:
            raise CvefixesReviewDecisionError(
                f"unknown update candidate id: {candidate_id}"
            )
        if not _decision_is_finished(update):
            raise CvefixesReviewDecisionError(
                f"{candidate_id}: update must be finished"
            )
        current = decision_by_id[candidate_id]
        if _decision_is_finished(current):
            if current != update:
                raise CvefixesReviewDecisionError(
                    f"{candidate_id}: refusing to overwrite existing decision"
                )
            unchanged += 1
            continue
        current.update(update)
        applied += 1

    serialized = (
        json.dumps(decisions, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    )
    temporary_path = decisions_path.with_suffix(decisions_path.suffix + ".tmp")
    temporary_path.write_text(serialized, encoding="utf-8")
    temporary_path.replace(decisions_path)
    return {
        "queue_sha256": decisions["queue_sha256"],
        "applied_records": applied,
        "unchanged_records": unchanged,
        "decisions_sha256": _sha256_file(decisions_path),
    }


def _load_review_queue(queue_path: Path) -> dict[str, Any]:
    if not queue_path.is_file():
        raise CvefixesReviewDecisionError(
            f"review queue is not a regular file: {queue_path}"
        )
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    if queue.get("schema_version") != CVEFIXES_REVIEW_QUEUE_SCHEMA_VERSION:
        raise CvefixesReviewDecisionError("unsupported review queue schema")
    if queue.get("decision") != "manual_review_ready":
        raise CvefixesReviewDecisionError("review queue is not ready")
    if queue.get("approved_for_manual_review") is not True:
        raise CvefixesReviewDecisionError("manual review is not approved")
    if queue.get("approved_for_training") is not False:
        raise CvefixesReviewDecisionError(
            "review queue training approval must remain false"
        )
    records = queue.get("records")
    if not isinstance(records, list) or not records:
        raise CvefixesReviewDecisionError("review queue records are empty")
    candidate_ids = [str(record["candidate_id"]) for record in records]
    if len(candidate_ids) != len(set(candidate_ids)):
        raise CvefixesReviewDecisionError("review queue candidate ids repeat")
    return queue


def _validate_decisions_document(
    queue_path: Path,
    queue: dict[str, Any],
    decisions: dict[str, Any],
) -> None:
    if decisions.get("schema_version") != CVEFIXES_REVIEW_DECISIONS_SCHEMA_VERSION:
        raise CvefixesReviewDecisionError("unsupported decisions schema")
    if decisions.get("queue_sha256") != _sha256_file(queue_path):
        raise CvefixesReviewDecisionError("decision queue hash mismatch")
    error_budget = decisions.get("error_budget")
    if not isinstance(error_budget, int) or error_budget < 0:
        raise CvefixesReviewDecisionError("invalid error budget")
    records = decisions.get("records")
    if not isinstance(records, list):
        raise CvefixesReviewDecisionError("decision records must be a list")
    queue_ids = {str(record["candidate_id"]) for record in queue["records"]}
    decision_ids = [str(record.get("candidate_id", "")) for record in records]
    if len(decision_ids) != len(set(decision_ids)):
        raise CvefixesReviewDecisionError("decision candidate ids repeat")
    if set(decision_ids) != queue_ids:
        missing = sorted(queue_ids - set(decision_ids))
        extra = sorted(set(decision_ids) - queue_ids)
        raise CvefixesReviewDecisionError(
            f"decision candidate ids mismatch: missing={missing}, extra={extra}"
        )
    for record in records:
        _validate_decision_record(record)


def _validate_decision_record(record: dict[str, Any]) -> None:
    candidate_id = str(record.get("candidate_id", ""))
    patch_related = record.get("operator_patch_related")
    cwe_supported = record.get("operator_cwe_supported")
    pair_quality = record.get("operator_pair_quality")
    error_kinds = record.get("error_kinds", [])
    notes = record.get("operator_notes", "")
    if patch_related not in {True, False, None}:
        raise CvefixesReviewDecisionError(
            f"{candidate_id}: invalid operator_patch_related"
        )
    if cwe_supported not in {True, False, None}:
        raise CvefixesReviewDecisionError(
            f"{candidate_id}: invalid operator_cwe_supported"
        )
    if pair_quality not in PAIR_QUALITY_VALUES | {None}:
        raise CvefixesReviewDecisionError(
            f"{candidate_id}: invalid operator_pair_quality"
        )
    if not isinstance(error_kinds, list) or any(
        kind not in ERROR_KINDS for kind in error_kinds
    ):
        raise CvefixesReviewDecisionError(f"{candidate_id}: invalid error_kinds")
    if len(error_kinds) != len(set(error_kinds)):
        raise CvefixesReviewDecisionError(f"{candidate_id}: duplicate error_kinds")
    if not isinstance(notes, str):
        raise CvefixesReviewDecisionError(
            f"{candidate_id}: operator_notes must be a string"
        )
    fields = (patch_related, cwe_supported, pair_quality)
    partially_finished = any(value is not None for value in fields)
    finished = all(value is not None for value in fields)
    if partially_finished and not finished:
        raise CvefixesReviewDecisionError(
            f"{candidate_id}: partially finished decision"
        )
    if finished:
        is_error = (
            patch_related is not True
            or cwe_supported is not True
            or pair_quality != "pass"
        )
        if is_error and not error_kinds:
            raise CvefixesReviewDecisionError(
                f"{candidate_id}: error decision requires error_kinds"
            )
        if not is_error and error_kinds:
            raise CvefixesReviewDecisionError(
                f"{candidate_id}: passing decision cannot have error_kinds"
            )


def _decision_is_finished(record: dict[str, Any]) -> bool:
    return (
        record.get("operator_patch_related") is not None
        and record.get("operator_cwe_supported") is not None
        and record.get("operator_pair_quality") is not None
    )


def _decision_is_error(record: dict[str, Any]) -> bool:
    return (
        record.get("operator_patch_related") is not True
        or record.get("operator_cwe_supported") is not True
        or record.get("operator_pair_quality") != "pass"
    )


def _render_batch(
    records: list[dict[str, Any]],
    *,
    packet_number: int,
    start_index: int,
    queue_sha256: str,
) -> str:
    lines = [
        f"# CVEfixes Manual Review Batch {packet_number:02d}",
        "",
        f"- queue SHA-256: `{queue_sha256}`",
        f"- records: `{start_index}`–`{start_index + len(records) - 1}`",
        "- 이 문서는 model input이나 학습 shard가 아니라 수동 검토용입니다.",
        "- `uncertain`도 오류 예산에 포함합니다.",
        "",
    ]
    for index, record in enumerate(records, start=start_index):
        lines.extend(
            [
                f"## {index}. `{record['candidate_id']}`",
                "",
                f"- target CWE: `{record['target_cwe']}`",
                f"- CVE: `{', '.join(record['cve_ids'])}`",
                f"- language: `{record['programming_language']}`",
                f"- repository: `{record['repository_url']}`",
                f"- commit: `{record['commit_hash']}`",
                "",
                "### Function diff",
                "",
                "````diff",
                str(record["function_diff"]).rstrip(),
                "````",
                "",
                "<details>",
                "<summary>전체 before/after 함수</summary>",
                "",
                "#### Before",
                "",
                "````c",
                str(record["before_code"]).rstrip(),
                "````",
                "",
                "#### After",
                "",
                "````c",
                str(record["after_code"]).rstrip(),
                "````",
                "",
                "</details>",
                "",
                "판정: `patch_related=? / cwe_supported=? / pair_quality=?`",
                "",
            ]
        )
    return "\n".join(lines) + "\n"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
