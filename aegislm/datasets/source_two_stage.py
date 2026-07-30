"""Build evidence challenges from first-stage source decision predictions."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any, Literal, cast

from aegislm.datasets.source import SourceContractError
from aegislm.datasets.source_compact import project_full_report_target
from aegislm.datasets.source_evidence_lines import (
    format_evidence_lines_prompt,
    project_compact_to_evidence_lines,
)


def build_predicted_assessment_evidence_challenge(
    private_records: Sequence[Mapping[str, Any]],
    decision_predictions: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Condition evidence prompts on valid binary decision predictions."""
    records = _index(private_records, id_key="id", name="private records")
    predictions = _index(
        decision_predictions,
        id_key="record_id",
        name="decision predictions",
    )
    if set(records) != set(predictions):
        raise SourceContractError("private record and decision prediction ids differ")
    rows: list[dict[str, Any]] = []
    for record_id, record in records.items():
        assessment = _parse_assessment(predictions[record_id], record_id)
        rows.append(
            {
                "id": record_id,
                "messages": format_evidence_lines_prompt(
                    record,
                    assessment=assessment,
                ),
            }
        )
    return rows


def build_source_evidence_gold(
    private_records: Sequence[Mapping[str, Any]],
    report_gold_rows: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Project full-report gold into deterministic evidence line ranges."""
    records = _index(private_records, id_key="id", name="private records")
    report_gold = _index(report_gold_rows, id_key="id", name="report gold")
    missing_gold = set(records) - set(report_gold)
    if missing_gold:
        raise SourceContractError(
            f"report gold is missing {len(missing_gold)} private record ids"
        )
    rows: list[dict[str, Any]] = []
    for record_id, record in records.items():
        code = record.get("code")
        if not isinstance(code, Mapping) or not isinstance(code.get("text"), str):
            raise SourceContractError(f"{record_id}: private source code is missing")
        expected = report_gold[record_id].get("expected_output")
        if not isinstance(expected, Mapping):
            raise SourceContractError(f"{record_id}: report gold is invalid")
        source_code = str(code["text"])
        compact = project_full_report_target(expected, source_code=source_code)
        rows.append(
            {
                "id": record_id,
                "expected_output": project_compact_to_evidence_lines(
                    compact,
                    source_code=source_code,
                ),
            }
        )
    return rows


def _parse_assessment(
    prediction: Mapping[str, Any],
    record_id: str,
) -> Literal["present", "not_observed"]:
    raw_output = prediction.get("raw_output")
    if not isinstance(raw_output, str):
        raise SourceContractError(f"{record_id}: decision raw_output is missing")
    try:
        output = json.loads(raw_output)
    except json.JSONDecodeError as exc:
        raise SourceContractError(
            f"{record_id}: decision output is invalid JSON"
        ) from exc
    if not isinstance(output, dict) or set(output) != {"assessment"}:
        raise SourceContractError(
            f"{record_id}: decision output must contain only assessment"
        )
    assessment = output.get("assessment")
    if assessment not in {"present", "not_observed"}:
        raise SourceContractError(
            f"{record_id}: decision output is not a binary assessment"
        )
    return cast(Literal["present", "not_observed"], assessment)


def _index(
    rows: Sequence[Mapping[str, Any]],
    *,
    id_key: str,
    name: str,
) -> dict[str, Mapping[str, Any]]:
    indexed: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        record_id = row.get(id_key)
        if not isinstance(record_id, str) or not record_id:
            raise SourceContractError(f"{name} contains an invalid id")
        if record_id in indexed:
            raise SourceContractError(f"{name} contains duplicate id: {record_id}")
        indexed[record_id] = row
    return indexed
