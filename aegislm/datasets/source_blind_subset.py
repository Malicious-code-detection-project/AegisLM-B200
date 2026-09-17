"""Build an untouched source-code blind subset after development exposure."""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from aegislm.datasets.source import SourceContractError
from aegislm.datasets.source_decision import (
    to_decision_challenge_record,
    to_decision_gold_record,
)
from aegislm.datasets.source_two_stage import build_source_evidence_gold


@dataclass(frozen=True)
class UntouchedBlindSubset:
    """Materialized blind rows and their non-model-visible audit manifest."""

    challenge: list[dict[str, Any]]
    gold: list[dict[str, Any]]
    private_records: list[dict[str, Any]]
    manifest: dict[str, Any]


@dataclass(frozen=True)
class FreshBlindContracts:
    """Decision and evidence contracts projected from a frozen source blind."""

    decision_challenge: list[dict[str, Any]]
    decision_gold: list[dict[str, Any]]
    evidence_gold: list[dict[str, Any]]
    manifest: dict[str, Any]


def build_fresh_blind_contracts(
    source_challenge_rows: Sequence[Mapping[str, Any]],
    source_gold_rows: Sequence[Mapping[str, Any]],
    private_records: Sequence[Mapping[str, Any]],
) -> FreshBlindContracts:
    """Project one frozen full-report blind into two-stage evaluation contracts."""
    challenge = _index(
        source_challenge_rows,
        id_keys=("id",),
        name="source challenge",
    )
    gold = _index(source_gold_rows, id_keys=("id",), name="source gold")
    records = _index(private_records, id_keys=("id",), name="private records")
    if set(challenge) != set(gold) or set(challenge) != set(records):
        raise SourceContractError(
            "source challenge, gold, and private record ids differ"
        )
    for record_id, row in challenge.items():
        if row.get("expected_output") is not None:
            raise SourceContractError(
                f"{record_id}: source challenge contains model-visible gold"
            )

    decision_challenge = [
        to_decision_challenge_record(challenge[record_id]) for record_id in challenge
    ]
    decision_gold = [
        to_decision_gold_record(gold[record_id]) for record_id in challenge
    ]
    evidence_gold = build_source_evidence_gold(
        [records[record_id] for record_id in challenge],
        [gold[record_id] for record_id in challenge],
    )
    labels = Counter(_gold_assessment(row) for row in decision_gold)
    ids = sorted(challenge)
    return FreshBlindContracts(
        decision_challenge=decision_challenge,
        decision_gold=decision_gold,
        evidence_gold=evidence_gold,
        manifest={
            "schema_version": "aegislm.fresh-source-blind-contracts.v1",
            "status": "frozen_blind",
            "count": len(ids),
            "labels": dict(sorted(labels.items())),
            "ids_sha256": _ids_sha256(ids),
            "model_visible_gold_count": 0,
            "decision_challenge_gold_ids_match": True,
            "evidence_gold_coverage": 1.0,
        },
    )


def build_untouched_blind_subset(
    challenge_rows: Sequence[Mapping[str, Any]],
    gold_rows: Sequence[Mapping[str, Any]],
    private_records: Sequence[Mapping[str, Any]],
    exposed_prediction_rows: Sequence[Mapping[str, Any]],
    *,
    expected_count: int | None = None,
) -> UntouchedBlindSubset:
    """Remove exactly the previously exposed IDs from a label-blind challenge."""
    challenge = _index(challenge_rows, id_keys=("id",), name="challenge")
    gold = _index(gold_rows, id_keys=("id",), name="gold")
    records = _index(private_records, id_keys=("id",), name="private records")
    exposed = _collect_ids(
        exposed_prediction_rows,
        id_keys=("record_id", "id"),
        name="exposed predictions",
    )

    if set(challenge) != set(gold):
        raise SourceContractError("challenge and gold ids differ")
    missing_records = set(challenge) - set(records)
    if missing_records:
        raise SourceContractError(
            f"private records are missing {len(missing_records)} challenge ids"
        )
    unknown_exposed = exposed - set(challenge)
    if unknown_exposed:
        raise SourceContractError(
            f"exposed predictions contain {len(unknown_exposed)} unknown ids"
        )
    for record_id, row in challenge.items():
        if row.get("expected_output") is not None:
            raise SourceContractError(
                f"{record_id}: challenge contains model-visible gold"
            )

    untouched_ids = [record_id for record_id in challenge if record_id not in exposed]
    if expected_count is not None and len(untouched_ids) != expected_count:
        raise SourceContractError(
            f"untouched count {len(untouched_ids)} != expected {expected_count}"
        )

    selected_challenge = [dict(challenge[record_id]) for record_id in untouched_ids]
    selected_gold = [dict(gold[record_id]) for record_id in untouched_ids]
    selected_records = [dict(records[record_id]) for record_id in untouched_ids]
    labels = Counter(_gold_assessment(row) for row in selected_gold)
    manifest = {
        "schema_version": "aegislm.untouched-source-blind-subset.v1",
        "source_count": len(challenge),
        "exposed_count": len(exposed),
        "untouched_count": len(untouched_ids),
        "expected_count": expected_count,
        "labels": dict(sorted(labels.items())),
        "challenge_gold_ids_match": True,
        "private_record_coverage": 1.0,
        "model_visible_gold_count": 0,
        "exposed_ids_sha256": _ids_sha256(sorted(exposed)),
        "untouched_ids_sha256": _ids_sha256(sorted(untouched_ids)),
    }
    return UntouchedBlindSubset(
        challenge=selected_challenge,
        gold=selected_gold,
        private_records=selected_records,
        manifest=manifest,
    )


def _index(
    rows: Sequence[Mapping[str, Any]],
    *,
    id_keys: tuple[str, ...],
    name: str,
) -> dict[str, Mapping[str, Any]]:
    indexed: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        record_id = next(
            (
                value
                for key in id_keys
                if isinstance((value := row.get(key)), str) and value
            ),
            None,
        )
        if record_id is None:
            raise SourceContractError(f"{name} contains an invalid id")
        if record_id in indexed:
            raise SourceContractError(f"{name} contains duplicate id: {record_id}")
        indexed[record_id] = row
    return indexed


def _collect_ids(
    rows: Sequence[Mapping[str, Any]],
    *,
    id_keys: tuple[str, ...],
    name: str,
) -> set[str]:
    collected: set[str] = set()
    for row in rows:
        record_id = next(
            (
                value
                for key in id_keys
                if isinstance((value := row.get(key)), str) and value
            ),
            None,
        )
        if record_id is None:
            raise SourceContractError(f"{name} contains an invalid id")
        collected.add(record_id)
    return collected


def _gold_assessment(row: Mapping[str, Any]) -> str:
    expected = row.get("expected_output")
    if not isinstance(expected, Mapping):
        raise SourceContractError(f"{row.get('id')}: invalid blind gold")
    assessment = expected.get("assessment")
    if assessment not in {"present", "not_observed"}:
        raise SourceContractError(f"{row.get('id')}: invalid blind assessment")
    return str(assessment)


def _ids_sha256(ids: Sequence[str]) -> str:
    payload = "".join(f"{record_id}\n" for record_id in ids).encode()
    return hashlib.sha256(payload).hexdigest()
