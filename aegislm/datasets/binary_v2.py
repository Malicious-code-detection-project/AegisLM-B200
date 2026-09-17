"""Build the pre-training manual review for role-structured binary targets."""

from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from typing import Any, cast

from aegislm.datasets.binary import (
    build_binary_pair_role_targets,
    compact_binary_record,
    validate_binary_record,
    validate_binary_role_output_for_record,
)
from aegislm.datasets.phase_f import PhaseFDatasetError

BINARY_V2_PROFILE = "phase-f-binary-derived-v2"
BINARY_V2_SEED = 20260728
BINARY_V2_MANUAL_REVIEW_RECORDS = 100
BINARY_V2_TARGET_POLICY = "role-structured-evidence-v2"
BINARY_V2_OUTPUT_CONTRACT = "aegislm.binary-role-assessment-output.v2"


def build_binary_role_manual_review(
    records: Sequence[Mapping[str, Any]],
    gate: Mapping[str, Any],
    *,
    seed: int = BINARY_V2_SEED,
    review_records: int = BINARY_V2_MANUAL_REVIEW_RECORDS,
) -> dict[str, Any]:
    """Select a fixed stratified sample and build its v2 expected outputs."""
    if review_records <= 0 or review_records % 2:
        raise PhaseFDatasetError(
            "binary v2 review record count must be positive and even"
        )
    if gate.get("gate_pass") is not True and gate.get("review_eligible") is not True:
        raise PhaseFDatasetError(
            "binary v2 review requires a passed or review-eligible tokenizer gate"
        )
    if gate.get("output_contract") != BINARY_V2_OUTPUT_CONTRACT:
        raise PhaseFDatasetError("binary v2 review requires the v2 output contract")

    indexed = _index_records(records)
    accepted_ids = [str(value) for value in gate["accepted_pair_ids"]]
    accepted_variants = cast(
        Mapping[str, Sequence[str]],
        gate["accepted_pair_variants"],
    )
    pair_cwes: dict[str, str] = {}
    for pair_id in accepted_ids:
        variants = [str(value) for value in accepted_variants[pair_id]]
        if not variants:
            raise PhaseFDatasetError(f"{pair_id} has no accepted compiler variant")
        present = _pair_record(indexed, pair_id, "present", variants[0])
        pair_cwes[pair_id] = str(present["task"]["target_cwe"])

    pair_count = review_records // 2
    selected_pairs = _stratified_pair_sample(
        accepted_ids,
        pair_cwes,
        seed=seed,
        count=pair_count,
    )
    variant_counts: Counter[str] = Counter()
    rows: list[dict[str, Any]] = []
    for pair_id in selected_pairs:
        choices = [str(value) for value in accepted_variants[pair_id]]
        variant = min(
            choices,
            key=lambda value: (
                variant_counts[value],
                _stable_hash(f"{seed}:{pair_id}:{value}"),
            ),
        )
        variant_counts[variant] += 1
        compacted = {
            label: compact_binary_record(_pair_record(indexed, pair_id, label, variant))
            for label in ("present", "not_observed")
        }
        targets = dict(
            zip(
                ("present", "not_observed"),
                build_binary_pair_role_targets(
                    compacted["present"],
                    compacted["not_observed"],
                ),
                strict=True,
            )
        )
        for label in ("present", "not_observed"):
            record = compacted[label]
            target = targets[label]
            errors = validate_binary_role_output_for_record(target, record)
            if errors:
                raise PhaseFDatasetError(
                    f"{record['id']} failed v2 semantic validation: "
                    + "; ".join(errors)
                )
            function = cast(
                Mapping[str, Any],
                cast(list[Any], record["analysis"]["functions"])[0],
            )
            rows.append(
                {
                    "id": record["id"],
                    "pair_id": pair_id,
                    "private_label": label,
                    "target_cwe": pair_cwes[pair_id],
                    "compiler_variant": variant,
                    "pseudo_c": function["pseudo_c"],
                    "expected_output": target,
                    "operator_label_error": None,
                    "operator_evidence_error": None,
                    "notes": "",
                }
            )
    cwes = Counter(pair_cwes[pair_id] for pair_id in selected_pairs)
    return {
        "rows": rows,
        "manifest": {
            "schema_version": "aegislm.binary-role-manual-review-manifest.v1",
            "profile": BINARY_V2_PROFILE,
            "target_policy": BINARY_V2_TARGET_POLICY,
            "output_contract": BINARY_V2_OUTPUT_CONTRACT,
            "status": "manual_review_required",
            "seed": seed,
            "review_record_count": len(rows),
            "review_pair_count": len(selected_pairs),
            "selected_pair_ids": selected_pairs,
            "cwe_pair_counts": dict(sorted(cwes.items())),
            "compiler_variant_pair_counts": dict(sorted(variant_counts.items())),
            "maximum_label_or_evidence_error_rate": 0.05,
            "raw_object_execution_count": 0,
        },
    }


def render_binary_role_manual_review(rows: Sequence[Mapping[str, Any]]) -> str:
    """Render v2 rows as a compact, decision-oriented Markdown workbook."""
    sections = [
        "# Phase F Binary Role Target v2 — Manual Review",
        "",
        "각 항목은 `private_label`을 가린 상태에서 pseudo-C와 role 관계가 "
        "target CWE 결론을 실제로 뒷받침하는지 확인합니다.",
        "",
        "- `operator_label_error`: scoped present/not_observed 판정 오류",
        "- `operator_evidence_error`: 필수 role·span·relation 누락 또는 잘못된 연결",
        "- 한 pair의 present/fixed를 함께 읽고 전역 안전성은 판단하지 않습니다.",
        "",
    ]
    for index, row in enumerate(rows, start=1):
        output = cast(Mapping[str, Any], row["expected_output"])
        finding = cast(
            Mapping[str, Any],
            cast(list[Any], output["findings"])[0],
        )
        sections.extend(
            [
                f"## {index}. {row['id']}",
                "",
                f"- Pair: `{row['pair_id']}`",
                f"- CWE: `{row['target_cwe']}`",
                f"- Private label: `{row['private_label']}`",
                f"- Compiler: `{row['compiler_variant']}`",
                "",
                "### Pseudo-C",
                "",
                "```c",
                str(row["pseudo_c"]),
                "```",
                "",
                "### Target role graph",
                "",
            ]
        )
        for evidence in cast(list[Mapping[str, Any]], finding["evidence"]):
            sections.append(
                f"- `{evidence['evidence_id']}` / `{evidence['role']}`: "
                f"`{evidence['code_span']}`"
            )
        sections.extend(["", "Relations:", ""])
        for relation in cast(list[Mapping[str, Any]], finding["relations"]):
            sections.append(
                f"- `{relation['from_evidence_id']}` "
                f"`{relation['relationship']}` → "
                f"`{relation['to_evidence_id']}`"
            )
        sections.extend(
            [
                "",
                "Decision:",
                "",
                "- operator_label_error: `pending`",
                "- operator_evidence_error: `pending`",
                "- notes:",
                "",
            ]
        )
    return "\n".join(sections) + "\n"


def _index_records(
    records: Sequence[Mapping[str, Any]],
) -> dict[tuple[str, str], Mapping[str, Any]]:
    indexed: dict[tuple[str, str], Mapping[str, Any]] = {}
    for record in records:
        validate_binary_record(record)
        group_id = str(record["metadata"]["compiler_group_id"])
        variant = (
            f"{record['artifact']['compiler']}-{record['artifact']['optimization']}"
        )
        key = (group_id, variant)
        previous = indexed.get(key)
        if previous is not None and previous != record:
            raise PhaseFDatasetError(f"conflicting normalized record: {key}")
        indexed[key] = record
    return indexed


def _pair_record(
    indexed: Mapping[tuple[str, str], Mapping[str, Any]],
    pair_id: str,
    label: str,
    variant: str,
) -> Mapping[str, Any]:
    opaque = hashlib.sha256(f"{pair_id}:{label}".encode()).hexdigest()[:16]
    record = indexed.get((f"binary-group-{opaque}", variant))
    if record is None:
        raise PhaseFDatasetError(f"{pair_id} is missing {label} variant {variant}")
    return record


def _stratified_pair_sample(
    pair_ids: Sequence[str],
    pair_cwes: Mapping[str, str],
    *,
    seed: int,
    count: int,
) -> list[str]:
    if count > len(pair_ids):
        raise PhaseFDatasetError(
            f"review requires {count} pairs but only {len(pair_ids)} are accepted"
        )
    by_cwe: dict[str, list[str]] = defaultdict(list)
    for pair_id in pair_ids:
        by_cwe[pair_cwes[pair_id]].append(pair_id)
    for cwe, values in by_cwe.items():
        values.sort(key=lambda pair_id: _stable_hash(f"{seed}:{cwe}:{pair_id}"))
    selected: list[str] = []
    positions: Counter[str] = Counter()
    cwes = sorted(by_cwe)
    while len(selected) < count:
        progressed = False
        for cwe in cwes:
            position = positions[cwe]
            if position >= len(by_cwe[cwe]):
                continue
            selected.append(by_cwe[cwe][position])
            positions[cwe] += 1
            progressed = True
            if len(selected) == count:
                break
        if not progressed:
            break
    if len(selected) != count:
        raise PhaseFDatasetError("could not fill the stratified v2 review sample")
    return selected


def _stable_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()
