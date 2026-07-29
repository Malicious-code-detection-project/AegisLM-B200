"""F2 source-target quality and tokenizer audits."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any

from aegislm.datasets.source import (
    SourceContractError,
    build_source_target,
    format_source_prompt,
    phase_f_record_to_source_record,
    source_prompt_variant_id,
    validate_source_output,
)

_GENERIC_EVIDENCE_MARKERS = (
    "dataset label",
    "positive for the scoped",
    "requires deterministic validation",
    "code-visible operation on the vulnerable execution path",
    "exact source operation is the code-visible basis",
)


def audit_source_targets(
    materialized_records: Sequence[Mapping[str, Any]],
    manifest_rows: Sequence[Mapping[str, Any]],
    *,
    tokenizer: Any,
    cutoff_len: int = 2048,
    grounded_findings_by_id: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
    required_counts: Mapping[str, Mapping[str, int]] | None = None,
) -> dict[str, Any]:
    """Audit conservative F2 targets without filling evidence or quota gaps."""
    manifest_by_id = {str(row["record_id"]): row for row in manifest_rows}
    findings_by_id = grounded_findings_by_id or {}
    required = (
        required_counts
        if required_counts is not None
        else {
            "train": {"present": 5000, "not_observed": 5000},
            "validation": {"present": 500, "not_observed": 500},
            "test": {"present": 250, "not_observed": 250},
        }
    )
    cases: list[dict[str, Any]] = []
    target_hashes: Counter[str] = Counter()
    eligible_counts: Counter[tuple[str, str]] = Counter()
    variant_counts: Counter[tuple[str, int]] = Counter()
    exclusion_counts: Counter[str] = Counter()
    tokenized_sequence_count = 0
    maximum_observed_token_count = 0

    for record in materialized_records:
        record_id = str(record.get("id") or "")
        manifest = manifest_by_id.get(record_id)
        if manifest is None:
            cases.append(
                {
                    "record_id": record_id,
                    "eligible": False,
                    "reason": "manifest_missing",
                    "errors": ["selected manifest row missing"],
                }
            )
            exclusion_counts["manifest_missing"] += 1
            continue
        try:
            source_record = phase_f_record_to_source_record(record, manifest)
            prompt = format_source_prompt(source_record)
            prompt_leakage = _prompt_leakage(source_record, prompt)
            result = build_source_target(
                source_record,
                findings=findings_by_id.get(record_id, ()),
            )
        except SourceContractError as exc:
            cases.append(
                {
                    "record_id": record_id,
                    "eligible": False,
                    "reason": "contract_error",
                    "errors": [str(exc)],
                }
            )
            exclusion_counts["contract_error"] += 1
            continue

        metadata = source_record["metadata"]
        split = str(metadata["split"])
        label = str(metadata["label"])
        materialization = str(manifest.get("materialization") or "")
        variant_id = source_prompt_variant_id(source_record)
        variant_counts[(label, variant_id)] += 1
        if not result.eligible or result.target is None:
            exclusion_counts[result.reason] += 1
            cases.append(
                {
                    "record_id": record_id,
                    "split": split,
                    "materialization": materialization,
                    "label": label,
                    "eligible": False,
                    "reason": result.reason,
                    "prompt_variant": variant_id,
                    "prompt_leakage": prompt_leakage,
                    "errors": [],
                }
            )
            continue

        target_errors = validate_source_output(
            result.target,
            source_code=str(source_record["code"]["text"]),
        )
        target_json = json.dumps(
            result.target,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        target_hash = hashlib.sha256(target_json.encode()).hexdigest()
        token_count = count_source_training_tokens(
            tokenizer,
            prompt,
            result.target,
        )
        tokenized_sequence_count += 1
        maximum_observed_token_count = max(maximum_observed_token_count, token_count)
        if token_count > cutoff_len:
            exclusion_counts["tokenizer_cutoff_exceeded"] += 1
            cases.append(
                {
                    "record_id": record_id,
                    "split": split,
                    "materialization": materialization,
                    "label": label,
                    "eligible": False,
                    "reason": "tokenizer_cutoff_exceeded",
                    "prompt_variant": variant_id,
                    "prompt_leakage": prompt_leakage,
                    "schema_valid": not target_errors,
                    "evidence_linked": result.evidence_linked,
                    "token_count": token_count,
                    "over_cutoff": True,
                    "errors": target_errors,
                }
            )
            continue

        target_hashes[target_hash] += 1
        if materialization in {"train", "validation", "blind_test"}:
            eligible_counts[(split, label)] += 1
        cases.append(
            {
                "record_id": record_id,
                "split": split,
                "materialization": materialization,
                "label": label,
                "eligible": True,
                "reason": "eligible",
                "prompt_variant": variant_id,
                "prompt_leakage": prompt_leakage,
                "schema_valid": not target_errors,
                "evidence_linked": result.evidence_linked,
                "generic_evidence": _contains_generic_evidence(result.target),
                "global_safety_claim": any(
                    error.endswith("global safety claim") for error in target_errors
                ),
                "token_count": token_count,
                "over_cutoff": token_count > cutoff_len,
                "target_sha256": target_hash,
                "errors": target_errors,
            }
        )

    eligible_cases = [case for case in cases if case.get("eligible")]
    positive_cases = [case for case in eligible_cases if case.get("label") == "present"]
    quota_results = {
        f"{split}:{label}": eligible_counts[(split, label)] >= count
        for split, labels in required.items()
        for label, count in labels.items()
    }
    duplicate_count = sum(count - 1 for count in target_hashes.values())
    maximum_exact_count = max(target_hashes.values(), default=0)
    schema_pass_rate = _rate(eligible_cases, "schema_valid")
    positive_link_rate = _rate(positive_cases, "evidence_linked")
    exact_duplicate_rate = _ratio(duplicate_count, len(eligible_cases))
    maximum_exact_fraction = _ratio(maximum_exact_count, len(eligible_cases))
    metrics: dict[str, Any] = {
        "total_count": len(cases),
        "eligible_count": len(eligible_cases),
        "excluded_count": len(cases) - len(eligible_cases),
        "eligible_counts": {
            f"{split}:{label}": count
            for (split, label), count in sorted(eligible_counts.items())
        },
        "exclusion_counts": dict(sorted(exclusion_counts.items())),
        "schema_pass_rate": schema_pass_rate,
        "prompt_leakage_count": sum(bool(case.get("prompt_leakage")) for case in cases),
        "positive_evidence_link_rate": positive_link_rate,
        "generic_evidence_count": sum(
            bool(case.get("generic_evidence")) for case in eligible_cases
        ),
        "exact_target_duplicate_rate": exact_duplicate_rate,
        "maximum_exact_target_fraction": maximum_exact_fraction,
        "global_safety_claim_count": sum(
            bool(case.get("global_safety_claim")) for case in eligible_cases
        ),
        "over_cutoff_count": sum(
            bool(case.get("over_cutoff")) for case in eligible_cases
        ),
        "maximum_token_count": max(
            (int(case["token_count"]) for case in eligible_cases),
            default=0,
        ),
        "tokenizer_loaded": True,
        "tokenizer_name_or_path": str(
            getattr(tokenizer, "name_or_path", type(tokenizer).__name__)
        ),
        "tokenized_sequence_count": tokenized_sequence_count,
        "maximum_observed_token_count": maximum_observed_token_count,
        "tokenizer_cutoff_excluded_count": exclusion_counts[
            "tokenizer_cutoff_exceeded"
        ],
        "prompt_variant_counts": {
            f"{label}:{variant}": count
            for (label, variant), count in sorted(variant_counts.items())
        },
    }
    quality_gates = {
        "schema_validation": schema_pass_rate == 1.0,
        "model_visible_leakage": metrics["prompt_leakage_count"] == 0,
        "positive_code_linkage": positive_link_rate >= 0.95,
        "generic_positive_evidence": metrics["generic_evidence_count"] == 0,
        "exact_target_duplicates": exact_duplicate_rate <= 0.05,
        "single_target_fraction": maximum_exact_fraction <= 0.02,
        "negative_global_safety_claims": (metrics["global_safety_claim_count"] == 0),
        "tokenizer_cutoff": metrics["over_cutoff_count"] == 0,
    }
    supply_pass = all(quota_results.values())
    automated_pass = (
        bool(eligible_cases) and all(quality_gates.values()) and supply_pass
    )
    status = (
        "manual_review_required"
        if automated_pass
        else "evidence_supply_blocked"
        if not supply_pass
        else "automated_quality_gate_failed"
    )
    return {
        "schema_version": "aegislm.source-target-audit.v1",
        "status": status,
        "overall_pass": False,
        "automated_pass": automated_pass,
        "manual_review": {
            "required_count": 100,
            "status": "not_started",
            "maximum_label_or_evidence_error_rate": 0.05,
        },
        "cutoff_len": cutoff_len,
        "quality_gates": quality_gates,
        "quota_gates": quota_results,
        "metrics": metrics,
        "cases": cases,
    }


def count_source_training_tokens(
    tokenizer: Any,
    prompt: Sequence[Any],
    target: Mapping[str, Any],
) -> int:
    """Count the exact non-truncated chat sequence with thinking disabled."""
    messages = [
        *[dict(message) for message in prompt],
        {
            "role": "assistant",
            "content": json.dumps(
                target,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
        },
    ]
    try:
        encoded = tokenizer.apply_chat_template(
            messages,
            tokenize=True,
            add_generation_prompt=False,
            enable_thinking=False,
        )
    except TypeError:
        encoded = tokenizer.apply_chat_template(
            messages,
            tokenize=True,
            add_generation_prompt=False,
        )
    if isinstance(encoded, Mapping):
        encoded = encoded.get("input_ids")
        if encoded is None:
            raise TypeError("chat template result does not contain input_ids")
    if hasattr(encoded, "shape"):
        shape = encoded.shape
        return int(shape[-1])
    if isinstance(encoded, Sequence) and encoded and isinstance(encoded[0], Sequence):
        return len(encoded[0])
    return len(encoded)


def _prompt_leakage(
    record: Mapping[str, Any],
    prompt: Sequence[Any],
) -> list[str]:
    metadata = record["metadata"]
    joined = "\n".join(str(message["content"]) for message in prompt).lower()
    candidates = {
        "record_id": str(record["id"]),
        "source_dataset": str(metadata["source_dataset"]),
    }
    hits = [
        name for name, value in candidates.items() if value and value.lower() in joined
    ]
    control_keys = (
        '"dataset"',
        '"dataset_name"',
        '"source_dataset"',
        '"source_revision"',
        '"target"',
        '"label"',
        '"gold"',
        '"split"',
        '"expected_output"',
        '"is_vulnerable"',
    )
    hits.extend(key for key in control_keys if key in joined)
    return sorted(set(hits))


def _contains_generic_evidence(target: Mapping[str, Any]) -> bool:
    text = json.dumps(target, ensure_ascii=False).lower()
    return any(marker in text for marker in _GENERIC_EVIDENCE_MARKERS)


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _rate(cases: Sequence[Mapping[str, Any]], key: str) -> float:
    return _ratio(sum(bool(case.get(key)) for case in cases), len(cases))
