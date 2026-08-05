"""Build the frozen Phase F binary-derived v1 SFT dataset."""

from __future__ import annotations

import hashlib
import json
import math
import shutil
import tempfile
from collections import Counter
from collections.abc import Mapping, Sequence
from copy import deepcopy
from pathlib import Path
from typing import Any

from aegislm.datasets.binary import (
    BinaryRecordValidationError,
    build_binary_pair_targets,
    compact_binary_record,
    format_binary_prompt,
    validate_binary_output_for_record,
    validate_binary_record,
)
from aegislm.datasets.phase_f import (
    PhaseFDatasetError,
    write_jsonl,
    write_parquet,
)
from aegislm.datasets.source_audit import count_source_training_tokens
from aegislm.training.llamafactory import (
    build_dataset_info_entry,
    write_llamafactory_dataset,
)

BINARY_V1_PROFILE = "phase-f-binary-derived-v1"
BINARY_V1_SEED = 20260728
BINARY_V1_CUTOFF_LEN = 4096
BINARY_V1_TRAIN_PAIRS = 2000
BINARY_V1_VALIDATION_PAIRS = 200
BINARY_V1_TEST_PAIRS = 250
BINARY_V1_CONSISTENCY_PAIRS = 100
BINARY_V1_MANUAL_REVIEW_RECORDS = 100
BINARY_V1_TARGET_POLICY = "memory-write-read-linked-evidence-v9"
BINARY_V1_VARIANTS = ("gcc-O0", "gcc-O2", "clang-O0", "clang-O2")
BINARY_V1_TRAIN_NAME = "phase_f_binary_v1_train"
BINARY_V1_VALIDATION_NAME = "phase_f_binary_v1_validation"


def prepare_binary_v1(
    records: Sequence[Mapping[str, Any]],
    gate: Mapping[str, Any],
    *,
    tokenizer: Any,
    seed: int = BINARY_V1_SEED,
    cutoff_len: int = BINARY_V1_CUTOFF_LEN,
    train_pairs: int = BINARY_V1_TRAIN_PAIRS,
    validation_pairs: int = BINARY_V1_VALIDATION_PAIRS,
    test_pairs: int = BINARY_V1_TEST_PAIRS,
    consistency_pairs: int = BINARY_V1_CONSISTENCY_PAIRS,
    manual_review_records: int = BINARY_V1_MANUAL_REVIEW_RECORDS,
) -> dict[str, Any]:
    """Split reviewed pairs, select variants, and build model-ready records."""
    required_pairs = train_pairs + validation_pairs + test_pairs
    if manual_review_records % 2 or manual_review_records > required_pairs * 2:
        raise PhaseFDatasetError(
            "manual review record count must be even and fit the accepted pair supply"
        )
    accepted_pair_ids = [str(value) for value in gate["accepted_pair_ids"]]
    if len(accepted_pair_ids) != required_pairs:
        raise PhaseFDatasetError(
            f"accepted pair count must be exactly {required_pairs}, "
            f"got {len(accepted_pair_ids)}"
        )
    by_group = _index_compiler_groups(records)
    pair_variants: dict[str, dict[str, dict[str, Mapping[str, Any]]]] = {}
    pair_cwes: dict[str, str] = {}
    for pair_id in accepted_pair_ids:
        labels: dict[str, dict[str, Mapping[str, Any]]] = {}
        for label in ("present", "not_observed"):
            opaque = hashlib.sha256(f"{pair_id}:{label}".encode()).hexdigest()[:16]
            group_id = f"binary-group-{opaque}"
            variants = by_group.get(group_id)
            if variants is None:
                raise PhaseFDatasetError(
                    f"accepted pair is missing normalized {label} records: {pair_id}"
                )
            labels[label] = variants
        cwes = {
            str(record["task"]["target_cwe"])
            for variants in labels.values()
            for record in variants.values()
        }
        if len(cwes) != 1:
            raise PhaseFDatasetError(f"pair has inconsistent target CWE: {pair_id}")
        pair_cwes[pair_id] = cwes.pop()
        pair_variants[pair_id] = labels

    selected_variants, prepared, token_counts = _select_balanced_variants(
        pair_variants,
        tokenizer=tokenizer,
        seed=seed,
        cutoff_len=cutoff_len,
    )
    full_variant_pair_ids = [
        pair_id
        for pair_id in accepted_pair_ids
        if all(
            (pair_id, label, variant) in prepared
            for variant in BINARY_V1_VARIANTS
            for label in ("present", "not_observed")
        )
    ]
    consistency_pair_ids = _select_consistency_pairs(
        full_variant_pair_ids,
        pair_cwes,
        seed=seed,
        count=consistency_pairs,
    )
    split_by_pair = _stratified_pair_split(
        pair_cwes,
        seed=seed,
        sizes={
            "train": train_pairs,
            "validation": validation_pairs,
            "test": test_pairs,
        },
        required_test_pair_ids=consistency_pair_ids,
    )

    canonical: list[dict[str, Any]] = []
    manifest_rows: list[dict[str, Any]] = []
    materialized: dict[str, list[dict[str, Any]]] = {
        "train": [],
        "validation": [],
        "test": [],
    }
    targets_by_id: dict[str, dict[str, Any]] = {}
    records_by_pair_label: dict[tuple[str, str], dict[str, Any]] = {}
    prompt_leakage: list[str] = []
    semantic_errors: list[str] = []
    target_hashes: Counter[str] = Counter()
    label_counts: Counter[tuple[str, str]] = Counter()

    for pair_id in sorted(accepted_pair_ids):
        split = split_by_pair[pair_id]
        variant = selected_variants[pair_id]
        for label in ("present", "not_observed"):
            record, target = prepared[(pair_id, label, variant)]
            final_record = deepcopy(record)
            final_record["metadata"]["split"] = split
            validate_binary_record(final_record)
            errors = validate_binary_output_for_record(target, final_record)
            semantic_errors.extend(f"{final_record['id']}: {error}" for error in errors)
            prompt = format_binary_prompt(final_record)
            visible = json.dumps(prompt, ensure_ascii=False)
            forbidden = [
                value
                for value in (
                    pair_id,
                    str(final_record["metadata"]["source_dataset"]),
                    f'"label": "{label}"',
                    f'"split": "{split}"',
                )
                if value in visible
            ]
            if forbidden:
                prompt_leakage.append(f"{final_record['id']}: {', '.join(forbidden)}")
            assistant = {
                "role": "assistant",
                "content": _compact_json(target),
            }
            row = {
                "id": final_record["id"],
                "messages": [*prompt, assistant],
            }
            canonical.append(final_record)
            materialized[split].append(row)
            targets_by_id[str(final_record["id"])] = target
            records_by_pair_label[(pair_id, label)] = final_record
            label_counts[(split, label)] += 1
            target_hashes[
                hashlib.sha256(assistant["content"].encode()).hexdigest()
            ] += 1
            manifest_rows.append(
                {
                    "record_id": final_record["id"],
                    "pair_id": pair_id,
                    "split": split,
                    "label": label,
                    "target_cwe": pair_cwes[pair_id],
                    "compiler_variant": variant,
                    "compiler_group_id": final_record["metadata"]["compiler_group_id"],
                    "token_count": token_counts[(pair_id, label, variant)],
                    "representation": (
                        "pseudo_c+static_features+bounded_assembly_evidence"
                    ),
                    "eligible": True,
                    "disposition": "selected",
                }
            )

    challenge = [
        {"id": row["id"], "messages": row["messages"][:2]}
        for row in materialized["test"]
    ]
    gold = [
        {"id": row["id"], "expected_output": targets_by_id[str(row["id"])]}
        for row in materialized["test"]
    ]
    consistency_challenge: list[dict[str, Any]] = []
    consistency_gold: list[dict[str, Any]] = []
    for pair_id in consistency_pair_ids:
        for variant in BINARY_V1_VARIANTS:
            for label in ("present", "not_observed"):
                record, target = prepared[(pair_id, label, variant)]
                final_record = deepcopy(record)
                final_record["metadata"]["split"] = "test"
                consistency_challenge.append(
                    {
                        "id": final_record["id"],
                        "messages": format_binary_prompt(final_record),
                    }
                )
                consistency_gold.append(
                    {"id": final_record["id"], "expected_output": target}
                )
    manual_review_pairs = _select_consistency_pairs(
        accepted_pair_ids,
        pair_cwes,
        seed=seed,
        count=manual_review_records // 2,
    )
    manual_review: list[dict[str, Any]] = []
    for pair_id in manual_review_pairs:
        for label in ("present", "not_observed"):
            record = records_by_pair_label[(pair_id, label)]
            function = record["analysis"]["functions"][0]
            manual_review.append(
                {
                    "id": record["id"],
                    "pair_id": pair_id,
                    "private_label": label,
                    "target_cwe": pair_cwes[pair_id],
                    "compiler_variant": selected_variants[pair_id],
                    "pseudo_c": function["pseudo_c"],
                    "assembly_evidence": function["assembly_evidence"],
                    "static_features": function["static_features"],
                    "expected_output": targets_by_id[str(record["id"])],
                    "operator_label_error": None,
                    "operator_evidence_error": None,
                    "notes": "",
                }
            )

    duplicate_count = sum(count - 1 for count in target_hashes.values())
    split_pair_sets = {
        split: {pair_id for pair_id, value in split_by_pair.items() if value == split}
        for split in ("train", "validation", "test")
    }
    overlap_count = sum(
        len(split_pair_sets[left] & split_pair_sets[right])
        for left, right in (
            ("train", "validation"),
            ("train", "test"),
            ("validation", "test"),
        )
    )
    selected_variant_counts = Counter(selected_variants.values())
    selected_token_counts = [
        token_counts[(pair_id, label, selected_variants[pair_id])]
        for pair_id in accepted_pair_ids
        for label in ("present", "not_observed")
    ]
    maximum_tokens = max(selected_token_counts, default=0)
    counts = {
        "accepted_pairs": len(accepted_pair_ids),
        "train_pairs": len(split_pair_sets["train"]),
        "validation_pairs": len(split_pair_sets["validation"]),
        "test_pairs": len(split_pair_sets["test"]),
        "train_records": len(materialized["train"]),
        "validation_records": len(materialized["validation"]),
        "challenge_records": len(challenge),
        "gold_records": len(gold),
        "consistency_pairs": len(consistency_pair_ids),
        "consistency_records": len(consistency_challenge),
        "labels": {
            f"{split}:{label}": label_counts[(split, label)]
            for split in ("train", "validation", "test")
            for label in ("present", "not_observed")
        },
        "selected_variants": {
            variant: selected_variant_counts[variant] for variant in BINARY_V1_VARIANTS
        },
    }
    quality_gates = {
        "accepted_pair_supply": len(accepted_pair_ids) == required_pairs,
        "pair_split_overlap": overlap_count == 0,
        "split_and_class_quota": (
            counts["train_records"] == train_pairs * 2
            and counts["validation_records"] == validation_pairs * 2
            and counts["challenge_records"] == test_pairs * 2
            and all(
                label_counts[(split, label)] == expected
                for split, expected in (
                    ("train", train_pairs),
                    ("validation", validation_pairs),
                    ("test", test_pairs),
                )
                for label in ("present", "not_observed")
            )
        ),
        "schema_and_semantic_validation": not semantic_errors,
        "model_visible_leakage": not prompt_leakage,
        "tokenizer_cutoff": maximum_tokens <= cutoff_len,
        "exact_target_duplicate_rate": (
            duplicate_count / len(canonical) if canonical else 0.0
        )
        <= 0.05,
        "challenge_gold_contract": (
            {str(row["id"]) for row in challenge} == {str(row["id"]) for row in gold}
            and all(set(row) == {"id", "messages"} for row in challenge)
            and all(set(row) == {"id", "expected_output"} for row in gold)
        ),
        "compiler_consistency_supply": (
            len(consistency_pair_ids) == consistency_pairs
            and len(consistency_challenge) == consistency_pairs * 8
        ),
        "raw_payload_absent": all(
            record["metadata"]["contains_executable_payload"] is False
            for record in canonical
        ),
    }
    audit = {
        "schema_version": "aegislm.phase-f-binary-v1-audit.v1",
        "profile": BINARY_V1_PROFILE,
        "target_policy": BINARY_V1_TARGET_POLICY,
        "overall_pass": all(quality_gates.values()),
        "seed": seed,
        "cutoff_len": cutoff_len,
        "tokenizer_name_or_path": str(
            getattr(tokenizer, "name_or_path", type(tokenizer).__name__)
        ),
        "counts": counts,
        "metrics": {
            "maximum_token_count": maximum_tokens,
            "over_cutoff_count": sum(
                value > cutoff_len for value in selected_token_counts
            ),
            "pair_split_overlap_count": overlap_count,
            "prompt_leakage_count": len(prompt_leakage),
            "semantic_error_count": len(semantic_errors),
            "exact_target_duplicate_rate": (
                duplicate_count / len(canonical) if canonical else 0.0
            ),
            "selected_variant_count_spread": (
                max(selected_variant_counts.values(), default=0)
                - min(
                    (
                        selected_variant_counts[variant]
                        for variant in BINARY_V1_VARIANTS
                    ),
                    default=0,
                )
            ),
        },
        "quality_gates": quality_gates,
        "errors": [*semantic_errors, *prompt_leakage],
    }
    if not audit["overall_pass"]:
        failed = [name for name, passed in quality_gates.items() if not passed]
        raise PhaseFDatasetError("binary v1 quality gates failed: " + ", ".join(failed))
    return {
        "canonical_records": canonical,
        "manifest": manifest_rows,
        "train": materialized["train"],
        "validation": materialized["validation"],
        "challenge": challenge,
        "gold": gold,
        "consistency_challenge": consistency_challenge,
        "consistency_gold": consistency_gold,
        "manual_review": manual_review,
        "audit": audit,
    }


def freeze_binary_v1(
    prepared: Mapping[str, Any],
    output_dir: Path,
    *,
    source_gate_path: str,
    source_records_path: str,
    train_dataset_name: str = BINARY_V1_TRAIN_NAME,
    validation_dataset_name: str = BINARY_V1_VALIDATION_NAME,
) -> dict[str, Any]:
    """Atomically freeze prepared binary v1 data and its hash inventory."""
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise PhaseFDatasetError(f"output directory already exists: {output_dir}")
    parent = output_dir.parent
    parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}-", dir=parent))
    try:
        canonical = list(prepared["canonical_records"])
        manifest_rows = list(prepared["manifest"])
        train = list(prepared["train"])
        validation = list(prepared["validation"])
        write_jsonl(canonical, temporary / "private" / "records.jsonl")
        write_parquet(manifest_rows, temporary / "eligible_manifest.parquet")
        write_jsonl(train, temporary / "train.jsonl")
        write_jsonl(validation, temporary / "validation.jsonl")
        write_jsonl(list(prepared["challenge"]), temporary / "challenge.jsonl")
        write_jsonl(list(prepared["gold"]), temporary / "gold.jsonl")
        write_jsonl(
            list(prepared["consistency_challenge"]),
            temporary / "compiler_consistency_challenge.jsonl",
        )
        write_jsonl(
            list(prepared["consistency_gold"]),
            temporary / "compiler_consistency_gold.jsonl",
        )
        write_jsonl(
            list(prepared["manual_review"]),
            temporary / "private" / "manual_review_100.jsonl",
        )
        train_export = [_to_llamafactory_record(row) for row in train]
        validation_export = [_to_llamafactory_record(row) for row in validation]
        write_llamafactory_dataset(
            train_export,
            temporary / "llamafactory" / "train.jsonl",
        )
        write_llamafactory_dataset(
            validation_export,
            temporary / "llamafactory" / "validation.jsonl",
        )
        dataset_info: dict[str, Any] = {}
        dataset_info.update(
            build_dataset_info_entry(
                dataset_name=train_dataset_name,
                file_name="llamafactory/train.jsonl",
            )
        )
        dataset_info.update(
            build_dataset_info_entry(
                dataset_name=validation_dataset_name,
                file_name="llamafactory/validation.jsonl",
            )
        )
        _write_json(temporary / "dataset_info.json", dataset_info)
        audit = dict(prepared["audit"])
        _write_json(temporary / "target_quality_and_token_audit.json", audit)
        manifest = {
            "schema_version": "aegislm.phase-f-binary-dataset-manifest.v1",
            "profile": BINARY_V1_PROFILE,
            "status": "manual_target_review_required",
            "approved_for_training": False,
            "seed": audit["seed"],
            "cutoff_len": audit["cutoff_len"],
            "output_contract": "aegislm.binary-assessment-output.v1",
            "target_policy": BINARY_V1_TARGET_POLICY,
            "source_artifacts": {
                "final_gate": source_gate_path,
                "normalized_audit_pool": source_records_path,
            },
            "counts": audit["counts"],
            "metrics": audit["metrics"],
            "quality_gates": audit["quality_gates"],
            "manual_review": {
                "required_count": len(prepared["manual_review"]),
                "status": "not_started",
                "maximum_label_or_evidence_error_rate": 0.05,
            },
            "challenge_gold_policy": {
                "challenge_file": "challenge.jsonl",
                "gold_file": "gold.jsonl",
                "gold_must_not_be_passed_to_inference": True,
                "compiler_consistency_challenge": (
                    "compiler_consistency_challenge.jsonl"
                ),
                "compiler_consistency_gold": "compiler_consistency_gold.jsonl",
            },
            "llamafactory": {
                "dataset_info": "dataset_info.json",
                "dataset_dir": ".",
                "train_dataset": train_dataset_name,
                "validation_dataset": validation_dataset_name,
                "format": "alpaca",
            },
            "frozen_files": _file_hashes(temporary),
        }
        _write_json(temporary / "dataset_manifest.json", manifest)
        _write_hashes(temporary)
        temporary.replace(output_dir)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return manifest


def summarize_binary_manual_review(
    rows: Sequence[Mapping[str, Any]],
    *,
    required_count: int = BINARY_V1_MANUAL_REVIEW_RECORDS,
    maximum_error_rate: float = 0.05,
) -> dict[str, Any]:
    """Validate the fixed binary target review and return its gate decision."""
    if len(rows) != required_count:
        raise ValueError(
            f"manual review requires exactly {required_count} rows; got {len(rows)}"
        )
    unfinished = [
        str(row.get("id") or index)
        for index, row in enumerate(rows)
        if not isinstance(row.get("operator_label_error"), bool)
        or not isinstance(row.get("operator_evidence_error"), bool)
    ]
    reviewed = [
        row
        for row in rows
        if isinstance(row.get("operator_label_error"), bool)
        and isinstance(row.get("operator_evidence_error"), bool)
    ]
    error_count = sum(
        bool(row["operator_label_error"]) or bool(row["operator_evidence_error"])
        for row in reviewed
    )
    maximum_error_count = math.floor(required_count * maximum_error_rate)
    early_failure = bool(unfinished) and error_count > maximum_error_count
    if unfinished and not early_failure:
        raise ValueError(
            "manual review has unfinished boolean decisions: "
            + ", ".join(unfinished[:10])
        )
    error_rate = error_count / required_count
    return {
        "required_count": required_count,
        "reviewed_count": len(reviewed),
        "unfinished_count": len(unfinished),
        "error_count": error_count,
        "error_rate": error_rate,
        "observed_error_rate": error_count / len(reviewed) if reviewed else 0.0,
        "maximum_error_count": maximum_error_count,
        "maximum_label_or_evidence_error_rate": maximum_error_rate,
        "status": (
            "fail_early"
            if early_failure
            else "pass"
            if error_rate <= maximum_error_rate
            else "fail"
        ),
        "pass": not unfinished and error_rate <= maximum_error_rate,
    }


def _index_compiler_groups(
    records: Sequence[Mapping[str, Any]],
) -> dict[str, dict[str, Mapping[str, Any]]]:
    groups: dict[str, dict[str, Mapping[str, Any]]] = {}
    ids: set[str] = set()
    for record in records:
        validate_binary_record(record)
        record_id = str(record["id"])
        if record_id in ids:
            raise PhaseFDatasetError(f"duplicate normalized record ID: {record_id}")
        ids.add(record_id)
        group_id = str(record["metadata"]["compiler_group_id"])
        variant = (
            f"{record['artifact']['compiler']}-{record['artifact']['optimization']}"
        )
        if variant in groups.setdefault(group_id, {}):
            raise PhaseFDatasetError(
                f"duplicate compiler variant in {group_id}: {variant}"
            )
        groups[group_id][variant] = record
    for group_id, variants in groups.items():
        if not variants or not set(variants) <= set(BINARY_V1_VARIANTS):
            raise PhaseFDatasetError(
                f"{group_id} contains no supported compiler variants"
            )
    return groups


def _select_balanced_variants(
    pairs: Mapping[str, Mapping[str, Mapping[str, Mapping[str, Any]]]],
    *,
    tokenizer: Any,
    seed: int,
    cutoff_len: int,
) -> tuple[
    dict[str, str],
    dict[tuple[str, str, str], tuple[dict[str, Any], dict[str, Any]]],
    dict[tuple[str, str, str], int],
]:
    prepared: dict[tuple[str, str, str], tuple[dict[str, Any], dict[str, Any]]] = {}
    token_counts: dict[tuple[str, str, str], int] = {}
    eligible: dict[str, list[str]] = {}
    for pair_id, labels in pairs.items():
        available_variants = tuple(
            variant
            for variant in BINARY_V1_VARIANTS
            if variant in labels["present"] and variant in labels["not_observed"]
        )
        for variant in available_variants:
            maximum = 0
            variant_prepared: dict[str, tuple[dict[str, Any], dict[str, Any], int]] = {}
            compacted_by_label = {
                label: compact_binary_record(labels[label][variant])
                for label in ("present", "not_observed")
            }
            try:
                pair_targets = dict(
                    zip(
                        ("present", "not_observed"),
                        build_binary_pair_targets(
                            compacted_by_label["present"],
                            compacted_by_label["not_observed"],
                        ),
                        strict=True,
                    )
                )
            except BinaryRecordValidationError:
                continue
            for label in ("present", "not_observed"):
                compacted = compacted_by_label[label]
                target = pair_targets[label]
                token_count = count_source_training_tokens(
                    tokenizer,
                    format_binary_prompt(compacted),
                    target,
                )
                variant_prepared[label] = (compacted, target, token_count)
                maximum = max(maximum, token_count)
            if variant_prepared and maximum <= cutoff_len:
                for label, (compacted, target, token_count) in variant_prepared.items():
                    prepared[(pair_id, label, variant)] = (compacted, target)
                    token_counts[(pair_id, label, variant)] = token_count
                eligible.setdefault(pair_id, []).append(variant)
        if not eligible.get(pair_id):
            available_maximums = [
                max(
                    token_counts[(pair_id, label, variant)]
                    for label in ("present", "not_observed")
                )
                for variant in available_variants
                if all(
                    (pair_id, label, variant) in token_counts
                    for label in ("present", "not_observed")
                )
            ]
            detail = (
                f"minimum pair maximum is {min(available_maximums)}"
                if available_maximums
                else "target-specific evidence is absent in every variant"
            )
            raise PhaseFDatasetError(
                f"{pair_id} has no eligible compiler variant within cutoff "
                f"{cutoff_len}; {detail}"
            )

    counts: Counter[str] = Counter()
    selected: dict[str, str] = {}
    ordered_pairs = sorted(
        pairs,
        key=lambda pair_id: _stable_hash(f"{seed}:variant-pair:{pair_id}"),
    )
    for pair_id in ordered_pairs:
        choices = sorted(
            eligible[pair_id],
            key=lambda variant: (
                counts[variant],
                _stable_hash(f"{seed}:{pair_id}:{variant}"),
            ),
        )
        selected[pair_id] = choices[0]
        counts[choices[0]] += 1
    return selected, prepared, token_counts


def _stratified_pair_split(
    pair_cwes: Mapping[str, str],
    *,
    seed: int,
    sizes: Mapping[str, int],
    required_test_pair_ids: Sequence[str] = (),
) -> dict[str, str]:
    required_test = set(required_test_pair_ids)
    unknown = required_test - set(pair_cwes)
    if unknown:
        raise PhaseFDatasetError("required test pair is absent from accepted supply")
    if len(required_test) > int(sizes["test"]):
        raise PhaseFDatasetError("required test pairs exceed test split quota")
    remaining = set(pair_cwes) - required_test
    assignments: dict[str, str] = {pair_id: "test" for pair_id in required_test}
    for split in ("train", "validation"):
        target = int(sizes[split])
        quotas = _proportional_quotas(
            Counter(pair_cwes[pair_id] for pair_id in remaining),
            target,
            seed=seed,
            namespace=split,
        )
        chosen: set[str] = set()
        for cwe, quota in quotas.items():
            candidates = sorted(
                (pair_id for pair_id in remaining if pair_cwes[pair_id] == cwe),
                key=lambda pair_id: _stable_hash(f"{seed}:{split}:{cwe}:{pair_id}"),
            )
            chosen.update(candidates[:quota])
        if len(chosen) != target:
            raise PhaseFDatasetError(f"{split} stratification produced {len(chosen)}")
        assignments.update({pair_id: split for pair_id in chosen})
        remaining -= chosen
    remaining_test_quota = int(sizes["test"]) - len(required_test)
    if len(remaining) != remaining_test_quota:
        raise PhaseFDatasetError(
            f"test stratification produced {len(remaining)}, "
            f"expected {remaining_test_quota}"
        )
    assignments.update({pair_id: "test" for pair_id in remaining})
    return assignments


def _proportional_quotas(
    counts: Mapping[str, int],
    target: int,
    *,
    seed: int,
    namespace: str,
) -> dict[str, int]:
    total = sum(counts.values())
    if target > total:
        raise PhaseFDatasetError("split quota exceeds remaining pair supply")
    exact = {key: target * count / total for key, count in counts.items()}
    quotas = {key: int(value) for key, value in exact.items()}
    remainder = target - sum(quotas.values())
    order = sorted(
        counts,
        key=lambda key: (
            -(exact[key] - quotas[key]),
            _stable_hash(f"{seed}:{namespace}:quota:{key}"),
        ),
    )
    for key in order[:remainder]:
        quotas[key] += 1
    return quotas


def _select_consistency_pairs(
    pair_ids: Sequence[str],
    pair_cwes: Mapping[str, str],
    *,
    seed: int,
    count: int,
) -> list[str]:
    if count > len(pair_ids):
        raise PhaseFDatasetError("compiler consistency quota exceeds test pairs")
    quotas = _proportional_quotas(
        Counter(pair_cwes[pair_id] for pair_id in pair_ids),
        count,
        seed=seed,
        namespace="consistency",
    )
    selected: list[str] = []
    for cwe, quota in sorted(quotas.items()):
        candidates = sorted(
            (pair_id for pair_id in pair_ids if pair_cwes[pair_id] == cwe),
            key=lambda pair_id: _stable_hash(f"{seed}:consistency:{cwe}:{pair_id}"),
        )
        selected.extend(candidates[:quota])
    return sorted(selected)


def _to_llamafactory_record(row: Mapping[str, Any]) -> dict[str, str]:
    messages = row["messages"]
    if not isinstance(messages, list) or len(messages) != 3:
        raise PhaseFDatasetError("binary training rows require three messages")
    if tuple(message["role"] for message in messages) != (
        "system",
        "user",
        "assistant",
    ):
        raise PhaseFDatasetError("binary training row roles are invalid")
    return {
        "system": str(messages[0]["content"]),
        "instruction": str(messages[1]["content"]),
        "input": "",
        "output": str(messages[2]["content"]),
    }


def _compact_json(value: Mapping[str, Any]) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _stable_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _file_hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): _sha256_file(path)
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.name not in {"SHA256SUMS", "dataset_manifest.json"}
    }


def _write_hashes(root: Path) -> None:
    lines = [
        f"{_sha256_file(path)}  {path.relative_to(root).as_posix()}\n"
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.name != "SHA256SUMS"
    ]
    (root / "SHA256SUMS").write_text("".join(lines), encoding="utf-8")


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
