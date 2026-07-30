"""Apply the actual Qwen tokenizer and target-builder gate to binary pairs."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from transformers import AutoTokenizer

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.datasets.binary import (  # noqa: E402
    BinaryRecordValidationError,
    BINARY_STRICT_ROLE_CWES,
    BINARY_STRICT_V4_QUARANTINED_CWES,
    BINARY_STRICT_V4_ROLE_CWES,
    BINARY_STRICT_V5_QUARANTINED_CWES,
    BINARY_STRICT_V5_ROLE_CWES,
    BINARY_STRICT_V6_QUARANTINED_CWES,
    BINARY_STRICT_V6_ROLE_CWES,
    BINARY_STRICT_V7_QUARANTINED_CWES,
    BINARY_STRICT_V7_ROLE_CWES,
    build_binary_pair_role_targets,
    build_binary_pair_strict_role_targets,
    build_binary_pair_strict_v4_role_targets,
    build_binary_pair_strict_v5_role_targets,
    build_binary_pair_strict_v6_role_targets,
    build_binary_pair_strict_v7_role_targets,
    build_binary_pair_targets,
    compact_binary_record,
    format_binary_prompt,
    format_binary_role_prompt,
    validate_binary_record,
)
from aegislm.datasets.phase_f import load_jsonl  # noqa: E402
from aegislm.datasets.source_audit import count_source_training_tokens  # noqa: E402


def build_tokenizer_gate(
    relation_gate: Mapping[str, Any],
    record_sources: Sequence[Sequence[Mapping[str, Any]]],
    *,
    tokenizer: Any,
    required_pairs: int,
    cutoff_len: int,
    minimum_consistency_pairs: int = 100,
    target_contract: str = "v1",
) -> dict[str, Any]:
    """Select exact pairs only after both labels fit without truncation."""
    if target_contract not in {
        "v1",
        "v2",
        "v2-strict",
        "v2-strict-v4",
        "v2-strict-v5",
        "v2-strict-v6",
        "v2-strict-v7",
    }:
        raise ValueError(f"unsupported target contract: {target_contract}")
    target_builder = {
        "v1": build_binary_pair_targets,
        "v2": build_binary_pair_role_targets,
        "v2-strict": build_binary_pair_strict_role_targets,
        "v2-strict-v4": build_binary_pair_strict_v4_role_targets,
        "v2-strict-v5": build_binary_pair_strict_v5_role_targets,
        "v2-strict-v6": build_binary_pair_strict_v6_role_targets,
        "v2-strict-v7": build_binary_pair_strict_v7_role_targets,
    }[target_contract]
    prompt_formatter = (
        format_binary_role_prompt
        if target_contract
        in {
            "v2",
            "v2-strict",
            "v2-strict-v4",
            "v2-strict-v5",
            "v2-strict-v6",
            "v2-strict-v7",
        }
        else format_binary_prompt
    )
    indexed: dict[tuple[str, str], Mapping[str, Any]] = {}
    for records in record_sources:
        for record in records:
            validate_binary_record(record)
            group_id = str(record["metadata"]["compiler_group_id"])
            variant = (
                f"{record['artifact']['compiler']}-{record['artifact']['optimization']}"
            )
            key = (group_id, variant)
            previous = indexed.get(key)
            if previous is not None and previous != record:
                raise ValueError(f"conflicting normalized record: {key}")
            indexed[key] = record

    qualified_ids = [str(value) for value in relation_gate["qualified_pair_ids"]]
    configured = relation_gate["qualified_pair_variants"]
    eligible_variants: dict[str, list[str]] = {}
    excluded: dict[str, dict[str, str]] = {}
    pair_cwes: dict[str, str] = {}
    observed_maximum = 0
    for pair_id in qualified_ids:
        variant_failures: dict[str, str] = {}
        for variant_value in configured[pair_id]:
            variant = str(variant_value)
            maximum = 0
            try:
                compacted_by_label: dict[str, Mapping[str, Any]] = {}
                for label in ("present", "not_observed"):
                    opaque = hashlib.sha256(f"{pair_id}:{label}".encode()).hexdigest()[
                        :16
                    ]
                    candidate = indexed.get((f"binary-group-{opaque}", variant))
                    if candidate is None:
                        raise ValueError(f"missing normalized {label} record")
                    pair_cwes.setdefault(pair_id, str(candidate["task"]["target_cwe"]))
                    compacted = compact_binary_record(candidate)
                    compacted_by_label[label] = compacted
                targets = dict(
                    zip(
                        ("present", "not_observed"),
                        target_builder(
                            compacted_by_label["present"],
                            compacted_by_label["not_observed"],
                        ),
                        strict=True,
                    )
                )
                for label in ("present", "not_observed"):
                    prompt_record = compacted_by_label[label]
                    target = targets[label]
                    tokens = count_source_training_tokens(
                        tokenizer,
                        prompt_formatter(prompt_record),
                        target,
                    )
                    maximum = max(maximum, tokens)
                    observed_maximum = max(observed_maximum, tokens)
            except (BinaryRecordValidationError, ValueError) as exc:
                variant_failures[variant] = f"target_error: {exc}"
                continue
            if maximum > cutoff_len:
                variant_failures[variant] = (
                    f"tokenizer_cutoff: {maximum} > {cutoff_len}"
                )
                continue
            eligible_variants.setdefault(pair_id, []).append(variant)
        if pair_id not in eligible_variants:
            excluded[pair_id] = variant_failures

    eligible_order = [
        pair_id for pair_id in qualified_ids if pair_id in eligible_variants
    ]
    accepted = eligible_order[:required_pairs]
    reserve = eligible_order[required_pairs:]
    accepted_variants = {pair_id: eligible_variants[pair_id] for pair_id in accepted}
    full_variant_pairs = sum(
        len(accepted_variants[pair_id]) == 4 for pair_id in accepted
    )
    cwes = Counter(pair_cwes[pair_id] for pair_id in accepted)
    gates = {
        "accepted_pair_supply": len(accepted) == required_pairs,
        "tokenizer_cutoff": not any(
            reason.startswith("tokenizer_cutoff")
            for failures in excluded.values()
            for reason in failures.values()
        )
        or len(eligible_order) >= required_pairs,
        "compiler_consistency_supply": (
            full_variant_pairs >= minimum_consistency_pairs
        ),
        "raw_payload_absent": True,
    }
    review_eligible = (
        len(eligible_order) >= 50
        and full_variant_pairs >= minimum_consistency_pairs
        and gates["raw_payload_absent"]
    )
    passed = all(gates.values())
    result = {
        "schema_version": "aegislm.phase-f-binary-tokenizer-gate.v1",
        "profile": "phase-f-binary-derived-v1",
        "target_policy": (
            "strict-cwe-role-evidence-v7"
            if target_contract == "v2-strict-v7"
            else "strict-cwe-role-evidence-v6"
            if target_contract == "v2-strict-v6"
            else "strict-cwe-role-evidence-v5"
            if target_contract == "v2-strict-v5"
            else "strict-cwe-role-evidence-v4"
            if target_contract == "v2-strict-v4"
            else "strict-cwe-role-evidence-v3"
            if target_contract == "v2-strict"
            else "role-structured-evidence-v2"
            if target_contract == "v2"
            else "memory-write-read-linked-evidence-v9"
        ),
        "output_contract": (
            "aegislm.binary-role-assessment-output.v2"
            if target_contract
            in {
                "v2",
                "v2-strict",
                "v2-strict-v4",
                "v2-strict-v5",
                "v2-strict-v6",
                "v2-strict-v7",
            }
            else "aegislm.binary-assessment-output.v1"
        ),
        "decision": "pass" if passed else "fail",
        "gate_pass": passed,
        "review_eligible": review_eligible,
        "target_relation_policy": relation_gate["target_relation_policy"],
        "required_accepted_pair_count": required_pairs,
        "accepted_pair_count": len(accepted),
        "accepted_pair_ids": accepted,
        "accepted_pair_variants": accepted_variants,
        "qualified_relation_pair_count": len(qualified_ids),
        "qualified_after_tokenizer_pair_count": len(eligible_order),
        "qualified_reserve_pair_count": len(reserve),
        "qualified_reserve_pair_ids": reserve,
        "excluded_pair_count": len(excluded),
        "excluded_pairs": excluded,
        "cutoff_len": cutoff_len,
        "maximum_observed_token_count": observed_maximum,
        "tokenizer_name_or_path": str(
            getattr(tokenizer, "name_or_path", type(tokenizer).__name__)
        ),
        "full_four_variant_pair_count": full_variant_pairs,
        "accepted_cwe_pair_counts": dict(sorted(cwes.items())),
        "quality_gates": gates,
        "raw_object_execution_count": 0,
        "selection_policy": (
            "frozen relation-qualified order after exact target and tokenizer gate"
        ),
    }
    if target_contract == "v2-strict":
        result["supported_cwes"] = sorted(BINARY_STRICT_ROLE_CWES)
        result["quarantined_cwes"] = []
    elif target_contract == "v2-strict-v4":
        result["supported_cwes"] = sorted(BINARY_STRICT_V4_ROLE_CWES)
        result["quarantined_cwes"] = sorted(BINARY_STRICT_V4_QUARANTINED_CWES)
    elif target_contract == "v2-strict-v5":
        result["supported_cwes"] = sorted(BINARY_STRICT_V5_ROLE_CWES)
        result["quarantined_cwes"] = sorted(BINARY_STRICT_V5_QUARANTINED_CWES)
    elif target_contract == "v2-strict-v6":
        result["supported_cwes"] = sorted(BINARY_STRICT_V6_ROLE_CWES)
        result["quarantined_cwes"] = sorted(BINARY_STRICT_V6_QUARANTINED_CWES)
    elif target_contract == "v2-strict-v7":
        result["supported_cwes"] = sorted(BINARY_STRICT_V7_ROLE_CWES)
        result["quarantined_cwes"] = sorted(BINARY_STRICT_V7_QUARANTINED_CWES)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--relation-gate", type=Path, required=True)
    parser.add_argument("--records", type=Path, action="append", required=True)
    parser.add_argument("--model-dir", type=Path, required=True)
    parser.add_argument("--required-pairs", type=int, default=2450)
    parser.add_argument("--cutoff-len", type=int, default=4096)
    parser.add_argument(
        "--target-contract",
        choices=(
            "v1",
            "v2",
            "v2-strict",
            "v2-strict-v4",
            "v2-strict-v5",
            "v2-strict-v6",
            "v2-strict-v7",
        ),
        default="v1",
    )
    parser.add_argument("--output-gate", type=Path, required=True)
    args = parser.parse_args()
    relation_gate = json.loads(args.relation_gate.read_text(encoding="utf-8"))
    tokenizer = AutoTokenizer.from_pretrained(
        args.model_dir,
        trust_remote_code=True,
        local_files_only=True,
    )
    gate = build_tokenizer_gate(
        relation_gate,
        [load_jsonl(path) for path in args.records],
        tokenizer=tokenizer,
        required_pairs=args.required_pairs,
        cutoff_len=args.cutoff_len,
        minimum_consistency_pairs=100,
        target_contract=args.target_contract,
    )
    gate["source_sha256"] = {
        "relation_gate": _sha256(args.relation_gate),
        "record_sources": {str(path): _sha256(path) for path in args.records},
    }
    args.output_gate.parent.mkdir(parents=True, exist_ok=True)
    args.output_gate.write_text(
        json.dumps(gate, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Phase F binary tokenizer gate: "
        f"accepted={gate['accepted_pair_count']}, "
        f"qualified={gate['qualified_after_tokenizer_pair_count']}, "
        f"excluded={gate['excluded_pair_count']}, "
        f"decision={gate['decision']}"
    )
    if not gate["gate_pass"]:
        raise SystemExit(2)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    main()
