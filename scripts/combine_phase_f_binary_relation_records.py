"""Combine filtered existing and recovery binary records under one frozen gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.datasets.binary import (  # noqa: E402
    binary_target_relation_visible,
    format_binary_prompt,
    validate_binary_record,
)
from aegislm.datasets.phase_f import load_jsonl, write_jsonl  # noqa: E402
from scripts.build_phase_f_binary_b0_records import prompt_leakage  # noqa: E402


def combine_relation_records(
    gate: Mapping[str, Any],
    record_sources: Sequence[Sequence[Mapping[str, Any]]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Select exactly the gate-authorized pair/variant/label records."""
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

    accepted = [str(value) for value in gate["accepted_pair_ids"]]
    configured = gate["accepted_pair_variants"]
    selected: list[dict[str, Any]] = []
    cwes: Counter[str] = Counter()
    variant_counts: Counter[str] = Counter()
    leakage: list[str] = []
    for pair_id in accepted:
        variants = [str(value) for value in configured[pair_id]]
        for variant in variants:
            pair_records: dict[str, Mapping[str, Any]] = {}
            for label in ("present", "not_observed"):
                opaque = hashlib.sha256(f"{pair_id}:{label}".encode()).hexdigest()[:16]
                key = (f"binary-group-{opaque}", variant)
                candidate = indexed.get(key)
                if candidate is None:
                    raise ValueError(f"missing selected record: {pair_id}/{variant}")
                if candidate["metadata"]["label"] != label:
                    raise ValueError(f"label mismatch: {pair_id}/{variant}/{label}")
                pair_records[label] = candidate
            present = pair_records["present"]
            fixed = pair_records["not_observed"]
            present_pseudo = str(present["analysis"]["functions"][0]["pseudo_c"])
            fixed_pseudo = str(fixed["analysis"]["functions"][0]["pseudo_c"])
            target_cwe = str(present["task"]["target_cwe"])
            if target_cwe != fixed["task"]["target_cwe"]:
                raise ValueError(f"target CWE mismatch: {pair_id}/{variant}")
            if present_pseudo.strip() == fixed_pseudo.strip():
                raise ValueError(f"pair distinction missing: {pair_id}/{variant}")
            if not binary_target_relation_visible(target_cwe, present_pseudo):
                raise ValueError(f"target relation missing: {pair_id}/{variant}")
            for label in ("present", "not_observed"):
                record = dict(pair_records[label])
                prompt = json.dumps(
                    format_binary_prompt(record),
                    ensure_ascii=False,
                )
                found = prompt_leakage(prompt)
                if found:
                    leakage.append(f"{record['id']}: {', '.join(found)}")
                selected.append(record)
            cwes[target_cwe] += 1
            variant_counts[variant] += 1

    expected_records = sum(len(configured[pair_id]) * 2 for pair_id in accepted)
    full_variant_pairs = sum(len(configured[pair_id]) == 4 for pair_id in accepted)
    ids = [str(record["id"]) for record in selected]
    audit = {
        "schema_version": "aegislm.phase-f-binary-relation-record-audit.v1",
        "profile": gate["profile"],
        "accepted_pair_count": len(accepted),
        "record_count": len(selected),
        "expected_record_count": expected_records,
        "unique_record_id_count": len(set(ids)),
        "full_four_variant_pair_count": full_variant_pairs,
        "compiler_consistency_supply_pass": full_variant_pairs >= 100,
        "selected_variant_counts": dict(sorted(variant_counts.items())),
        "target_cwe_variant_counts": dict(sorted(cwes.items())),
        "prompt_leakage_count": len(leakage),
        "prompt_leakage": leakage,
        "raw_executable_payload_count": 0,
        "raw_object_execution_count": 0,
        "target_relation_policy": gate["target_relation_policy"],
        "gate_pass": (
            len(selected) == expected_records
            and len(set(ids)) == len(selected)
            and full_variant_pairs >= 100
            and not leakage
        ),
    }
    return selected, audit


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gate", type=Path, required=True)
    parser.add_argument(
        "--records",
        type=Path,
        action="append",
        required=True,
    )
    parser.add_argument("--output-jsonl", type=Path, required=True)
    parser.add_argument("--output-audit", type=Path, required=True)
    args = parser.parse_args()
    gate = json.loads(args.gate.read_text(encoding="utf-8"))
    records, audit = combine_relation_records(
        gate,
        [load_jsonl(path) for path in args.records],
    )
    write_jsonl(records, args.output_jsonl)
    audit["gate_sha256"] = _sha256(args.gate)
    audit["record_source_sha256"] = {str(path): _sha256(path) for path in args.records}
    audit["records_sha256"] = _sha256(args.output_jsonl)
    args.output_audit.parent.mkdir(parents=True, exist_ok=True)
    args.output_audit.write_text(
        json.dumps(audit, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Phase F binary relation records: "
        f"pairs={audit['accepted_pair_count']}, "
        f"records={audit['record_count']}, "
        f"full_variants={audit['full_four_variant_pair_count']}, "
        f"decision={'pass' if audit['gate_pass'] else 'fail'}"
    )
    print(f"records_sha256={audit['records_sha256']}")
    print(f"audit_sha256={_sha256(args.output_audit)}")
    if not audit["gate_pass"]:
        raise SystemExit(2)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    main()
