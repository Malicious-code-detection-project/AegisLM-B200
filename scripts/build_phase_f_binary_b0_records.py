"""Materialize the accepted Phase F B0 pairs as safe normalized records."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter
from collections.abc import Callable
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
from scripts.build_phase_f_binary_smoke_records import (  # noqa: E402
    sanitize_pseudo_c,
)

_FUNCTION_HEADER = re.compile(r"^[0-9a-f]+ <(.+)>:$")
_INSTRUCTION = re.compile(r"^\s*[0-9a-f]+:\s+(?:(?:[0-9a-f]{2})\s+)+\s*(.+?)\s*$")
_ANGLE_SYMBOL = re.compile(r"<[^>]+>")
_SOURCE_SYMBOL = re.compile(r"\bCWE[0-9]+_")
_SECTION = re.compile(r"\[\s*\d+\]\s+(\S+)")

StaticExtractor = Callable[[Path, str], dict[str, list[str]]]


def build_records(
    *,
    gate: dict[str, Any],
    review_entries: list[dict[str, Any]],
    compile_items: list[dict[str, Any]],
    static_extractor: StaticExtractor,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Join approved review evidence, objects, and bounded static features."""
    accepted = frozenset(str(value) for value in gate["accepted_pair_ids"])
    if len(accepted) != int(gate["required_accepted_pair_count"]):
        raise ValueError("B0 gate does not contain the required accepted pair supply")

    selected_variants = _selected_variants(gate, accepted)
    relation_audited = (
        gate.get("target_relation_policy") == "observable-target-relation-v1"
    )
    reviews: dict[tuple[str, str], dict[str, Any]] = {}
    for entry in review_entries:
        pair_id = str(entry["pair_id"])
        if pair_id not in accepted:
            continue
        if entry["operator_decision"] != "pass" and not relation_audited:
            raise ValueError(f"accepted pair has non-pass review: {pair_id}")
        variant = f"{entry['compiler']}-{entry['optimization']}"
        if variant not in selected_variants[pair_id]:
            continue
        key = (pair_id, variant)
        if key in reviews:
            raise ValueError(f"duplicate review variant: {pair_id}/{variant}")
        reviews[key] = entry

    objects: dict[tuple[str, str], dict[str, Any]] = {}
    for item in compile_items:
        pair_id = str(item["pair_id"])
        if pair_id not in accepted or not bool(item["compile_success"]):
            continue
        variant = f"{item['compiler']}-{item['optimization']}"
        if variant not in selected_variants[pair_id]:
            continue
        key = (pair_id, variant)
        if key in objects:
            raise ValueError(f"duplicate compiled variant: {pair_id}/{variant}")
        objects[key] = item

    expected_variants = {
        (pair_id, variant)
        for pair_id in accepted
        for variant in selected_variants[pair_id]
    }
    if set(reviews) != expected_variants:
        raise ValueError(
            "review evidence does not cover every accepted compiler variant"
        )
    if set(objects) != expected_variants:
        raise ValueError(
            "compiled objects do not cover every accepted compiler variant"
        )

    records: list[dict[str, Any]] = []
    leakage: list[str] = []
    assembly_linked = 0
    static_linked = 0
    for pair_id, variant in sorted(expected_variants):
        review = reviews[(pair_id, variant)]
        item = objects[(pair_id, variant)]
        object_path = Path(str(item["_object_path"]))
        for label, pseudo_field in (
            ("present", "present_pseudo_c"),
            ("not_observed", "not_observed_pseudo_c"),
        ):
            pseudo_c = sanitize_pseudo_c(str(review[pseudo_field]))
            if label == "present" and not binary_target_relation_visible(
                str(review["target_cwe"]),
                pseudo_c,
            ):
                raise ValueError(
                    "selected variant lacks observable target relation: "
                    f"{pair_id}/{variant}"
                )
            if label == "present" and pseudo_c == sanitize_pseudo_c(
                str(review["not_observed_pseudo_c"])
            ):
                raise ValueError(
                    "selected variant has no present/not_observed distinction: "
                    f"{pair_id}/{variant}"
                )
            features = static_extractor(object_path, label)
            opaque_group = hashlib.sha256(f"{pair_id}:{label}".encode()).hexdigest()[
                :16
            ]
            function_hash = hashlib.sha256(
                (
                    pseudo_c
                    + "\n"
                    + "\n".join(features["assembly"])
                    + "\n"
                    + "\n".join(features["imports"])
                    + "\n"
                    + "\n".join(features["sections"])
                ).encode()
            ).hexdigest()
            record: dict[str, Any] = {
                "schema_version": "aegislm.binary-analysis-record.v1",
                "id": f"binary-b0-{opaque_group}-{variant.lower()}",
                "artifact": {
                    "sha256": item["object_sha256"],
                    "format": "ELF",
                    "architecture": "x86_64",
                    "compiler": item["compiler"],
                    "optimization": item["optimization"],
                    "stripped": False,
                    "external_artifact_ref": (
                        f"artifact://phase-f-binary-b0/{item['object_sha256']}"
                    ),
                },
                "analysis": {
                    "analyzer": "GNU-binutils-normalizer",
                    "analyzer_version": "2.42",
                    "decompiler": "Ghidra",
                    "decompiler_version": "12.1.2",
                    "functions": [
                        {
                            "function_id": f"function-{opaque_group}",
                            "function_hash": function_hash,
                            "pseudo_c": pseudo_c,
                            "assembly_evidence": features["assembly"],
                            "static_features": {
                                "imports": features["imports"],
                                "sections": features["sections"],
                                "strings": [],
                                "symbols": [],
                            },
                        }
                    ],
                    "warnings": [
                        "The ELF relocatable object was not executed.",
                        (
                            "Source and debug symbols were used only for private "
                            "linkage and removed from model-visible evidence."
                        ),
                    ],
                },
                "task": {"target_cwe": review["target_cwe"]},
                "metadata": {
                    "split": "test",
                    "source_dataset": "NIST SARD Juliet C/C++ 1.3",
                    "label": label,
                    "compiler_group_id": f"binary-group-{opaque_group}",
                    "contains_executable_payload": False,
                },
            }
            validate_binary_record(record)
            prompt = json.dumps(format_binary_prompt(record), ensure_ascii=False)
            found = prompt_leakage(prompt)
            if found:
                leakage.append(f"{record['id']}: {', '.join(found)}")
            assembly_linked += bool(features["assembly"])
            static_linked += bool(features["imports"] or features["sections"])
            records.append(record)

    groups = Counter(str(record["metadata"]["compiler_group_id"]) for record in records)
    expected_records = sum(len(variants) * 2 for variants in selected_variants.values())
    expected_group_sizes = {
        "binary-group-"
        + hashlib.sha256(f"{pair_id}:{label}".encode()).hexdigest()[:16]: len(variants)
        for pair_id, variants in selected_variants.items()
        for label in ("present", "not_observed")
    }
    audit = {
        "schema_version": "aegislm.phase-f-binary-b0-record-audit.v1",
        "accepted_pair_count": len(accepted),
        "variant_count": sum(len(value) for value in selected_variants.values()),
        "record_count": len(records),
        "expected_record_count": expected_records,
        "compiler_group_count": len(groups),
        "compiler_groups_with_expected_variants": sum(
            value == expected_group_sizes.get(group_id)
            for group_id, value in groups.items()
        ),
        "schema_validation_rate": 1.0,
        "prompt_leakage_count": len(leakage),
        "prompt_leakage": leakage,
        "raw_executable_payload_count": 0,
        "raw_object_execution_count": 0,
        "pseudo_c_linkage_rate": 1.0,
        "assembly_linkage_rate": assembly_linked / len(records),
        "static_feature_linkage_rate": static_linked / len(records),
        "evidence_linkage_rate": sum(
            bool(record["analysis"]["functions"][0]["pseudo_c"])
            or bool(record["analysis"]["functions"][0]["assembly_evidence"])
            or any(record["analysis"]["functions"][0]["static_features"].values())
            for record in records
        )
        / len(records),
        "gate_pass": (
            len(records) == expected_records
            and len(groups) == len(accepted) * 2
            and groups == Counter(expected_group_sizes)
            and not leakage
        ),
    }
    return records, audit


def _selected_variants(
    gate: dict[str, Any],
    accepted: frozenset[str],
) -> dict[str, tuple[str, ...]]:
    allowed = {"gcc-O0", "gcc-O2", "clang-O0", "clang-O2"}
    configured = gate.get("accepted_pair_variants")
    if configured is None:
        return {
            pair_id: ("gcc-O0", "gcc-O2", "clang-O0", "clang-O2")
            for pair_id in accepted
        }
    if not isinstance(configured, dict) or set(configured) != set(accepted):
        raise ValueError("accepted_pair_variants must cover every accepted pair")
    result: dict[str, tuple[str, ...]] = {}
    for pair_id in accepted:
        values = tuple(str(value) for value in configured[pair_id])
        if not values or len(values) != len(set(values)) or not set(values) <= allowed:
            raise ValueError(f"invalid selected variants for pair: {pair_id}")
        result[pair_id] = values
    return result


def extract_static_features(object_path: Path, label: str) -> dict[str, list[str]]:
    """Extract bounded assembly, undefined imports, and section names."""
    assembly_text = _run(["objdump", "-d", "-C", str(object_path)])
    readelf_text = _run(["readelf", "-SW", str(object_path)])
    nm_text = _run(["nm", "-u", str(object_path)])
    return {
        "assembly": extract_labeled_assembly(assembly_text, label=label),
        "imports": extract_imports(nm_text),
        "sections": extract_sections(readelf_text),
    }


def extract_labeled_assembly(
    text: str,
    *,
    label: str,
    maximum_instructions: int = 80,
) -> list[str]:
    """Extract bounded instructions from Juliet present or fixed functions."""
    selected = False
    instructions: list[str] = []
    for line in text.splitlines():
        header = _FUNCTION_HEADER.match(line.strip())
        if header:
            selected = _matches_label(header.group(1), label)
            continue
        if not selected:
            continue
        match = _INSTRUCTION.match(line)
        if not match:
            continue
        value = _ANGLE_SYMBOL.sub("<symbol>", match.group(1))
        value = re.sub(r"\bCWE[0-9]+_[A-Za-z0-9_:()]+", "target_symbol", value)
        instructions.append(value)
        if len(instructions) >= maximum_instructions:
            break
    return instructions


def extract_imports(text: str) -> list[str]:
    """Return undefined imports after removing source-bearing symbols."""
    values: list[str] = []
    for line in text.splitlines():
        parts = line.strip().split()
        if len(parts) < 2 or parts[-2] != "U":
            continue
        value = parts[-1].split("@", maxsplit=1)[0]
        if value and not _SOURCE_SYMBOL.search(value):
            values.append(value)
    return sorted(dict.fromkeys(values))


def extract_sections(text: str) -> list[str]:
    """Return stable ELF section names."""
    values = [
        match.group(1) for match in map(_SECTION.search, text.splitlines()) if match
    ]
    return sorted(dict.fromkeys(values))


def prompt_leakage(prompt: str) -> list[str]:
    """Find private provenance, gold, source path, or label-bearing symbols."""
    patterns = {
        "dataset provenance": re.compile(r"(?:NIST SARD|Juliet)", re.IGNORECASE),
        "gold label": re.compile(r'"label"\s*:'),
        "metadata key": re.compile(r"source_dataset"),
        "artifact reference": re.compile(r"artifact://"),
        "source path": re.compile(r"(?:C/testcases|artifacts/evaluation)"),
        "source symbol": re.compile(r"\bCWE[0-9]+_"),
        "Juliet label symbol": re.compile(
            r"(?:::|_)(?:bad|good(?:G2B|B2G)?[A-Za-z0-9_]*)\s*\(",
        ),
    }
    return [name for name, pattern in patterns.items() if pattern.search(prompt)]


def load_compile_items(roots: list[Path]) -> list[dict[str, Any]]:
    """Load successful object references with an absolute private object path."""
    items: list[dict[str, Any]] = []
    for root in roots:
        summary = json.loads(
            (root / "compile-summary.json").read_text(encoding="utf-8")
        )
        for item in summary["results"]:
            copied = dict(item)
            if item["object_ref"] is not None:
                copied["_object_path"] = str((root / item["object_ref"]).resolve())
            items.append(copied)
    return items


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gate-summary", type=Path, required=True)
    parser.add_argument(
        "--review-jsonl",
        type=Path,
        action="append",
        required=True,
    )
    parser.add_argument(
        "--compile-root",
        type=Path,
        action="append",
        required=True,
    )
    parser.add_argument("--output-jsonl", type=Path, required=True)
    parser.add_argument("--output-audit", type=Path, required=True)
    args = parser.parse_args()
    gate = json.loads(args.gate_summary.read_text(encoding="utf-8"))
    review_entries = [
        json.loads(line)
        for path in args.review_jsonl
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    records, audit = build_records(
        gate=gate,
        review_entries=review_entries,
        compile_items=load_compile_items(args.compile_root),
        static_extractor=extract_static_features,
    )
    args.output_jsonl.parent.mkdir(parents=True, exist_ok=True)
    args.output_jsonl.write_text(
        "".join(
            json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"
            for record in records
        ),
        encoding="utf-8",
    )
    audit["gate_summary_sha256"] = _sha256_file(args.gate_summary)
    audit["records_sha256"] = _sha256_file(args.output_jsonl)
    args.output_audit.write_text(
        json.dumps(audit, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Phase F binary B0 normalized records: "
        f"records={audit['record_count']}, "
        f"leakage={audit['prompt_leakage_count']}, "
        f"decision={'pass' if audit['gate_pass'] else 'fail'}"
    )
    print(f"records_sha256={audit['records_sha256']}")
    print(f"audit_sha256={_sha256_file(args.output_audit)}")
    if not audit["gate_pass"]:
        raise SystemExit(2)


def _matches_label(symbol: str, label: str) -> bool:
    normalized = symbol.lower()
    if label == "present":
        return bool(re.search(r"(?:::|_)bad(?:\(\))?$", normalized))
    return bool(
        re.search(
            r"(?:::|_)good(?:g2b|b2g)?[a-z0-9_]*(?:\(\))?$",
            normalized,
        )
    )


def _run(command: list[str]) -> str:
    completed = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return completed.stdout


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    main()
