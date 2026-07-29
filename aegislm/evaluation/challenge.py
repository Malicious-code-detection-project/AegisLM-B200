"""Build deterministic, label-blind source-code evaluation challenges."""

from __future__ import annotations

import hashlib
import json
import random
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

GOLD_SCHEMA_VERSION = "aegislm.blind-code-gold.v1"
CHALLENGE_SCHEMA_VERSION = "aegislm.blind-code-challenge.v1"


def collect_training_fingerprints(
    records: Iterable[Mapping[str, Any]],
) -> set[str]:
    """Collect source-code fingerprints from normalized training records."""
    fingerprints: set[str] = set()
    for record in records:
        signals = _signals(record)
        for key in (
            "code_excerpt_sha256",
            "vulnerable_excerpt_sha256",
            "fixed_excerpt_sha256",
        ):
            value = signals.get(key)
            if isinstance(value, str) and value:
                fingerprints.add(value)
    return fingerprints


def build_blind_code_challenge(
    records: Iterable[Mapping[str, Any]],
    *,
    per_class: int,
    seed: int,
    training_fingerprints: set[str] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    """Create balanced prompt and gold records from DiverseVul test records.

    Labels, dataset names, source URLs, target fields, and pre-computed hashes are
    excluded from prompt records. Gold records must be stored separately from the
    prompt JSONL used during inference.
    """
    if per_class < 1:
        raise ValueError("per_class must be at least 1")

    seen_fingerprints = training_fingerprints or set()
    candidates: dict[bool, list[tuple[dict[str, Any], dict[str, Any]]]] = {
        False: [],
        True: [],
    }
    source_count = 0
    eligible_count = 0
    excluded_training_overlap = 0

    for record in records:
        source_count += 1
        converted = _convert_diversevul_record(record)
        if converted is None:
            continue
        eligible_count += 1
        prompt_record, gold_record = converted
        fingerprint = str(gold_record["code_sha256"])
        if fingerprint in seen_fingerprints:
            excluded_training_overlap += 1
            continue
        candidates[bool(gold_record["is_vulnerable"])].append(
            (prompt_record, gold_record)
        )

    rng = random.Random(seed)
    for class_candidates in candidates.values():
        rng.shuffle(class_candidates)

    available_per_class = min(len(candidates[False]), len(candidates[True]))
    if available_per_class < per_class:
        raise ValueError(
            "not enough balanced DiverseVul records after filtering: "
            f"requested={per_class}, available={available_per_class}"
        )

    selected = candidates[False][:per_class] + candidates[True][:per_class]
    rng.shuffle(selected)
    prompt_records = [prompt for prompt, _gold in selected]
    gold_records = [gold for _prompt, gold in selected]
    summary = {
        "source_count": source_count,
        "eligible_count": eligible_count,
        "excluded_training_overlap": excluded_training_overlap,
        "selected_benign": per_class,
        "selected_vulnerable": per_class,
        "selected_total": len(selected),
    }
    return prompt_records, gold_records, summary


def write_jsonl(records: Iterable[Mapping[str, Any]], path: Path) -> int:
    """Write mappings as UTF-8 JSONL and return the record count."""
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as output_file:
        for record in records:
            output_file.write(json.dumps(record, ensure_ascii=False) + "\n")
            count += 1
    return count


def _convert_diversevul_record(
    record: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    signals = _signals(record)
    if signals.get("dataset") != "DiverseVul":
        return None

    target = signals.get("target")
    if target not in (0, 1, False, True):
        return None
    code = _extract_code(record)
    if not code:
        return None

    source_fingerprint = signals.get("code_excerpt_sha256")
    fingerprint = (
        source_fingerprint
        if isinstance(source_fingerprint, str) and source_fingerprint
        else hashlib.sha256(code.encode("utf-8")).hexdigest()
    )
    record_id = f"aegislm-code-{fingerprint}"
    prompt_record = {
        "id": record_id,
        "challenge_schema": CHALLENGE_SCHEMA_VERSION,
        "source": {
            "type": "public_security_dataset",
            "name": "AegisLM blind code challenge",
            "url": None,
            "license_or_terms": None,
            "retrieved_at": None,
        },
        "input": {
            "task": (
                "analyze the supplied source-code excerpt for security "
                "vulnerabilities and explain only evidence visible in the code"
            ),
            "context": f"Source-code excerpt:\n{code}",
            "signals": {},
        },
        "metadata": {
            "split": "test",
            "safety_level": "redacted",
            "contains_executable_payload": False,
            "notes": [
                "Provenance and evaluation annotations are withheld during inference."
            ],
        },
    }
    gold_record = {
        "schema_version": GOLD_SCHEMA_VERSION,
        "record_id": record_id,
        "is_vulnerable": bool(target),
        "code_sha256": fingerprint,
    }
    return prompt_record, gold_record


def _signals(record: Mapping[str, Any]) -> Mapping[str, Any]:
    input_section = record.get("input")
    if not isinstance(input_section, Mapping):
        return {}
    signals = input_section.get("signals")
    return signals if isinstance(signals, Mapping) else {}


def _extract_code(record: Mapping[str, Any]) -> str:
    input_section = record.get("input")
    if not isinstance(input_section, Mapping):
        return ""
    context = input_section.get("context")
    if not isinstance(context, str):
        return ""

    marker = "Code excerpt:\n"
    if marker not in context:
        return ""
    return context.split(marker, 1)[1].strip()
