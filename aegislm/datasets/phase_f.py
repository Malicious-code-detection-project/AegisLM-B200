"""Phase F catalog, sampling, and safe source materialization helpers."""

from __future__ import annotations

import hashlib
import json
import random
import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from copy import deepcopy
from pathlib import Path
from typing import Any

import pyarrow as pa  # type: ignore[import-untyped]
import pyarrow.parquet as pq  # type: ignore[import-untyped]

PHASE_F_SOURCE_PROFILE = "phase-f-source-v2"
PHASE_F_BUILD_SEED = 20260728
CATALOG_SCHEMA_VERSION = "aegislm.raw-catalog.v1"
MANIFEST_SCHEMA_VERSION = "aegislm.eligible-manifest.v1"

PROMPT_VARIANTS = (
    "Analyze the supplied source-code excerpt for the scoped security task.",
    "Review the supplied function and report only security evidence visible in the code.",
    "Assess the supplied code for the target vulnerability without relying on provenance.",
    "Perform an evidence-grounded defensive review of the supplied source excerpt.",
)

_GOLD_SIGNAL_KEYS = {
    "dataset",
    "dataset_name",
    "source_dataset",
    "source_revision",
    "target",
    "label",
    "gold",
    "split",
    "expected_output",
    "is_vulnerable",
}
_LEAKAGE_PATTERNS = {
    "dataset_name": re.compile(r"\b(?:diversevul|bigvul)\b", re.IGNORECASE),
    "dataset_label": re.compile(
        r"\b(?:dataset\s+label|target\s*[=:]|labeled\s+vulnerable)\b",
        re.IGNORECASE,
    ),
    "split": re.compile(r"\b(?:train|validation|test)\s+split\b", re.IGNORECASE),
}
_CODE_MARKERS = (
    "Source-code excerpt:\n",
    "Code excerpt:\n",
    "Vulnerable excerpt:\n",
)


class PhaseFDatasetError(ValueError):
    """Raised when Phase F data cannot satisfy the fixed profile."""


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    """Load object-only JSONL with useful line errors."""
    records: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise PhaseFDatasetError(
                    f"{path}:{line_number}: invalid JSONL: {exc.msg}"
                ) from exc
            if not isinstance(value, dict):
                raise PhaseFDatasetError(
                    f"{path}:{line_number}: JSONL item must be an object"
                )
            records.append(value)
    return records


def write_jsonl(records: Iterable[Mapping[str, Any]], path: Path) -> int:
    """Write deterministic UTF-8 JSONL."""
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as stream:
        for record in records:
            stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
            count += 1
    return count


def write_parquet(rows: Sequence[Mapping[str, Any]], path: Path) -> None:
    """Write flat catalog/manifest rows as compressed Parquet."""
    if not rows:
        raise PhaseFDatasetError("cannot write an empty Parquet table")
    path.parent.mkdir(parents=True, exist_ok=True)
    table = pa.Table.from_pylist([dict(row) for row in rows])
    pq.write_table(table, path, compression="zstd")


def read_parquet(path: Path) -> list[dict[str, Any]]:
    """Read catalog/manifest Parquet into Python mappings."""
    return pq.read_table(path).to_pylist()


def build_raw_catalog(
    records: Sequence[Mapping[str, Any]],
    *,
    source_revisions: Mapping[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Audit canonical records without storing source or executable payloads."""
    revisions = source_revisions or {}
    catalog: list[dict[str, Any]] = []
    first_exact: dict[str, str] = {}
    first_near: dict[str, str] = {}

    for record in records:
        row = _catalog_row(record, revisions)
        exact_hash = row["content_sha256"]
        near_hash = row["near_duplicate_sha256"]
        row["exact_duplicate_of"] = first_exact.get(exact_hash)
        row["near_duplicate_of"] = first_near.get(near_hash)
        first_exact.setdefault(exact_hash, str(row["record_id"]))
        first_near.setdefault(near_hash, str(row["record_id"]))

        if row["contains_executable_payload"]:
            row["disposition"] = "reject"
            row["disposition_reason"] = "executable_payload_forbidden"
        elif row["exact_duplicate_of"] is not None:
            row["disposition"] = "reject"
            row["disposition_reason"] = "exact_duplicate"
        elif not row["has_source_code"]:
            row["disposition"] = "reject"
            row["disposition_reason"] = "source_code_missing"
        elif row["source_dataset"] == "DiverseVul" and row["label_value"] in (
            "present",
            "not_observed",
        ):
            row["disposition"] = "eligible"
            row["disposition_reason"] = "requires_prompt_and_target_sanitization"
        elif row["source_dataset"] == "BigVul":
            row["disposition"] = "quarantine"
            row["disposition_reason"] = "verified_before_after_pair_required"
        else:
            row["disposition"] = "quarantine"
            row["disposition_reason"] = "outside_phase_f_source_profile"
        catalog.append(row)
    return catalog


def build_source_profile(
    records: Sequence[Mapping[str, Any]],
    catalog: Sequence[Mapping[str, Any]],
    *,
    seed: int = PHASE_F_BUILD_SEED,
    train_per_class: int = 5000,
    validation_per_class: int = 500,
    test_per_class: int = 250,
) -> dict[str, Any]:
    """Select, sanitize, and split the fixed balanced Phase F source profile."""
    if len(records) != len(catalog):
        raise PhaseFDatasetError("records and catalog must have equal length")
    if min(train_per_class, validation_per_class, test_per_class) < 1:
        raise PhaseFDatasetError("all per-class quotas must be positive")

    candidates: dict[str, list[tuple[Mapping[str, Any], Mapping[str, Any]]]] = {
        "present": [],
        "not_observed": [],
    }
    for record, row in zip(records, catalog, strict=True):
        label = str(row["label_value"])
        if (
            row["disposition"] == "eligible"
            and label in candidates
            and row["source_dataset"] == "DiverseVul"
        ):
            candidates[label].append((record, row))

    total_per_class = train_per_class + validation_per_class + test_per_class
    for label, items in candidates.items():
        if len(items) < total_per_class:
            raise PhaseFDatasetError(
                f"not enough {label} records: "
                f"required={total_per_class}, available={len(items)}"
            )

    selected_by_split: dict[str, list[tuple[Mapping[str, Any], Mapping[str, Any]]]] = {
        "train": [],
        "validation": [],
        "test": [],
    }
    for label, items in candidates.items():
        ordered = sorted(items, key=lambda item: str(item[1]["group_id"]))
        random.Random(_derived_seed(seed, label)).shuffle(ordered)
        test_end = test_per_class
        validation_end = test_end + validation_per_class
        train_end = validation_end + train_per_class
        selected_by_split["test"].extend(ordered[:test_end])
        selected_by_split["validation"].extend(ordered[test_end:validation_end])
        selected_by_split["train"].extend(ordered[validation_end:train_end])

    outputs: dict[str, Any] = {
        "train": [],
        "validation": [],
        "challenge": [],
        "gold": [],
        "manifest": [],
    }
    for split_name, items in selected_by_split.items():
        random.Random(_derived_seed(seed, split_name)).shuffle(items)
        for source_record, row in items:
            materialized = materialize_source_record(
                source_record,
                row,
                split=split_name,
                seed=seed,
            )
            outputs["manifest"].append(_manifest_row(row, materialized, split_name))
            if split_name == "test":
                outputs["challenge"].append(_challenge_record(materialized))
                outputs["gold"].append(
                    {
                        "schema_version": "aegislm.blind-code-gold.v1",
                        "record_id": materialized["id"],
                        "is_vulnerable": row["label_value"] == "present",
                        "code_sha256": row["content_sha256"],
                        "label_scope": "target vulnerability in benchmark",
                    }
                )
            else:
                outputs[split_name].append(materialized)

    _assert_group_isolation(outputs["manifest"])
    outputs["summary"] = _profile_summary(outputs, seed)
    return outputs


def materialize_source_record(
    record: Mapping[str, Any],
    catalog_row: Mapping[str, Any],
    *,
    split: str,
    seed: int,
) -> dict[str, Any]:
    """Create a model-ready v1 record with no provenance or label in the prompt."""
    if split not in {"train", "validation", "test"}:
        raise PhaseFDatasetError(f"unsupported split: {split}")
    code = extract_source_code(record)
    if not code:
        raise PhaseFDatasetError(f"{record.get('id')}: source code missing")
    label = str(catalog_row["label_value"])
    if label not in {"present", "not_observed"}:
        raise PhaseFDatasetError(f"{record.get('id')}: unsupported label {label}")

    content_hash = str(catalog_row["content_sha256"])
    variant_id = _derived_seed(seed, content_hash) % len(PROMPT_VARIANTS)
    signals = _observable_signals(record)
    materialized = {
        "id": f"phase-f-source-{content_hash}",
        "source": deepcopy(record["source"]),
        "input": {
            "task": PROMPT_VARIANTS[variant_id],
            "context": f"Source-code excerpt:\n{code}",
            "signals": signals,
        },
        "expected_output": _source_target(label, signals, variant_id),
        "metadata": {
            "split": split,
            "safety_level": "redacted",
            "contains_executable_payload": False,
            "notes": [
                PHASE_F_SOURCE_PROFILE,
                "Negative labels are scoped to the target benchmark vulnerability.",
                f"prompt_variant={variant_id}",
            ],
        },
    }
    return materialized


def extract_source_code(record: Mapping[str, Any]) -> str:
    """Extract only the code excerpt from a canonical source record."""
    input_section = record.get("input")
    if not isinstance(input_section, Mapping):
        return ""
    context = input_section.get("context")
    if not isinstance(context, str):
        return ""
    for marker in _CODE_MARKERS:
        if marker in context:
            return context.split(marker, 1)[1].strip()
    return ""


def assert_no_model_visible_leakage(record: Mapping[str, Any]) -> None:
    """Reject materialized records that expose gold/provenance in model input."""
    input_section = record.get("input")
    if not isinstance(input_section, Mapping):
        raise PhaseFDatasetError("record.input must be an object")
    text = json.dumps(input_section, ensure_ascii=False).lower()
    forbidden = (
        "diversevul",
        "bigvul",
        "dataset label",
        '"target"',
        '"label"',
        '"split"',
        "expected_output",
    )
    hits = [item for item in forbidden if item in text]
    if hits:
        raise PhaseFDatasetError(
            f"{record.get('id')}: model-visible leakage detected: {hits}"
        )


def _catalog_row(
    record: Mapping[str, Any],
    source_revisions: Mapping[str, str],
) -> dict[str, Any]:
    source = record.get("source")
    input_section = record.get("input")
    metadata = record.get("metadata")
    source = source if isinstance(source, Mapping) else {}
    input_section = input_section if isinstance(input_section, Mapping) else {}
    metadata = metadata if isinstance(metadata, Mapping) else {}
    signals = input_section.get("signals")
    signals = signals if isinstance(signals, Mapping) else {}
    code = extract_source_code(record)
    content_hash = _sha256_text(code)
    source_name = str(source.get("name") or "unknown")
    dataset = _dataset_name(source_name, signals)
    label_value = _label_value(signals)
    leakage_flags = _leakage_flags(input_section)
    group_seed = "|".join(
        str(signals.get(key) or "")
        for key in ("repository", "project", "commit_id", "function_id")
    )
    near_hash = _sha256_text(_normalize_code(code))
    group_id = _sha256_text(group_seed) if group_seed.strip("|") else near_hash
    expected_output = record.get("expected_output")
    template_hash = _sha256_text(
        json.dumps(expected_output, sort_keys=True, ensure_ascii=False)
    )
    return {
        "schema_version": CATALOG_SCHEMA_VERSION,
        "record_id": str(record.get("id") or ""),
        "source_dataset": dataset,
        "source_revision": source_revisions.get(source_name),
        "license_status": str(source.get("license_or_terms") or "unverified"),
        "source_uri": str(source.get("url") or ""),
        "source_sha256": _sha256_text(
            json.dumps(source, sort_keys=True, ensure_ascii=False)
        ),
        "content_sha256": content_hash,
        "near_duplicate_sha256": near_hash,
        "group_id": group_id,
        "repository": str(signals.get("repository") or signals.get("project") or ""),
        "function_id": str(signals.get("function_id") or ""),
        "patch_group_id": str(
            signals.get("patch_group_id") or signals.get("commit_id") or ""
        ),
        "language": _guess_language(code),
        "cwe": str(signals.get("cwe") or signals.get("cwe_id") or ""),
        "label_task": "target_vulnerability_presence",
        "label_value": label_value,
        "label_confidence": "dataset_label" if label_value != "unknown" else "unknown",
        "target_template_sha256": template_hash,
        "estimated_tokens": max(1, len(code) // 4) if code else 0,
        "prompt_leakage_flags": leakage_flags,
        "has_source_code": bool(code),
        "contains_executable_payload": bool(
            metadata.get("contains_executable_payload")
        ),
        "representation_type": "source",
        "executable_status": "non_executable_representation",
        "original_split": str(metadata.get("split") or ""),
    }


def _manifest_row(
    catalog_row: Mapping[str, Any],
    record: Mapping[str, Any],
    split: str,
) -> dict[str, Any]:
    assert_no_model_visible_leakage(record)
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "profile": PHASE_F_SOURCE_PROFILE,
        "record_id": record["id"],
        "source_record_id": catalog_row["record_id"],
        "content_sha256": catalog_row["content_sha256"],
        "group_id": catalog_row["group_id"],
        "source_dataset": catalog_row["source_dataset"],
        "label_task": catalog_row["label_task"],
        "label_value": catalog_row["label_value"],
        "label_confidence": catalog_row["label_confidence"],
        "split": split,
        "representation_type": "source",
        "disposition": "eligible",
        "disposition_reason": "selected_by_phase_f_source_profile",
    }


def _challenge_record(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": record["id"],
        "challenge_schema": "aegislm.blind-code-challenge.v1",
        "source": {
            "type": "public_security_dataset",
            "name": "AegisLM blind code challenge",
            "url": None,
            "license_or_terms": None,
            "retrieved_at": None,
        },
        "input": deepcopy(record["input"]),
        "metadata": {
            "split": "test",
            "safety_level": "redacted",
            "contains_executable_payload": False,
            "notes": ["Gold and provenance are stored separately."],
        },
    }


def _source_target(
    label: str,
    signals: Mapping[str, Any],
    variant_id: int,
) -> dict[str, Any]:
    names = signals.get("observable_static_signals")
    signal_names = [str(item) for item in names] if isinstance(names, list) else []
    positive = label == "present"
    if positive and signal_names:
        behaviors = [
            {
                "behavior": name.replace("_", " "),
                "evidence": f"The supplied excerpt contains the observable static signal: {name}.",
                "confidence": "medium",
            }
            for name in signal_names[:3]
        ]
    elif positive:
        behaviors = [
            {
                "behavior": "Potential target vulnerability",
                "evidence": (
                    "The supplied source excerpt is the only available evidence; "
                    "the exact vulnerable operation requires deterministic validation."
                ),
                "confidence": "low",
            }
        ]
    else:
        behaviors = []

    positive_summaries = (
        "The supplied function is assessed as containing the scoped target vulnerability.",
        "Code-level review indicates the scoped target vulnerability is present.",
        "The supplied excerpt should be treated as positive for the target vulnerability task.",
        "The scoped vulnerability assessment is positive for this source excerpt.",
    )
    negative_summaries = (
        "The scoped target vulnerability is not observed in the supplied excerpt.",
        "No code evidence for the target vulnerability is identified in the supplied function.",
        "The supplied excerpt is negative for the scoped benchmark vulnerability.",
        "The target vulnerability is not observed within the provided code boundary.",
    )
    return {
        "summary": (positive_summaries if positive else negative_summaries)[variant_id],
        "behavior_explanation": (
            "The assessment is restricted to operations visible in the supplied "
            "function and must be verified with deterministic analysis."
        ),
        "risk_level": "high" if positive else "low",
        "malware_like_behaviors": behaviors,
        "attack_mapping": [],
        "recommendations": [
            "Confirm the scoped finding with deterministic static analysis and human review."
        ],
        "limitations": [
            "The assessment is scoped to the target vulnerability and supplied function only.",
            "Absence of the target finding does not establish that the full program is safe.",
        ],
    }


def _observable_signals(record: Mapping[str, Any]) -> dict[str, Any]:
    input_section = record.get("input")
    if not isinstance(input_section, Mapping):
        return {}
    raw = input_section.get("signals")
    if not isinstance(raw, Mapping):
        return {}
    visible: dict[str, Any] = {}
    signal_names = raw.get("suspicious_signal_names")
    if isinstance(signal_names, list):
        visible["observable_static_signals"] = [
            str(item) for item in signal_names if isinstance(item, str)
        ]
    return visible


def _leakage_flags(input_section: Mapping[str, Any]) -> list[str]:
    text = json.dumps(input_section, ensure_ascii=False, sort_keys=True)
    flags = [
        name for name, pattern in _LEAKAGE_PATTERNS.items() if pattern.search(text)
    ]
    signals = input_section.get("signals")
    if isinstance(signals, Mapping):
        for key in signals:
            if str(key).lower() in _GOLD_SIGNAL_KEYS:
                flags.append(f"signal_key:{key}")
    return sorted(set(flags))


def _dataset_name(source_name: str, signals: Mapping[str, Any]) -> str:
    explicit = signals.get("dataset")
    if isinstance(explicit, str):
        if explicit.lower() == "diversevul":
            return "DiverseVul"
        if explicit.lower() == "bigvul":
            return "BigVul"
        return explicit
    lowered = source_name.lower()
    if "diversevul" in lowered:
        return "DiverseVul"
    if "bigvul" in lowered:
        return "BigVul"
    return source_name


def _label_value(signals: Mapping[str, Any]) -> str:
    target = signals.get("target")
    if target in (1, True):
        return "present"
    if target in (0, False):
        return "not_observed"
    return "unknown"


def _profile_summary(outputs: Mapping[str, Any], seed: int) -> dict[str, Any]:
    manifest = outputs["manifest"]
    split_counts = Counter(str(row["split"]) for row in manifest)
    label_counts = Counter(f"{row['split']}:{row['label_value']}" for row in manifest)
    return {
        "profile": PHASE_F_SOURCE_PROFILE,
        "seed": seed,
        "catalog_schema_version": CATALOG_SCHEMA_VERSION,
        "manifest_schema_version": MANIFEST_SCHEMA_VERSION,
        "split_counts": dict(sorted(split_counts.items())),
        "label_counts": dict(sorted(label_counts.items())),
        "train_records": len(outputs["train"]),
        "validation_records": len(outputs["validation"]),
        "challenge_records": len(outputs["challenge"]),
        "gold_records": len(outputs["gold"]),
    }


def _assert_group_isolation(manifest: Sequence[Mapping[str, Any]]) -> None:
    splits_by_group: dict[str, set[str]] = {}
    for row in manifest:
        splits_by_group.setdefault(str(row["group_id"]), set()).add(str(row["split"]))
    leaked = sorted(
        group for group, splits in splits_by_group.items() if len(splits) > 1
    )
    if leaked:
        raise PhaseFDatasetError(
            f"cross-split group leakage detected for {len(leaked)} group(s)"
        )


def _normalize_code(code: str) -> str:
    without_comments = re.sub(r"/\*.*?\*/|//[^\n]*", "", code, flags=re.DOTALL)
    return re.sub(r"\s+", "", without_comments).lower()


def _guess_language(code: str) -> str:
    if "#include" in code or "::" in code:
        return "C++" if "::" in code else "C"
    if re.search(r"\b(?:int|void|char|size_t)\s+\w+\s*\(", code):
        return "C/C++"
    if re.search(r"\bdef\s+\w+\s*\(", code):
        return "Python"
    return "unknown"


def _derived_seed(seed: int, value: str) -> int:
    digest = hashlib.sha256(f"{seed}:{value}".encode()).digest()
    return int.from_bytes(digest[:8], "big")


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
