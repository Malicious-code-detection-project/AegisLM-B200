"""Phase F catalog, sampling, and safe source materialization helpers."""

from __future__ import annotations

import hashlib
import json
import math
import random
import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from copy import deepcopy
from pathlib import Path
from typing import Any

import pyarrow as pa  # type: ignore[import-untyped]
import pyarrow.parquet as pq  # type: ignore[import-untyped]

PHASE_F_SOURCE_PROFILE = "phase-f-source-v2-r2"
PHASE_F_BUILD_SEED = 20260728
CATALOG_SCHEMA_VERSION = "aegislm.raw-catalog.v2"
MANIFEST_SCHEMA_VERSION = "aegislm.eligible-manifest.v2"
MAX_PROJECT_FRACTION_PER_CLASS = 0.10
CWE_TEMPERATURE_EXPONENT = 0.25
PROJECT_TEMPERATURE_EXPONENT = 0.15

_WEAKNESS_FAMILY_BY_CWE = {
    "memory_safety": {
        119,
        120,
        121,
        122,
        124,
        125,
        126,
        127,
        129,
        131,
        134,
        415,
        416,
        476,
        787,
        788,
        823,
        824,
        825,
    },
    "injection": {74, 77, 78, 79, 89, 90, 91, 93, 94, 95, 96, 113, 564, 611, 917},
    "access_control": {22, 23, 35, 36, 73, 269, 276, 284, 285, 287, 306, 862, 863},
    "resource_lifetime": {400, 401, 404, 459, 664, 665, 770, 772, 775, 779, 789},
    "concurrency": {362, 364, 366, 367, 368, 369, 662, 663, 667, 833},
    "numeric": {128, 190, 191, 192, 193, 194, 195, 196, 197, 198, 681, 682, 839},
    "crypto": {
        295,
        310,
        311,
        312,
        319,
        320,
        321,
        322,
        323,
        326,
        327,
        328,
        329,
        330,
        331,
        338,
        347,
    },
    "information_exposure": {200, 201, 203, 209, 212, 215, 359, 497, 532, 538},
    "error_handling": {
        252,
        253,
        273,
        280,
        390,
        391,
        392,
        393,
        394,
        395,
        396,
        397,
        754,
        755,
    },
}

PROMPT_VARIANTS = (
    "Assess whether {scope} is present in the supplied source-code excerpt.",
    "Review the supplied function for {scope} and report only code-visible evidence.",
    "Determine whether the supplied code exhibits {scope} without relying on provenance.",
    "Perform an evidence-grounded defensive review of the excerpt scoped to {scope}.",
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
_SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"(?P<key>\b[A-Za-z0-9_]*(?:password|api_key|client_secret)[A-Za-z0-9_]*\b)"
    r"\s*=\s*"
    r"(?P<value>[^\s,;)}\]]+)",
    flags=re.IGNORECASE,
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
    catalog = [_catalog_row(record, revisions) for record in records]
    first_exact: dict[str, str] = {}
    first_near: dict[str, str] = {}
    labels_by_exact: dict[str, set[str]] = {}
    labels_by_near: dict[str, set[str]] = {}

    for row in catalog:
        labels_by_exact.setdefault(str(row["content_sha256"]), set()).add(
            str(row["label_value"])
        )
        labels_by_near.setdefault(str(row["near_duplicate_sha256"]), set()).add(
            str(row["label_value"])
        )

    for row in catalog:
        exact_hash = row["content_sha256"]
        near_hash = row["near_duplicate_sha256"]
        row["exact_duplicate_of"] = first_exact.get(exact_hash)
        row["near_duplicate_of"] = first_near.get(near_hash)
        first_exact.setdefault(exact_hash, str(row["record_id"]))
        first_near.setdefault(near_hash, str(row["record_id"]))

        if len(labels_by_exact[exact_hash]) > 1:
            row["disposition"] = "quarantine"
            row["disposition_reason"] = "conflicting_exact_duplicate_labels"
        elif len(labels_by_near[near_hash]) > 1:
            row["disposition"] = "quarantine"
            row["disposition_reason"] = "conflicting_near_duplicate_labels"
        elif row["contains_executable_payload"]:
            row["disposition"] = "reject"
            row["disposition_reason"] = "executable_payload_forbidden"
        elif row["exact_duplicate_of"] is not None:
            row["disposition"] = "reject"
            row["disposition_reason"] = "exact_duplicate"
        elif row["near_duplicate_of"] is not None:
            row["disposition"] = "reject"
            row["disposition_reason"] = "near_duplicate"
        elif not row["has_source_code"]:
            row["disposition"] = "reject"
            row["disposition_reason"] = "source_code_missing"
        elif not row["cwe"]:
            row["disposition"] = "quarantine"
            row["disposition_reason"] = "scoped_cwe_missing"
        elif row["source_dataset"] == "DiverseVul" and row["label_value"] in (
            "present",
            "not_observed",
        ):
            row["disposition"] = "eligible"
            row["disposition_reason"] = "requires_prompt_and_target_sanitization"
        elif (
            row["source_dataset"] in {"BigVul", "PrimeVul"}
            and row["pair_verified"]
            and row["pair_type"] in {"vulnerable_before", "fixed_after"}
            and row["label_value"] in {"present", "not_observed"}
        ):
            row["disposition"] = "eligible"
            row["disposition_reason"] = "verified_before_after_pair"
        elif row["source_dataset"] in {"BigVul", "PrimeVul"}:
            row["disposition"] = "quarantine"
            row["disposition_reason"] = "verified_before_after_pair_required"
        else:
            row["disposition"] = "quarantine"
            row["disposition_reason"] = "outside_phase_f_source_profile"
    return catalog


def build_source_profile(
    records: Sequence[Mapping[str, Any]],
    catalog: Sequence[Mapping[str, Any]],
    *,
    seed: int = PHASE_F_BUILD_SEED,
    train_per_class: int = 5000,
    validation_per_class: int = 500,
    test_per_class: int = 250,
    core_datasets: Sequence[str] = ("DiverseVul",),
    cross_dataset_names: Sequence[str] = ("BigVul", "PrimeVul"),
    cross_dataset_records: int = 200,
) -> dict[str, Any]:
    """Build group-first pools, fixed materializations, and retained reserves."""
    if len(records) != len(catalog):
        raise PhaseFDatasetError("records and catalog must have equal length")
    if min(train_per_class, validation_per_class, test_per_class) < 1:
        raise PhaseFDatasetError("all per-class quotas must be positive")
    if cross_dataset_records < 2 or cross_dataset_records % 2:
        raise PhaseFDatasetError("cross_dataset_records must be a positive even number")

    core_dataset_set = set(core_datasets)
    cross_dataset_set = set(cross_dataset_names)
    overlap = core_dataset_set & cross_dataset_set
    if overlap:
        raise PhaseFDatasetError(
            f"datasets cannot be both core and cross holdout: {sorted(overlap)}"
        )

    eligible_items: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    for record, row in zip(records, catalog, strict=True):
        label = str(row["label_value"])
        if row["disposition"] == "eligible" and label in {
            "present",
            "not_observed",
        }:
            eligible_items.append((record, row))

    pool_by_content = {
        str(row["content_sha256"]): _group_split(str(row["group_id"]), seed)
        for _, row in eligible_items
    }
    main_candidates = [
        item
        for item in eligible_items
        if str(item[1]["source_dataset"]) in core_dataset_set
    ]

    split_quotas = {
        "train": train_per_class,
        "validation": validation_per_class,
        "test": test_per_class,
    }
    selected_by_split: dict[str, list[tuple[Mapping[str, Any], Mapping[str, Any]]]] = {
        split: [] for split in split_quotas
    }
    for label in ("present", "not_observed"):
        label_items = [
            item for item in main_candidates if str(item[1]["label_value"]) == label
        ]
        for split, quota in split_quotas.items():
            split_items = [
                item
                for item in label_items
                if pool_by_content[str(item[1]["content_sha256"])] == split
            ]
            selected = _category_stratified_sample(
                split_items,
                quota=quota,
                seed=_derived_seed(seed, f"{label}:{split}"),
            )
            if len(selected) < quota:
                raise PhaseFDatasetError(
                    f"not enough {label} records in {split}: "
                    f"required={quota}, available={len(split_items)}"
                )
            selected_by_split[split].extend(selected)

    cross_selected: dict[str, list[tuple[Mapping[str, Any], Mapping[str, Any]]]] = {}
    for dataset in sorted(cross_dataset_set):
        dataset_items = [
            item for item in eligible_items if str(item[1]["source_dataset"]) == dataset
        ]
        selected = _select_cross_dataset_items(
            dataset_items,
            total_records=cross_dataset_records,
            seed=_derived_seed(seed, f"cross:{dataset}"),
        )
        if len(selected) < cross_dataset_records:
            raise PhaseFDatasetError(
                f"not enough balanced cross-dataset records for {dataset}: "
                f"required={cross_dataset_records}, available={len(dataset_items)}"
            )
        cross_selected[dataset] = selected

    outputs: dict[str, Any] = {
        "train": [],
        "validation": [],
        "challenge": [],
        "gold": [],
        "cross_dataset": {},
        "selected_manifest": [],
        "eligible_manifest": [],
        "reserve_manifest": [],
        "quarantine_manifest": [],
        "reject_manifest": [],
    }
    selection_by_content: dict[str, str] = {}
    for split_name, items in selected_by_split.items():
        random.Random(_derived_seed(seed, split_name)).shuffle(items)
        for source_record, row in items:
            materialization = "blind_test" if split_name == "test" else split_name
            selection_by_content[str(row["content_sha256"])] = materialization
            materialized = materialize_source_record(
                source_record,
                row,
                split=split_name,
                seed=seed,
            )
            outputs["selected_manifest"].append(
                _manifest_row(
                    row,
                    materialized,
                    pool=split_name,
                    materialization=materialization,
                )
            )
            if split_name == "test":
                outputs["challenge"].append(_challenge_record(materialized))
                outputs["gold"].append(_gold_record(materialized, row, source_record))
            else:
                outputs[split_name].append(materialized)

    for dataset, items in cross_selected.items():
        shuffled = list(items)
        random.Random(_derived_seed(seed, f"cross-order:{dataset}")).shuffle(shuffled)
        cross_output: dict[str, list[dict[str, Any]]] = {
            "challenge": [],
            "gold": [],
        }
        for source_record, row in shuffled:
            selection_by_content[str(row["content_sha256"])] = (
                f"cross_dataset_test:{dataset}"
            )
            materialized = materialize_source_record(
                source_record,
                row,
                split="test",
                seed=seed,
            )
            outputs["selected_manifest"].append(
                _manifest_row(
                    row,
                    materialized,
                    pool=pool_by_content[str(row["content_sha256"])],
                    materialization="cross_dataset_test",
                )
            )
            cross_output["challenge"].append(_challenge_record(materialized))
            cross_output["gold"].append(_gold_record(materialized, row, source_record))
        outputs["cross_dataset"][dataset] = cross_output

    for _, row in eligible_items:
        content_hash = str(row["content_sha256"])
        pool = pool_by_content[content_hash]
        materialization = selection_by_content.get(content_hash, "reserve")
        manifest_row = _manifest_row(
            row,
            None,
            pool=pool,
            materialization=materialization,
        )
        outputs["eligible_manifest"].append(manifest_row)
        if materialization == "reserve":
            outputs["reserve_manifest"].append(manifest_row)

    outputs["quarantine_manifest"] = [
        _catalog_disposition_row(row)
        for row in catalog
        if row["disposition"] == "quarantine"
    ]
    outputs["reject_manifest"] = [
        _catalog_disposition_row(row)
        for row in catalog
        if row["disposition"] == "reject"
    ]
    outputs["manifest"] = outputs["selected_manifest"]

    _assert_group_isolation(outputs["eligible_manifest"])
    outputs["summary"] = _profile_summary(outputs, catalog, seed)
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
    redacted_code, secret_redaction_count = _redact_sensitive_assignments(code)
    label = str(catalog_row["label_value"])
    if label not in {"present", "not_observed"}:
        raise PhaseFDatasetError(f"{record.get('id')}: unsupported label {label}")

    content_hash = str(catalog_row["content_sha256"])
    variant_id = _derived_seed(seed, content_hash) % len(PROMPT_VARIANTS)
    signals = _observable_signals(record)
    cwes = _scoped_cwes(record)
    scope = ", ".join(cwes)
    if not scope:
        raise PhaseFDatasetError(f"{record.get('id')}: scoped CWE missing")
    notes = [
        PHASE_F_SOURCE_PROFILE,
        "Negative labels are scoped to the target benchmark vulnerability.",
        f"prompt_variant={variant_id}",
    ]
    if secret_redaction_count:
        notes.append(f"secret_like_assignments_redacted={secret_redaction_count}")
    materialized = {
        "id": f"phase-f-source-{content_hash}",
        "source": deepcopy(record["source"]),
        "input": {
            "task": PROMPT_VARIANTS[variant_id].format(scope=scope),
            "context": f"Source-code excerpt:\n{redacted_code}",
            "signals": {**signals, "scoped_cwe": cwes},
        },
        "expected_output": _source_target(label, {**signals, "cwe": cwes}, variant_id),
        "metadata": {
            "split": split,
            "safety_level": "redacted",
            "contains_executable_payload": False,
            "notes": notes,
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

    signals = input_section.get("signals")
    signals = signals if isinstance(signals, Mapping) else {}
    control_text = json.dumps(
        {
            "task": input_section.get("task"),
            "signals": signals,
        },
        ensure_ascii=False,
    ).lower()
    forbidden = (
        "diversevul",
        "bigvul",
        "dataset label",
        '"target"',
        '"label"',
        '"split"',
        "expected_output",
    )
    hits = [item for item in forbidden if item in control_text]
    hits.extend(
        f"signal_key:{key}" for key in signals if str(key).lower() in _GOLD_SIGNAL_KEYS
    )
    if hits:
        raise PhaseFDatasetError(
            f"{record.get('id')}: model-visible leakage detected: {sorted(set(hits))}"
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
    provided_content_hash = signals.get("content_sha256")
    content_hash = (
        str(provided_content_hash)
        if isinstance(provided_content_hash, str) and len(provided_content_hash) == 64
        else _sha256_text(code)
    )
    source_name = str(source.get("name") or "unknown")
    dataset = _dataset_name(source_name, signals)
    label_value = _label_value(signals)
    leakage_flags = _leakage_flags(input_section)
    provided_near_hash = signals.get("near_duplicate_sha256")
    near_hash = (
        str(provided_near_hash)
        if isinstance(provided_near_hash, str) and len(provided_near_hash) == 64
        else _sha256_text(_normalize_code(code))
    )
    repository = str(signals.get("repository") or signals.get("project") or "")
    patch_group = str(signals.get("patch_group_id") or signals.get("commit_id") or "")
    function_id = str(signals.get("function_id") or "")
    if patch_group:
        group_seed = f"{dataset}|{repository}|patch:{patch_group}"
    elif function_id:
        group_seed = f"{dataset}|{repository}|function:{function_id}"
    else:
        group_seed = ""
    group_id = _sha256_text(group_seed) if group_seed else near_hash
    expected_output = record.get("expected_output")
    template_hash = _sha256_text(
        json.dumps(expected_output, sort_keys=True, ensure_ascii=False)
    )
    cwes = _cwe_values(signals)
    estimated_tokens = max(1, len(code) // 4) if code else 0
    pair_type = str(signals.get("pair_type") or "unpaired")
    evidence_level = str(
        signals.get("evidence_level") or ("cwe_scoped" if cwes else "label_only")
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
        "repository": repository,
        "function_id": function_id,
        "patch_group_id": patch_group,
        "source_language_audit": str(signals.get("source_language") or ""),
        "cwe": ",".join(cwes),
        "task_family": (
            "patch_analysis" if pair_type != "unpaired" else "source_vulnerability"
        ),
        "weakness_family": _weakness_family(cwes),
        "evidence_level": evidence_level,
        "representation": "source",
        "pair_type": pair_type,
        "label_task": "target_vulnerability_presence",
        "label_value": label_value,
        "label_confidence": str(
            signals.get("label_confidence")
            or ("dataset_label" if label_value != "unknown" else "unknown")
        ),
        "target_template_sha256": template_hash,
        "estimated_tokens": estimated_tokens,
        "length_bucket": _length_bucket(estimated_tokens),
        "pair_verified": bool(signals.get("pair_verified")),
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
    record: Mapping[str, Any] | None,
    *,
    pool: str,
    materialization: str,
) -> dict[str, Any]:
    if record is not None:
        assert_no_model_visible_leakage(record)
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "profile": PHASE_F_SOURCE_PROFILE,
        "record_id": (
            record["id"]
            if record is not None
            else f"phase-f-source-{catalog_row['content_sha256']}"
        ),
        "source_record_id": catalog_row["record_id"],
        "content_sha256": catalog_row["content_sha256"],
        "group_id": catalog_row["group_id"],
        "source_dataset": catalog_row["source_dataset"],
        "source_revision": catalog_row["source_revision"],
        "repository": catalog_row["repository"],
        "patch_group_id": catalog_row["patch_group_id"],
        "cwe": catalog_row["cwe"],
        "task_family": catalog_row["task_family"],
        "weakness_family": catalog_row["weakness_family"],
        "evidence_level": catalog_row["evidence_level"],
        "representation": catalog_row["representation"],
        "pair_type": catalog_row["pair_type"],
        "length_bucket": catalog_row["length_bucket"],
        "label_task": catalog_row["label_task"],
        "label_value": catalog_row["label_value"],
        "label_confidence": catalog_row["label_confidence"],
        "pool": pool,
        "split": pool,
        "materialization": materialization,
        "representation_type": "source",
        "disposition": "eligible",
        "disposition_reason": (
            "retained_in_reserve"
            if materialization == "reserve"
            else "selected_by_phase_f_source_profile"
        ),
    }


def _catalog_disposition_row(catalog_row: Mapping[str, Any]) -> dict[str, Any]:
    """Return a payload-free manifest row for quarantined or rejected input."""
    fields = (
        "schema_version",
        "record_id",
        "source_dataset",
        "source_revision",
        "content_sha256",
        "near_duplicate_sha256",
        "group_id",
        "repository",
        "function_id",
        "patch_group_id",
        "cwe",
        "task_family",
        "weakness_family",
        "evidence_level",
        "representation",
        "pair_type",
        "length_bucket",
        "label_task",
        "label_value",
        "label_confidence",
        "disposition",
        "disposition_reason",
    )
    return {field: catalog_row.get(field) for field in fields}


def _gold_record(
    materialized: Mapping[str, Any],
    catalog_row: Mapping[str, Any],
    source_record: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": "aegislm.blind-code-gold.v1",
        "record_id": materialized["id"],
        "is_vulnerable": catalog_row["label_value"] == "present",
        "code_sha256": catalog_row["content_sha256"],
        "scoped_cwe": _scoped_cwes(source_record),
        "label_scope": "target vulnerability in benchmark",
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
    cwes = _cwe_values(signals)
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
                "behavior": f"Potential {' / '.join(cwes)} weakness",
                "evidence": (
                    "The supplied function is positive for the scoped weakness task; "
                    "the exact operation still requires deterministic validation."
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


def _scoped_cwes(record: Mapping[str, Any]) -> list[str]:
    input_section = record.get("input")
    if not isinstance(input_section, Mapping):
        return []
    signals = input_section.get("signals")
    return _cwe_values(signals) if isinstance(signals, Mapping) else []


def _cwe_values(signals: Mapping[str, Any]) -> list[str]:
    raw = signals.get("cwe") or signals.get("cwe_id")
    values = raw if isinstance(raw, list) else [raw]
    result: list[str] = []
    for value in values:
        text = str(value or "").strip().upper()
        if text and text.startswith("CWE-") and text not in result:
            result.append(text)
    return result


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


def _profile_summary(
    outputs: Mapping[str, Any],
    catalog: Sequence[Mapping[str, Any]],
    seed: int,
) -> dict[str, Any]:
    selected_manifest = outputs["selected_manifest"]
    eligible_manifest = outputs["eligible_manifest"]
    materialization_counts = Counter(
        str(row["materialization"]) for row in selected_manifest
    )
    pool_counts = Counter(str(row["pool"]) for row in eligible_manifest)
    label_counts = Counter(
        f"{row['materialization']}:{row['label_value']}" for row in selected_manifest
    )
    catalog_datasets = Counter(str(row["source_dataset"]) for row in catalog)
    catalog_dispositions = Counter(str(row["disposition"]) for row in catalog)
    disposition_reasons = Counter(str(row["disposition_reason"]) for row in catalog)
    selected_repositories = Counter(str(row["repository"]) for row in selected_manifest)
    selected_cwes = Counter(
        cwe for row in selected_manifest for cwe in str(row["cwe"]).split(",") if cwe
    )
    category_counts = Counter(
        "|".join(
            (
                str(row["weakness_family"]),
                str(row["evidence_level"]),
                str(row["representation"]),
                str(row["pair_type"]),
                str(row["length_bucket"]),
                str(row["label_value"]),
                str(row["label_confidence"]),
            )
        )
        for row in selected_manifest
    )
    redaction_count = sum(
        int(note.split("=", 1)[1])
        for split in ("train", "validation")
        for record in outputs[split]
        for note in record["metadata"]["notes"]
        if str(note).startswith("secret_like_assignments_redacted=")
    )
    return {
        "profile": PHASE_F_SOURCE_PROFILE,
        "seed": seed,
        "catalog_schema_version": CATALOG_SCHEMA_VERSION,
        "manifest_schema_version": MANIFEST_SCHEMA_VERSION,
        "materialization_counts": dict(sorted(materialization_counts.items())),
        "eligible_pool_counts": dict(sorted(pool_counts.items())),
        "label_counts": dict(sorted(label_counts.items())),
        "catalog_records": len(catalog),
        "catalog_dataset_counts": dict(sorted(catalog_datasets.items())),
        "catalog_disposition_counts": dict(sorted(catalog_dispositions.items())),
        "catalog_disposition_reason_counts": dict(sorted(disposition_reasons.items())),
        "sampling": {
            "method": "group_first_category_stratified",
            "group_split_ratio": {"train": 0.8, "validation": 0.1, "test": 0.1},
            "category_axes": [
                "weakness_family",
                "evidence_level",
                "representation",
                "pair_type",
                "length_bucket",
                "label",
                "label_confidence",
            ],
            "language_used_for_sampling": False,
            "cwe_temperature_exponent": CWE_TEMPERATURE_EXPONENT,
            "repository_temperature_exponent": PROJECT_TEMPERATURE_EXPONENT,
            "max_repository_fraction_per_class": MAX_PROJECT_FRACTION_PER_CLASS,
        },
        "selected_unique_groups": len(
            {str(row["group_id"]) for row in selected_manifest}
        ),
        "selected_unique_repositories": len(selected_repositories),
        "selected_unique_cwes": len(selected_cwes),
        "selected_category_cell_count": len(category_counts),
        "selected_category_counts": dict(sorted(category_counts.items())),
        "selected_top_repositories": [
            [name, count] for name, count in selected_repositories.most_common(20)
        ],
        "selected_top_cwes": [
            [name, count] for name, count in selected_cwes.most_common(20)
        ],
        "secret_like_assignments_redacted": redaction_count,
        "train_records": len(outputs["train"]),
        "validation_records": len(outputs["validation"]),
        "challenge_records": len(outputs["challenge"]),
        "gold_records": len(outputs["gold"]),
        "cross_dataset_records": {
            dataset: len(values["challenge"])
            for dataset, values in sorted(outputs["cross_dataset"].items())
        },
        "eligible_records": len(outputs["eligible_manifest"]),
        "reserve_records": len(outputs["reserve_manifest"]),
        "quarantine_records": len(outputs["quarantine_manifest"]),
        "reject_records": len(outputs["reject_manifest"]),
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


def _group_split(group_id: str, seed: int) -> str:
    bucket = _derived_seed(seed, group_id) % 10_000
    if bucket < 8_000:
        return "train"
    if bucket < 9_000:
        return "validation"
    return "test"


def _tempered_stratified_sample(
    items: Sequence[tuple[Mapping[str, Any], Mapping[str, Any]]],
    *,
    quota: int,
    seed: int,
) -> list[tuple[Mapping[str, Any], Mapping[str, Any]]]:
    if len(items) < quota:
        return []

    cwe_counts = Counter(_primary_cwe(row) for _, row in items)
    project_counts = Counter(
        str(row.get("repository") or "unknown") for _, row in items
    )
    ranked: list[tuple[float, str, tuple[Mapping[str, Any], Mapping[str, Any]]]] = []
    for item in items:
        _, row = item
        cwe = _primary_cwe(row)
        project = str(row.get("repository") or "unknown")
        weight = cwe_counts[cwe] ** (-CWE_TEMPERATURE_EXPONENT) * project_counts[
            project
        ] ** (-PROJECT_TEMPERATURE_EXPONENT)
        content_hash = str(row["content_sha256"])
        uniform = (_derived_seed(seed, content_hash) + 1) / ((1 << 64) + 1)
        priority = -math.log(uniform) / weight
        ranked.append((priority, content_hash, item))
    ranked.sort(key=lambda entry: (entry[0], entry[1]))

    project_cap = max(1, math.ceil(quota * MAX_PROJECT_FRACTION_PER_CLASS))
    selected: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    selected_projects: Counter[str] = Counter()
    deferred: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    for _, _, item in ranked:
        project = str(item[1].get("repository") or "unknown")
        if selected_projects[project] >= project_cap:
            deferred.append(item)
            continue
        selected.append(item)
        selected_projects[project] += 1
        if len(selected) == quota:
            return selected

    for item in deferred:
        selected.append(item)
        if len(selected) == quota:
            return selected
    return selected


def _category_stratified_sample(
    items: Sequence[tuple[Mapping[str, Any], Mapping[str, Any]]],
    *,
    quota: int,
    seed: int,
) -> list[tuple[Mapping[str, Any], Mapping[str, Any]]]:
    """Sample round-robin across language-independent security category cells."""
    if len(items) < quota:
        return []

    cwe_counts = Counter(_primary_cwe(row) for _, row in items)
    project_counts = Counter(
        str(row.get("repository") or "unknown") for _, row in items
    )
    queues: dict[
        tuple[str, ...],
        list[tuple[float, str, tuple[Mapping[str, Any], Mapping[str, Any]]]],
    ] = {}
    for item in items:
        _, row = item
        cwe = _primary_cwe(row)
        project = str(row.get("repository") or "unknown")
        weight = cwe_counts[cwe] ** (-CWE_TEMPERATURE_EXPONENT) * project_counts[
            project
        ] ** (-PROJECT_TEMPERATURE_EXPONENT)
        content_hash = str(row["content_sha256"])
        uniform = (_derived_seed(seed, content_hash) + 1) / ((1 << 64) + 1)
        priority = -math.log(uniform) / weight
        queues.setdefault(_category_cell(row), []).append(
            (priority, content_hash, item)
        )
    for queue in queues.values():
        queue.sort(key=lambda entry: (entry[0], entry[1]))

    cell_order = sorted(
        queues,
        key=lambda cell: (
            _derived_seed(seed, "|".join(cell)),
            cell,
        ),
    )
    project_cap = max(1, math.ceil(quota * MAX_PROJECT_FRACTION_PER_CLASS))
    selected: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    selected_projects: Counter[str] = Counter()
    deferred: list[tuple[float, str, tuple[Mapping[str, Any], Mapping[str, Any]]]] = []

    while len(selected) < quota:
        progressed = False
        for cell in cell_order:
            queue = queues[cell]
            while queue:
                entry = queue.pop(0)
                project = str(entry[2][1].get("repository") or "unknown")
                if selected_projects[project] >= project_cap:
                    deferred.append(entry)
                    continue
                selected.append(entry[2])
                selected_projects[project] += 1
                progressed = True
                break
            if len(selected) == quota:
                return selected
        if not progressed:
            break

    remaining = deferred + [entry for queue in queues.values() for entry in queue]
    remaining.sort(key=lambda entry: (entry[0], entry[1]))
    selected.extend(entry[2] for entry in remaining[: quota - len(selected)])
    return selected


def _select_cross_dataset_items(
    items: Sequence[tuple[Mapping[str, Any], Mapping[str, Any]]],
    *,
    total_records: int,
    seed: int,
) -> list[tuple[Mapping[str, Any], Mapping[str, Any]]]:
    """Prefer complete present/fixed pairs for a balanced cross-dataset holdout."""
    groups: dict[str, dict[str, list[tuple[Mapping[str, Any], Mapping[str, Any]]]]] = {}
    for item in items:
        row = item[1]
        groups.setdefault(str(row["group_id"]), {}).setdefault(
            str(row["label_value"]), []
        ).append(item)

    paired_groups = [
        group_id
        for group_id, labels in groups.items()
        if labels.get("present") and labels.get("not_observed")
    ]
    paired_groups.sort(key=lambda group_id: (_derived_seed(seed, group_id), group_id))
    required_pairs = total_records // 2
    if len(paired_groups) >= required_pairs:
        selected: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
        for group_id in paired_groups[:required_pairs]:
            labels = groups[group_id]
            for label in ("present", "not_observed"):
                candidates = sorted(
                    labels[label],
                    key=lambda item: str(item[1]["content_sha256"]),
                )
                selected.append(candidates[0])
        return selected

    per_label = total_records // 2
    selected = []
    for label in ("present", "not_observed"):
        label_items = [item for item in items if str(item[1]["label_value"]) == label]
        chosen = _category_stratified_sample(
            label_items,
            quota=per_label,
            seed=_derived_seed(seed, label),
        )
        if len(chosen) < per_label:
            return []
        selected.extend(chosen)
    return selected


def _category_cell(row: Mapping[str, Any]) -> tuple[str, ...]:
    return (
        str(row.get("weakness_family") or "other"),
        str(row.get("evidence_level") or "unknown"),
        str(row.get("representation") or "source"),
        str(row.get("pair_type") or "unpaired"),
        str(row.get("length_bucket") or "unknown"),
        str(row.get("label_confidence") or "unknown"),
    )


def _primary_cwe(row: Mapping[str, Any]) -> str:
    return str(row.get("cwe") or "unknown").split(",", 1)[0]


def _weakness_family(cwes: Sequence[str]) -> str:
    for cwe in cwes:
        match = re.fullmatch(r"CWE-(\d+)", cwe)
        if not match:
            continue
        cwe_id = int(match.group(1))
        for family, members in _WEAKNESS_FAMILY_BY_CWE.items():
            if cwe_id in members:
                return family
    return "other"


def _length_bucket(estimated_tokens: int) -> str:
    if estimated_tokens <= 512:
        return "up_to_512"
    if estimated_tokens <= 1024:
        return "513_to_1024"
    if estimated_tokens <= 2048:
        return "1025_to_2048"
    return "over_2048"


def _normalize_code(code: str) -> str:
    without_comments = re.sub(r"/\*.*?\*/|//[^\n]*", "", code, flags=re.DOTALL)
    return re.sub(r"\s+", "", without_comments).lower()


def _redact_sensitive_assignments(value: str) -> tuple[str, int]:
    redaction_count = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal redaction_count
        redaction_count += 1
        return f"{match.group('key')} = [REDACTED_SECRET]"

    return _SECRET_ASSIGNMENT_PATTERN.sub(replace, value), redaction_count


def _derived_seed(seed: int, value: str) -> int:
    digest = hashlib.sha256(f"{seed}:{value}".encode()).digest()
    return int.from_bytes(digest[:8], "big")


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
