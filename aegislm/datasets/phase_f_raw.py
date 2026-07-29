"""Normalize immutable Phase F raw snapshots into audit-only canonical records."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

import pyarrow.csv as pacsv  # type: ignore[import-untyped]
import pyarrow.parquet as pq  # type: ignore[import-untyped]

DIVERSEVUL_REVISION = "3ed5dae8fdf3f6026f1e260f789656c4bb6d98e6"
BIGVUL_REVISION = "801dfa4f48205cb70976bea1e77d357178e68212"
CYBERSECURITY_QA_REVISION = "4b6f278056b35bb28ddd685d28e1a030196fed47"
PRIMEVUL_REVISION = "google-drive-folder-1cznxGme5o6A_9tT8T47JUh3MPEpRYiKK-v0.1"
PRIMEVUL_REPOSITORY_REVISION = "6f54687c84947b1d17486495440b37030d147289"
SARD_JULIET_CPP_REVISION = (
    "ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb"
)

SOURCE_REVISIONS = {
    "bstee615/diversevul": DIVERSEVUL_REVISION,
    "DynaOuchebara/BigVul": BIGVUL_REVISION,
    "DLVulDet/PrimeVul-v0.1": PRIMEVUL_REVISION,
}

MAX_SOURCE_EXCERPT_CHARS = 12_000

_BIGVUL_COLUMNS = [
    "Unnamed: 0",
    "CVE ID",
    "CWE ID",
    "commit_id",
    "file_name",
    "func_after",
    "func_before",
    "lang",
    "parentID",
    "patch",
    "project",
    "vul",
]


class PhaseFRawDataError(ValueError):
    """Raised when an immutable raw snapshot is missing or malformed."""


def load_diversevul_raw_records(raw_root: Path) -> list[dict[str, Any]]:
    """Load the pinned DiverseVul Parquet snapshot without changing raw files."""
    data_root = raw_root / "diversevul" / "data"
    paths = sorted(data_root.glob("*.parquet"))
    if not paths:
        raise PhaseFRawDataError(
            f"DiverseVul parquet files not found below {data_root}"
        )

    records: list[dict[str, Any]] = []
    for path in paths:
        original_split = path.name.split("-", 1)[0]
        parquet = pq.ParquetFile(path)
        for batch in parquet.iter_batches(batch_size=4096):
            for row in batch.to_pylist():
                records.append(
                    normalize_diversevul_row(
                        row,
                        index=len(records),
                        original_split=original_split,
                    )
                )
    return records


def iter_bigvul_raw_records(raw_root: Path) -> Iterator[dict[str, Any]]:
    """Stream BigVul before records and verified fixed-after pair records."""
    dataset_root = raw_root / "bigvul"
    paths = sorted(dataset_root.glob("*_set.csv"))
    if not paths:
        raise PhaseFRawDataError(f"BigVul CSV files not found below {dataset_root}")

    index = 0
    split_names = {
        "training": "train",
        "validation": "validation",
        "testing": "test",
    }
    for path in paths:
        original_split = split_names[path.stem.removesuffix("_set")]
        reader = pacsv.open_csv(
            path,
            read_options=pacsv.ReadOptions(
                block_size=64 * 1024 * 1024,
                use_threads=True,
            ),
            parse_options=pacsv.ParseOptions(newlines_in_values=True),
            convert_options=pacsv.ConvertOptions(
                include_columns=_BIGVUL_COLUMNS,
                strings_can_be_null=True,
            ),
        )
        for batch in reader:
            for row in batch.to_pylist():
                yield from normalize_bigvul_rows(
                    row, index=index, original_split=original_split
                )
                index += 1


def iter_primevul_paired_records(raw_root: Path) -> Iterator[dict[str, Any]]:
    """Stream pinned PrimeVul paired files as verified before/fixed records."""
    dataset_root = raw_root / "primevul" / "v0.1"
    paths = [
        dataset_root / "primevul_train_paired.jsonl",
        dataset_root / "primevul_valid_paired.jsonl",
        dataset_root / "primevul_test_paired.jsonl",
    ]
    missing = [path for path in paths if not path.is_file()]
    if missing:
        raise PhaseFRawDataError(
            f"PrimeVul paired files missing: {[str(path) for path in missing]}"
        )

    global_pair_index = 0
    for path in paths:
        original_split = path.name.removeprefix("primevul_").split("_", 1)[0]
        with path.open(encoding="utf-8") as stream:
            pair: list[dict[str, Any]] = []
            for line_number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise PhaseFRawDataError(
                        f"{path}:{line_number}: PrimeVul row must be an object"
                    )
                pair.append(value)
                if len(pair) == 2:
                    yield from normalize_primevul_pair(
                        pair,
                        pair_index=global_pair_index,
                        original_split=original_split,
                    )
                    global_pair_index += 1
                    pair = []
            if pair:
                raise PhaseFRawDataError(f"{path}: unpaired trailing PrimeVul row")


def normalize_diversevul_row(
    row: Mapping[str, Any],
    *,
    index: int,
    original_split: str,
) -> dict[str, Any]:
    """Normalize one DiverseVul row for cataloging and later materialization."""
    code = _text(row.get("func"))
    target = _binary_label(row.get("target"))
    cwes = _cwe_list(row.get("cwe"))
    project = _text(row.get("project"))
    commit_id = _text(row.get("commit_id"))
    content_hash = _sha256(code)
    near_hash = _sha256(_normalize_code(code))

    return _canonical_raw_record(
        record_id=f"raw-diversevul-{index:06d}-{content_hash[:12]}",
        source_name="bstee615/diversevul",
        source_url="https://huggingface.co/datasets/bstee615/diversevul",
        license_or_terms=(
            "Research provenance identified; dataset redistribution/license "
            "requires separate review."
        ),
        code=code,
        signals={
            "dataset": "DiverseVul",
            "target": target,
            "cwe": cwes,
            "project": project,
            "repository": project,
            "commit_id": commit_id,
            "patch_group_id": f"{project}:{commit_id}" if commit_id else "",
            "function_id": content_hash,
            "content_sha256": content_hash,
            "near_duplicate_sha256": near_hash,
            "label_confidence": (
                "dataset_positive" if target == 1 else "benchmark_negative"
            ),
        },
        original_split=original_split,
        notes=["Normalized from immutable DiverseVul raw Parquet."],
    )


def normalize_bigvul_row(
    row: Mapping[str, Any],
    *,
    index: int,
    original_split: str,
) -> dict[str, Any]:
    """Normalize the BigVul before side for backward-compatible callers."""
    return normalize_bigvul_rows(row, index=index, original_split=original_split)[0]


def normalize_bigvul_rows(
    row: Mapping[str, Any],
    *,
    index: int,
    original_split: str,
) -> list[dict[str, Any]]:
    """Normalize a BigVul row and emit a verified fixed-after record when possible."""
    before = _text(row.get("func_before"))
    after = _text(row.get("func_after"))
    target = _binary_label(row.get("vul"))
    project = _text(row.get("project"))
    commit_id = _text(row.get("commit_id"))
    file_name = _text(row.get("file_name"))
    cwes = _cwe_list(row.get("CWE ID"))
    content_hash = _sha256(before)
    near_hash = _sha256(_normalize_code(before))
    patch = _text(row.get("patch"))
    pair_verified = bool(
        target == 1 and before and after and before != after and patch and cwes
    )
    patch_group_id = f"{project}:{commit_id}" if commit_id else ""
    common_signals = {
        "dataset": "BigVul",
        "cwe": cwes,
        "cve": _text(row.get("CVE ID")),
        "project": project,
        "repository": project,
        "commit_id": commit_id,
        "patch_group_id": patch_group_id,
        "pair_verified": pair_verified,
        "has_patch": bool(patch),
        "source_language": _text(row.get("lang")),
    }
    source_name = "DynaOuchebara/BigVul"
    source_url = "https://huggingface.co/datasets/DynaOuchebara/BigVul"
    license_or_terms = (
        "Upstream dataset repository is MIT; repack provenance and "
        "underlying source-code licenses require review."
    )
    records = [
        _canonical_raw_record(
            record_id=f"raw-bigvul-{index:06d}-{content_hash[:12]}",
            source_name=source_name,
            source_url=source_url,
            license_or_terms=license_or_terms,
            code=before,
            signals={
                **common_signals,
                "target": target,
                "function_id": f"{file_name}:{content_hash}",
                "content_sha256": content_hash,
                "near_duplicate_sha256": near_hash,
                "paired_content_sha256": _sha256(after) if after else "",
                "pair_changed": bool(before and after and before != after),
                "pair_type": "vulnerable_before" if pair_verified else "unpaired",
                "evidence_level": (
                    "patch_localized" if pair_verified else "dataset_label"
                ),
                "label_confidence": (
                    "patch_localized_positive" if target == 1 else "benchmark_negative"
                ),
            },
            original_split=original_split,
            notes=["Normalized from immutable BigVul raw CSV before-patch function."],
        )
    ]
    if pair_verified:
        after_hash = _sha256(after)
        records.append(
            _canonical_raw_record(
                record_id=f"raw-bigvul-{index:06d}-fixed-{after_hash[:12]}",
                source_name=source_name,
                source_url=source_url,
                license_or_terms=license_or_terms,
                code=after,
                signals={
                    **common_signals,
                    "target": 0,
                    "function_id": f"{file_name}:{after_hash}",
                    "content_sha256": after_hash,
                    "near_duplicate_sha256": _sha256(_normalize_code(after)),
                    "paired_content_sha256": content_hash,
                    "pair_changed": True,
                    "pair_type": "fixed_after",
                    "evidence_level": "patch_localized",
                    "label_confidence": "verified_fixed_after",
                },
                original_split=original_split,
                notes=[
                    "Normalized from immutable BigVul raw CSV fixed-after function.",
                    "not_observed is scoped to the target CWE after the recorded patch.",
                ],
            )
        )
    return records


def normalize_primevul_pair(
    rows: Sequence[Mapping[str, Any]],
    *,
    pair_index: int,
    original_split: str,
) -> list[dict[str, Any]]:
    """Normalize one consecutive PrimeVul positive/fixed pair."""
    if len(rows) != 2:
        raise PhaseFRawDataError("PrimeVul pair must contain exactly two rows")
    by_label = {_binary_label(row.get("target")): row for row in rows}
    if set(by_label) != {0, 1}:
        raise PhaseFRawDataError(
            f"PrimeVul pair {pair_index} must contain labels 1 and 0"
        )
    before = by_label[1]
    after = by_label[0]
    project = _text(before.get("project"))
    commit_id = _text(before.get("commit_id"))
    cve = _text(before.get("cve"))
    provenance_match = not any(
        _text(after.get(key)) != value
        for key, value in (
            ("project", project),
            ("commit_id", commit_id),
            ("cve", cve),
        )
    )
    records: list[dict[str, Any]] = []
    for target, row, pair_type, confidence in (
        (1, before, "vulnerable_before", "primevul_paired_positive"),
        (0, after, "fixed_after", "primevul_paired_fixed_after"),
    ):
        row_project = _text(row.get("project"))
        row_commit_id = _text(row.get("commit_id"))
        row_cve = _text(row.get("cve"))
        cwes = _cwe_list(row.get("cwe"))
        if provenance_match:
            pair_group = f"{project}:{commit_id}:primevul-pair-{pair_index}"
        else:
            pair_group = (
                f"{row_project}:{row_commit_id}:"
                f"primevul-unverified-{pair_index}-{target}"
            )
        code = _text(row.get("func"))
        content_hash = _sha256(code)
        records.append(
            _canonical_raw_record(
                record_id=(
                    f"raw-primevul-{pair_index:06d}-{target}-{content_hash[:12]}"
                ),
                source_name="DLVulDet/PrimeVul-v0.1",
                source_url="https://github.com/DLVulDet/PrimeVul",
                license_or_terms=(
                    "Dataset repository is MIT; underlying project source "
                    "licenses remain attached to original projects."
                ),
                code=code,
                signals={
                    "dataset": "PrimeVul",
                    "target": target,
                    "cwe": cwes,
                    "cve": row_cve,
                    "project": row_project,
                    "repository": row_project,
                    "commit_id": row_commit_id,
                    "patch_group_id": pair_group,
                    "function_id": _text(row.get("func_hash")) or content_hash,
                    "content_sha256": content_hash,
                    "near_duplicate_sha256": _sha256(_normalize_code(code)),
                    "paired_content_sha256": (
                        _sha256(_text((after if target == 1 else before).get("func")))
                        if provenance_match
                        else ""
                    ),
                    "pair_changed": provenance_match
                    and _text(before.get("func")) != _text(after.get("func")),
                    "pair_verified": provenance_match,
                    "has_patch": provenance_match,
                    "pair_type": pair_type if provenance_match else "unpaired",
                    "evidence_level": (
                        "patch_localized" if provenance_match else "dataset_label"
                    ),
                    "label_confidence": (
                        confidence if provenance_match else "primevul_pair_mismatch"
                    ),
                },
                original_split=original_split,
                notes=[
                    "Normalized from pinned PrimeVul v0.1 paired JSONL.",
                    (
                        "not_observed is scoped to the paired target CWE after patch."
                        if provenance_match
                        else "Pair provenance mismatch; quarantined from materialization."
                    ),
                ],
            )
        )
    return records


def raw_dataset_inventory(raw_root: Path) -> dict[str, Any]:
    """Return pinned dataset-level provenance without reading model payloads."""
    return {
        "schema_version": "aegislm.raw-dataset-inventory.v1",
        "raw_root": str(raw_root),
        "datasets": [
            {
                "name": "bstee615/diversevul",
                "revision": DIVERSEVUL_REVISION,
                "local_directory": "diversevul",
                "phase_f_role": "source_core",
                "license_status": "review_required",
            },
            {
                "name": "DynaOuchebara/BigVul",
                "revision": BIGVUL_REVISION,
                "local_directory": "bigvul",
                "phase_f_role": "verified_pair_cross_dataset_holdout",
                "license_status": "upstream_mit_repack_review_required",
            },
            {
                "name": "DLVulDet/PrimeVul-v0.1",
                "revision": PRIMEVUL_REVISION,
                "repository_revision": PRIMEVUL_REPOSITORY_REVISION,
                "local_directory": "primevul/v0.1",
                "phase_f_role": "paired_cross_dataset_holdout",
                "license_status": "repository_mit_underlying_source_review_required",
            },
            {
                "name": "NIST SARD Juliet C/C++ 1.3",
                "revision": SARD_JULIET_CPP_REVISION,
                "local_directory": "sard-juliet-c-cpp-1.3",
                "phase_f_role": "raw_build_source_pending_function_extractor",
                "license_status": "cc0_public_domain",
            },
            {
                "name": "rezaduty/cybersecurity-qa-v2",
                "revision": CYBERSECURITY_QA_REVISION,
                "local_directory": "cybersecurity-qa-v2",
                "phase_f_role": "provenance_only_excluded_from_source_sft",
                "license_status": "apache-2.0_dataset_card",
            },
        ],
    }


def _canonical_raw_record(
    *,
    record_id: str,
    source_name: str,
    source_url: str,
    license_or_terms: str,
    code: str,
    signals: dict[str, Any],
    original_split: str,
    notes: list[str],
) -> dict[str, Any]:
    excerpt = code[:MAX_SOURCE_EXCERPT_CHARS]
    if len(code) > MAX_SOURCE_EXCERPT_CHARS:
        excerpt = excerpt.rstrip() + "\n[TRUNCATED]"
    return {
        "id": record_id,
        "source": {
            "type": "public_security_dataset",
            "name": source_name,
            "url": source_url,
            "license_or_terms": license_or_terms,
            "retrieved_at": "2026-07-29",
        },
        "input": {
            "task": "Audit-only canonical source record; not a model prompt.",
            "context": f"Source-code excerpt:\n{excerpt}",
            "signals": signals,
        },
        "expected_output": {},
        "metadata": {
            "split": original_split,
            "safety_level": "redacted",
            "contains_executable_payload": False,
            "notes": notes,
        },
    }


def _binary_label(value: Any) -> int:
    if value is True:
        return 1
    if value is False or value is None or value == "":
        return 0
    try:
        return 1 if int(value) == 1 else 0
    except (TypeError, ValueError) as exc:
        raise PhaseFRawDataError(f"unsupported binary label: {value!r}") from exc


def _cwe_list(value: Any) -> list[str]:
    values = value if isinstance(value, list) else [value]
    result: list[str] = []
    for item in values:
        text = _text(item).upper()
        if not text:
            continue
        if text.isdigit():
            text = f"CWE-{text}"
        if not text.startswith("CWE-"):
            continue
        if text not in result:
            result.append(text)
    return result


def _normalize_code(code: str) -> str:
    without_comments = re.sub(r"/\*.*?\*/|//[^\n]*", "", code, flags=re.DOTALL)
    return re.sub(r"\s+", "", without_comments).lower()


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


def _text(value: Any) -> str:
    if value is None:
        return ""
    return value.strip() if isinstance(value, str) else str(value).strip()
