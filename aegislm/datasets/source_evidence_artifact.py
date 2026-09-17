"""Build the assessment-conditioned Phase F source evidence artifact."""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

from aegislm.datasets.phase_f import PhaseFDatasetError, load_jsonl, write_jsonl
from aegislm.datasets.source_audit import count_source_training_tokens
from aegislm.datasets.source_evidence_lines import (
    format_evidence_lines_payload,
    project_compact_to_evidence_lines,
    validate_evidence_lines_output,
)

SOURCE_EVIDENCE_PROFILE = "phase-f-source-evidence-lines-v1"
SOURCE_EVIDENCE_TRAIN_NAME = "phase_f_source_evidence_lines_v1_train"
SOURCE_EVIDENCE_VALIDATION_NAME = "phase_f_source_evidence_lines_v1_validation"
SOURCE_EVIDENCE_CUTOFF_LEN = 2048


def to_evidence_training_record(row: Mapping[str, Any]) -> dict[str, Any]:
    """Convert one approved compact row to assessment-conditioned evidence."""
    messages = _messages(row, expected_count=3)
    payload = _prompt_payload(str(messages[1]["content"]))
    compact = _json_object(messages[2]["content"], "compact target")
    assessment = _binary_assessment(compact, str(row["id"]))
    target = project_compact_to_evidence_lines(
        compact,
        source_code=str(payload["source_code"]),
    )
    prompt = format_evidence_lines_payload(
        target_cwe=str(cast(Mapping[str, Any], payload["scope"])["target_cwe"]),
        source_code=str(payload["source_code"]),
        assessment=assessment,
    )
    return {
        "id": str(row["id"]),
        "messages": [
            *prompt,
            {
                "role": "assistant",
                "content": json.dumps(
                    target,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            },
        ],
    }


def build_source_evidence_artifact(
    source_dir: Path,
    output_dir: Path,
    *,
    tokenizer: Any,
    profile: str = SOURCE_EVIDENCE_PROFILE,
    cutoff_len: int = SOURCE_EVIDENCE_CUTOFF_LEN,
    expected_train_count: int = 10000,
    expected_validation_count: int = 1000,
    expected_development_count: int = 100,
) -> dict[str, Any]:
    """Build and atomically freeze evidence train/validation/dev artifacts."""
    from aegislm.training.llamafactory import build_dataset_info_entry

    source_dir = source_dir.resolve()
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise PhaseFDatasetError(f"output directory already exists: {output_dir}")
    _verify_sha256s(source_dir)
    source_manifest = _load_object(source_dir / "dataset_manifest.json")
    if source_manifest.get("approved_for_training") is not True:
        raise PhaseFDatasetError("compact source artifact is not approved")

    train = [
        to_evidence_training_record(row)
        for row in load_jsonl(source_dir / "canonical" / "train.jsonl")
    ]
    validation = [
        to_evidence_training_record(row)
        for row in load_jsonl(source_dir / "canonical" / "validation.jsonl")
    ]
    compact_challenge = load_jsonl(source_dir / "development" / "challenge.jsonl")
    compact_gold = _index(
        load_jsonl(source_dir / "development" / "gold.jsonl"),
        "compact development gold",
    )
    challenge: list[dict[str, Any]] = []
    gold: list[dict[str, Any]] = []
    for row in compact_challenge:
        record_id = str(row["id"])
        messages = _messages(row, expected_count=2)
        payload = _prompt_payload(str(messages[1]["content"]))
        gold_row = compact_gold.get(record_id)
        if gold_row is None or not isinstance(gold_row.get("expected_output"), Mapping):
            raise PhaseFDatasetError(f"{record_id}: compact gold missing")
        compact = cast(Mapping[str, Any], gold_row["expected_output"])
        assessment = _binary_assessment(compact, record_id)
        prompt = format_evidence_lines_payload(
            target_cwe=str(cast(Mapping[str, Any], payload["scope"])["target_cwe"]),
            source_code=str(payload["source_code"]),
            assessment=assessment,
        )
        target = project_compact_to_evidence_lines(
            compact,
            source_code=str(payload["source_code"]),
        )
        challenge.append({"id": record_id, "messages": prompt})
        gold.append({"id": record_id, "expected_output": target})
    private_records = load_jsonl(source_dir / "development" / "private-records.jsonl")
    _validate_sets(
        train,
        validation,
        challenge,
        gold,
        private_records,
        expected_counts=(
            expected_train_count,
            expected_validation_count,
            expected_development_count,
        ),
    )
    token_counts = [
        count_source_training_tokens(
            tokenizer,
            row["messages"][:2],
            _json_object(row["messages"][2]["content"], "evidence target"),
        )
        for row in [*train, *validation]
    ]
    train_tokens = token_counts[: len(train)]
    validation_tokens = token_counts[len(train) :]
    excluded_train = [
        str(row["id"]) for row, count in zip(train, train_tokens) if count > cutoff_len
    ]
    excluded_validation = [
        str(row["id"])
        for row, count in zip(validation, validation_tokens)
        if count > cutoff_len
    ]
    train = [row for row, count in zip(train, train_tokens) if count <= cutoff_len]
    validation = [
        row for row, count in zip(validation, validation_tokens) if count <= cutoff_len
    ]
    approved_tokens = [count for count in token_counts if count <= cutoff_len]
    maximum_tokens = max(approved_tokens, default=0)

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{output_dir.name}-", dir=output_dir.parent)
    )
    try:
        write_jsonl(train, temporary / "canonical" / "train.jsonl")
        write_jsonl(validation, temporary / "canonical" / "validation.jsonl")
        write_jsonl(
            [_to_llamafactory(row) for row in train],
            temporary / "llamafactory" / "train.jsonl",
        )
        write_jsonl(
            [_to_llamafactory(row) for row in validation],
            temporary / "llamafactory" / "validation.jsonl",
        )
        write_jsonl(challenge, temporary / "development" / "challenge.jsonl")
        write_jsonl(gold, temporary / "development" / "gold.jsonl")
        write_jsonl(
            private_records,
            temporary / "development" / "private-records.jsonl",
        )
        dataset_info: dict[str, Any] = {}
        dataset_info.update(
            build_dataset_info_entry(
                dataset_name=SOURCE_EVIDENCE_TRAIN_NAME,
                file_name="llamafactory/train.jsonl",
            )
        )
        dataset_info.update(
            build_dataset_info_entry(
                dataset_name=SOURCE_EVIDENCE_VALIDATION_NAME,
                file_name="llamafactory/validation.jsonl",
            )
        )
        _write_json(temporary / "dataset_info.json", dataset_info)
        labels = Counter(
            _evidence_payload(str(_messages(row, expected_count=3)[1]["content"]))[
                "assessment"
            ]
            for row in [*train, *validation]
        )
        manifest = {
            "schema_version": "aegislm.phase-f-source-evidence-manifest.v1",
            "profile": profile,
            "status": "approved_for_evidence_canary",
            "approved_for_training": True,
            "canary_only": True,
            "cutoff_len": cutoff_len,
            "maximum_tokens": maximum_tokens,
            "counts": {
                "train": len(train),
                "validation": len(validation),
                "development_challenge": len(challenge),
                "development_gold": len(gold),
                "conditioned_assessments": dict(sorted(labels.items())),
            },
            "token_quarantine": {
                "train_count": len(excluded_train),
                "validation_count": len(excluded_validation),
                "train_ids_sha256": _ids_sha256(excluded_train),
                "validation_ids_sha256": _ids_sha256(excluded_validation),
                "replacement_records_added": 0,
            },
            "contract": {
                "schema_version": "aegislm.source-evidence-lines.v1",
                "assessment_is_input_condition": True,
                "assessment_is_not_generated": True,
                "maximum_ranges": 8,
                "deterministic_line_resolver": True,
            },
            "source_artifact": {
                "profile": source_manifest.get("profile"),
                "dataset_manifest_sha256": _sha256_file(
                    source_dir / "dataset_manifest.json"
                ),
                "sha256s_sha256": _sha256_file(source_dir / "SHA256SUMS"),
            },
            "development_policy": {
                "gold_assessment_conditioned": True,
                "assistant_removed_from_challenge": True,
                "gold_separated": True,
                "private_records_separated": True,
                "blind_challenge_used": False,
            },
            "llamafactory": {
                "train_dataset": SOURCE_EVIDENCE_TRAIN_NAME,
                "validation_dataset": SOURCE_EVIDENCE_VALIDATION_NAME,
            },
        }
        _write_json(temporary / "dataset_manifest.json", manifest)
        _write_hashes(temporary)
        temporary.replace(output_dir)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return manifest


def _binary_assessment(
    compact: Mapping[str, Any],
    record_id: str,
) -> Any:
    assessment = str(compact.get("assessment") or "")
    if assessment not in {"present", "not_observed"}:
        raise PhaseFDatasetError(
            f"{record_id}: evidence artifact requires a binary assessment"
        )
    return cast(Any, assessment)


def _messages(
    row: Mapping[str, Any],
    *,
    expected_count: int,
) -> list[Mapping[str, Any]]:
    messages = row.get("messages")
    if not isinstance(messages, list) or len(messages) != expected_count:
        raise PhaseFDatasetError(f"{row.get('id')}: expected {expected_count} messages")
    roles = [
        item.get("role") if isinstance(item, Mapping) else None for item in messages
    ]
    if roles != ["system", "user", "assistant"][:expected_count]:
        raise PhaseFDatasetError(f"{row.get('id')}: invalid message roles")
    return cast(list[Mapping[str, Any]], messages)


def _prompt_payload(content: str) -> dict[str, Any]:
    start = content.find("{")
    if start < 0:
        raise PhaseFDatasetError("source prompt does not contain JSON")
    try:
        payload, _ = json.JSONDecoder().raw_decode(content[start:])
    except json.JSONDecodeError as exc:
        raise PhaseFDatasetError(f"source prompt JSON is invalid: {exc.msg}") from exc
    if (
        not isinstance(payload, dict)
        or not isinstance(payload.get("source_code"), str)
        or not isinstance(payload.get("scope"), dict)
    ):
        raise PhaseFDatasetError("source prompt payload is incomplete")
    return payload


def _evidence_payload(content: str) -> dict[str, Any]:
    start = content.find("{")
    if start < 0:
        raise PhaseFDatasetError("evidence prompt does not contain JSON")
    try:
        payload, _ = json.JSONDecoder().raw_decode(content[start:])
    except json.JSONDecodeError as exc:
        raise PhaseFDatasetError(f"evidence prompt JSON is invalid: {exc.msg}") from exc
    if (
        not isinstance(payload, dict)
        or not isinstance(payload.get("numbered_source_code"), str)
        or payload.get("assessment") not in {"present", "not_observed"}
        or not isinstance(payload.get("scope"), dict)
    ):
        raise PhaseFDatasetError("evidence prompt payload is incomplete")
    return payload


def _json_object(value: Any, name: str) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise PhaseFDatasetError(f"{name} is invalid JSON: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise PhaseFDatasetError(f"{name} must be a JSON object")
    return value


def _to_llamafactory(row: Mapping[str, Any]) -> dict[str, str]:
    messages = _messages(row, expected_count=3)
    return {
        "system": str(messages[0]["content"]),
        "instruction": str(messages[1]["content"]),
        "input": "",
        "output": str(messages[2]["content"]),
    }


def _index(
    rows: Sequence[Mapping[str, Any]],
    name: str,
) -> dict[str, Mapping[str, Any]]:
    indexed = {str(row["id"]): row for row in rows}
    if len(indexed) != len(rows):
        raise PhaseFDatasetError(f"{name} contains duplicate ids")
    return indexed


def _validate_sets(
    train: Sequence[Mapping[str, Any]],
    validation: Sequence[Mapping[str, Any]],
    challenge: Sequence[Mapping[str, Any]],
    gold: Sequence[Mapping[str, Any]],
    private_records: Sequence[Mapping[str, Any]],
    *,
    expected_counts: tuple[int, int, int],
) -> None:
    actual = (len(train), len(validation), len(challenge))
    if actual != expected_counts or len(gold) != expected_counts[2]:
        raise PhaseFDatasetError(
            f"evidence dataset count mismatch: {actual}, gold={len(gold)}"
        )
    sets = [
        {str(row["id"]) for row in rows}
        for rows in (train, validation, challenge, gold, private_records)
    ]
    if any(
        len(ids) != len(rows)
        for ids, rows in zip(
            sets,
            (train, validation, challenge, gold, private_records),
        )
    ):
        raise PhaseFDatasetError("evidence artifact contains duplicate ids")
    if sets[0] & sets[1] or sets[0] & sets[2]:
        raise PhaseFDatasetError("evidence train ids overlap validation/development")
    if sets[2] != sets[3] or sets[2] != sets[4]:
        raise PhaseFDatasetError("evidence development ids do not match")
    for row in [*train, *validation]:
        messages = _messages(row, expected_count=3)
        payload = _evidence_payload(str(messages[1]["content"]))
        ranges = _json_object(messages[2]["content"], "evidence target")
        numbered = str(payload.get("numbered_source_code") or "")
        errors = validate_evidence_lines_output(
            ranges,
            line_count=len(numbered.splitlines()),
        )
        if errors:
            raise PhaseFDatasetError(f"{row['id']}: {'; '.join(errors)}")
    for row in challenge:
        messages = _messages(row, expected_count=2)
        visible = "\n".join(str(item["content"]) for item in messages)
        if any(
            key in visible
            for key in ('"label"', '"split"', '"source_dataset"', '"expected_output"')
        ):
            raise PhaseFDatasetError(f"{row['id']}: private metadata in prompt")


def _verify_sha256s(root: Path) -> None:
    sums = root / "SHA256SUMS"
    if not sums.is_file():
        raise PhaseFDatasetError(f"missing SHA256SUMS: {root}")
    for line in sums.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, relative = line.split("  ", 1)
        artifact = root / relative
        if not artifact.is_file() or _sha256_file(artifact) != expected:
            raise PhaseFDatasetError(f"source artifact hash mismatch: {relative}")


def _load_object(path: Path) -> dict[str, Any]:
    return _json_object(path.read_text(encoding="utf-8"), path.name)


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _write_hashes(root: Path) -> None:
    files = sorted(
        path for path in root.rglob("*") if path.is_file() and path.name != "SHA256SUMS"
    )
    (root / "SHA256SUMS").write_text(
        "".join(
            f"{_sha256_file(path)}  {path.relative_to(root).as_posix()}\n"
            for path in files
        ),
        encoding="utf-8",
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _ids_sha256(record_ids: Sequence[str]) -> str:
    return hashlib.sha256(
        "".join(f"{record_id}\n" for record_id in sorted(record_ids)).encode()
    ).hexdigest()
