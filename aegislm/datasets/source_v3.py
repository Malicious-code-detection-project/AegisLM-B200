"""Promote an approved F2 source artifact into the frozen F3 training dataset."""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from aegislm.datasets.phase_f import (
    PhaseFDatasetError,
    load_jsonl,
    read_parquet,
    write_jsonl,
)
from aegislm.datasets.source import (
    format_source_prompt,
    validate_source_output,
    validate_source_record,
)
from aegislm.datasets.source_audit import (
    SOURCE_ASSISTANT_TOKEN_LIMIT,
    count_source_assistant_tokens,
    count_source_training_tokens,
)
from aegislm.datasets.sard_juliet import summarize_juliet_manual_review
from aegislm.training.llamafactory import (
    build_dataset_info_entry,
    write_llamafactory_dataset,
)

SOURCE_V3_PROFILE = "phase-f-source-v3"
SOURCE_V3_SEED = 20260728
SOURCE_V3_CUTOFF_LEN = 2048
SOURCE_V3_TRAIN_NAME = "phase_f_source_v3_train"
SOURCE_V3_VALIDATION_NAME = "phase_f_source_v3_validation"


def promote_source_v3(
    source_dir: Path,
    output_dir: Path,
    *,
    tokenizer: Any,
    cutoff_len: int = SOURCE_V3_CUTOFF_LEN,
    profile: str = SOURCE_V3_PROFILE,
    train_dataset_name: str = SOURCE_V3_TRAIN_NAME,
    validation_dataset_name: str = SOURCE_V3_VALIDATION_NAME,
) -> dict[str, Any]:
    """Validate, convert, and atomically freeze one approved F2 artifact."""
    source_dir = source_dir.resolve()
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise PhaseFDatasetError(f"output directory already exists: {output_dir}")
    _verify_sha256s(source_dir)
    source_manifest = _load_object(source_dir / "dataset_manifest.json")
    _require_source_approval(source_manifest)
    manual_review_rows = load_jsonl(source_dir / "manual_review_100.jsonl")
    manual_review = summarize_juliet_manual_review(manual_review_rows)
    if (
        not manual_review["pass"]
        or source_manifest.get("manual_review") != manual_review
    ):
        raise PhaseFDatasetError(
            "manual-review decisions do not match the approved source manifest"
        )

    canonical_rows = load_jsonl(source_dir / "private" / "records.jsonl")
    train_rows = load_jsonl(source_dir / "train.jsonl")
    validation_rows = load_jsonl(source_dir / "validation.jsonl")
    challenge_rows = load_jsonl(source_dir / "challenge.jsonl")
    gold_rows = load_jsonl(source_dir / "gold.jsonl")
    manifest_rows = read_parquet(source_dir / "eligible_manifest.parquet")

    audit = _audit_source_v3(
        canonical_rows=canonical_rows,
        train_rows=train_rows,
        validation_rows=validation_rows,
        challenge_rows=challenge_rows,
        gold_rows=gold_rows,
        manifest_rows=manifest_rows,
        source_manifest=source_manifest,
        tokenizer=tokenizer,
        cutoff_len=cutoff_len,
        profile=profile,
    )
    if not audit["overall_pass"]:
        failed = [name for name, passed in audit["quality_gates"].items() if not passed]
        raise PhaseFDatasetError("F3 quality gates failed: " + ", ".join(failed))

    train_export = [_to_llamafactory_record(row) for row in train_rows]
    validation_export = [_to_llamafactory_record(row) for row in validation_rows]
    parent = output_dir.parent
    parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}-", dir=parent))
    try:
        shutil.copyfile(
            source_dir / "eligible_manifest.parquet",
            temporary / "eligible_manifest.parquet",
        )
        write_jsonl(train_rows, temporary / "train.jsonl")
        write_jsonl(validation_rows, temporary / "validation.jsonl")
        write_jsonl(challenge_rows, temporary / "challenge.jsonl")
        write_jsonl(gold_rows, temporary / "gold.jsonl")
        write_jsonl(canonical_rows, temporary / "private" / "records.jsonl")
        shutil.copyfile(
            source_dir / "manual_review_100.jsonl",
            temporary / "private" / "manual_review_100.jsonl",
        )
        write_llamafactory_dataset(
            train_export,
            temporary / "llamafactory" / "train.jsonl",
        )
        write_llamafactory_dataset(
            validation_export,
            temporary / "llamafactory" / "validation.jsonl",
        )
        dataset_info = {}
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
        _write_json(
            temporary / "target_quality_and_token_audit.json",
            audit,
        )
        frozen_files = _file_hashes(temporary)
        manifest = {
            "schema_version": "aegislm.phase-f-source-dataset-manifest.v3",
            "profile": profile,
            "status": "approved_for_training",
            "approved_for_training": True,
            "seed": int(source_manifest["seed"]),
            "cutoff_len": cutoff_len,
            "output_contract": source_manifest["output_contract"],
            "source_artifact": {
                "profile": source_manifest["profile"],
                "dataset_manifest_sha256": _sha256_file(
                    source_dir / "dataset_manifest.json"
                ),
                "sha256s_sha256": _sha256_file(source_dir / "SHA256SUMS"),
                "approved_for_source_v3_integration": True,
                "manual_review": source_manifest["manual_review"],
            },
            "counts": audit["counts"],
            "metrics": audit["metrics"],
            "quality_gates": audit["quality_gates"],
            "llamafactory": {
                "dataset_info": "dataset_info.json",
                "dataset_dir": ".",
                "train_dataset": train_dataset_name,
                "validation_dataset": validation_dataset_name,
                "format": "alpaca",
            },
            "challenge_gold_policy": {
                "challenge_file": "challenge.jsonl",
                "gold_file": "gold.jsonl",
                "gold_must_not_be_passed_to_inference": True,
            },
            "frozen_files": frozen_files,
        }
        _write_json(temporary / "dataset_manifest.json", manifest)
        _write_hashes(temporary)
        temporary.replace(output_dir)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return manifest


def _audit_source_v3(
    *,
    canonical_rows: Sequence[Mapping[str, Any]],
    train_rows: Sequence[Mapping[str, Any]],
    validation_rows: Sequence[Mapping[str, Any]],
    challenge_rows: Sequence[Mapping[str, Any]],
    gold_rows: Sequence[Mapping[str, Any]],
    manifest_rows: Sequence[Mapping[str, Any]],
    source_manifest: Mapping[str, Any],
    tokenizer: Any,
    cutoff_len: int,
    profile: str = SOURCE_V3_PROFILE,
) -> dict[str, Any]:
    canonical_by_id = _unique_by_id(canonical_rows, "canonical")
    manifest_by_id = _unique_by_id(
        manifest_rows,
        "eligible manifest",
        id_key="record_id",
    )
    train_by_id = _unique_by_id(train_rows, "train")
    validation_by_id = _unique_by_id(validation_rows, "validation")
    challenge_by_id = _unique_by_id(challenge_rows, "challenge")
    gold_by_id = _unique_by_id(gold_rows, "gold")

    split_ids = {
        "train": set(train_by_id),
        "validation": set(validation_by_id),
        "test": set(challenge_by_id),
    }
    expected_ids = set().union(*split_ids.values())
    overlap_count = sum(
        len(split_ids[left] & split_ids[right])
        for left, right in (
            ("train", "validation"),
            ("train", "test"),
            ("validation", "test"),
        )
    )
    id_set_match = set(canonical_by_id) == set(manifest_by_id) == expected_ids and set(
        challenge_by_id
    ) == set(gold_by_id)

    group_splits: dict[str, set[str]] = {}
    code_splits: dict[str, set[str]] = {}
    for row in manifest_rows:
        split = str(row.get("split"))
        group_splits.setdefault(str(row.get("group_id")), set()).add(split)
        code_splits.setdefault(str(row.get("code_sha256")), set()).add(split)
    group_overlap_count = sum(len(splits) > 1 for splits in group_splits.values())
    content_overlap_count = sum(len(splits) > 1 for splits in code_splits.values())

    errors: list[str] = []
    token_counts: dict[str, list[int]] = {
        "train": [],
        "validation": [],
        "test": [],
    }
    assistant_token_counts: dict[str, list[int]] = {
        "train": [],
        "validation": [],
        "test": [],
    }
    label_counts: Counter[tuple[str, str]] = Counter()
    all_materialized: dict[str, Mapping[str, Any]] = {
        **train_by_id,
        **validation_by_id,
    }
    for row in challenge_rows:
        record_id = str(row["id"])
        gold = gold_by_id.get(record_id)
        if gold is None:
            continue
        all_materialized[record_id] = {
            "id": record_id,
            "messages": [
                *list(row.get("messages", [])),
                {
                    "role": "assistant",
                    "content": json.dumps(
                        gold.get("expected_output"),
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                },
            ],
            "code_sha256": canonical_by_id.get(record_id, {})
            .get("code", {})
            .get("sha256"),
        }

    for record_id in sorted(expected_ids):
        canonical = canonical_by_id.get(record_id)
        manifest_row = manifest_by_id.get(record_id)
        materialized = all_materialized.get(record_id)
        if canonical is None or manifest_row is None or materialized is None:
            errors.append(
                f"{record_id}: missing canonical, manifest, or materialized row"
            )
            continue
        split = str(manifest_row.get("split"))
        if record_id not in split_ids.get(split, set()):
            errors.append(f"{record_id}: split does not match eligible manifest")
        record_errors = validate_source_record(canonical)
        if record_errors:
            errors.extend(f"{record_id}: {error}" for error in record_errors)
            continue
        messages = materialized.get("messages")
        if not isinstance(messages, list) or len(messages) != 3:
            errors.append(f"{record_id}: three chat messages are required")
            continue
        prompt = format_source_prompt(canonical)
        if messages[:2] != prompt:
            errors.append(f"{record_id}: canonical to prompt round-trip mismatch")
        try:
            target = json.loads(str(messages[2].get("content")))
        except (json.JSONDecodeError, AttributeError):
            errors.append(f"{record_id}: assistant target is not valid JSON")
            continue
        output_errors = validate_source_output(
            target,
            source_code=str(canonical["code"]["text"]),
        )
        errors.extend(f"{record_id}: {error}" for error in output_errors)
        label = str(canonical["metadata"]["label"])
        if target.get("assessment") != label:
            errors.append(
                f"{record_id}: target assessment does not match private label"
            )
        label_counts[(split, label)] += 1
        token_count = count_source_training_tokens(tokenizer, prompt, target)
        assistant_token_count = count_source_assistant_tokens(tokenizer, target)
        token_counts[split].append(token_count)
        assistant_token_counts[split].append(assistant_token_count)
        if token_count > cutoff_len:
            errors.append(
                f"{record_id}: {token_count} tokens exceeds cutoff {cutoff_len}"
            )
        if materialized.get("code_sha256") != canonical["code"]["sha256"]:
            errors.append(f"{record_id}: code SHA-256 round-trip mismatch")

    challenge_contract_pass = all(
        set(row) == {"id", "messages"}
        and isinstance(row.get("messages"), list)
        and len(row["messages"]) == 2
        and all(message.get("role") != "assistant" for message in row["messages"])
        for row in challenge_rows
    )
    gold_contract_pass = all(set(row) == {"id", "expected_output"} for row in gold_rows)
    counts = {
        "train": len(train_rows),
        "validation": len(validation_rows),
        "challenge": len(challenge_rows),
        "gold": len(gold_rows),
        "labels": {
            f"{split}:{label}": count
            for (split, label), count in sorted(label_counts.items())
        },
    }
    required_pairs = source_manifest.get("required_pairs", {})
    quota_pass = all(
        label_counts[(split, label)] == int(required_pairs.get(split, -1))
        for split in ("train", "validation", "test")
        for label in ("present", "not_observed")
    )
    maximum_tokens = max(
        (
            count
            for counts_for_split in token_counts.values()
            for count in counts_for_split
        ),
        default=0,
    )
    maximum_assistant_tokens = max(
        (
            count
            for counts_for_split in assistant_token_counts.values()
            for count in counts_for_split
        ),
        default=0,
    )
    source_gates = source_manifest.get("quality_gates", {})
    quality_gates = {
        "f2_automated_gate": bool(source_manifest.get("automated_pass"))
        and all(bool(value) for value in source_gates.values()),
        "f2_manual_gate": bool(source_manifest.get("manual_review", {}).get("pass")),
        "record_sets_match": id_set_match,
        "record_ids_do_not_overlap": overlap_count == 0,
        "group_split_overlap": group_overlap_count == 0,
        "content_split_overlap": content_overlap_count == 0,
        "challenge_contract": challenge_contract_pass,
        "gold_contract": gold_contract_pass,
        "challenge_gold_id_match": set(challenge_by_id) == set(gold_by_id),
        "quota_and_class_balance": quota_pass,
        "canonical_materialized_round_trip": not errors,
        "tokenizer_cutoff": maximum_tokens <= cutoff_len,
        "assistant_token_budget": (
            maximum_assistant_tokens <= SOURCE_ASSISTANT_TOKEN_LIMIT
        ),
    }
    return {
        "schema_version": "aegislm.phase-f-source-v3-audit.v1",
        "profile": profile,
        "overall_pass": all(quality_gates.values()),
        "cutoff_len": cutoff_len,
        "tokenizer_name_or_path": str(
            getattr(tokenizer, "name_or_path", type(tokenizer).__name__)
        ),
        "counts": counts,
        "metrics": {
            "maximum_tokens": maximum_tokens,
            "split_maximum_tokens": {
                split: max(values, default=0) for split, values in token_counts.items()
            },
            "maximum_assistant_tokens": maximum_assistant_tokens,
            "assistant_token_limit": SOURCE_ASSISTANT_TOKEN_LIMIT,
            "split_maximum_assistant_tokens": {
                split: max(values, default=0)
                for split, values in assistant_token_counts.items()
            },
            "record_id_overlap_count": overlap_count,
            "group_split_overlap_count": group_overlap_count,
            "content_split_overlap_count": content_overlap_count,
            "round_trip_error_count": len(errors),
        },
        "quality_gates": quality_gates,
        "errors": errors,
    }


def _to_llamafactory_record(row: Mapping[str, Any]) -> dict[str, str]:
    messages = row.get("messages")
    if not isinstance(messages, list) or len(messages) != 3:
        raise PhaseFDatasetError("LLaMA-Factory export requires three chat messages")
    roles = tuple(message.get("role") for message in messages)
    if roles != ("system", "user", "assistant"):
        raise PhaseFDatasetError(f"unexpected message roles: {roles}")
    return {
        "system": str(messages[0]["content"]),
        "instruction": str(messages[1]["content"]),
        "input": "",
        "output": str(messages[2]["content"]),
    }


def _require_source_approval(manifest: Mapping[str, Any]) -> None:
    if manifest.get("status") != "ready_for_source_v3_integration":
        raise PhaseFDatasetError(
            "source artifact is not ready for source-v3 integration"
        )
    if manifest.get("approved_for_source_v3_integration") is not True:
        raise PhaseFDatasetError("source artifact integration approval is missing")
    if manifest.get("approved_for_training") is not False:
        raise PhaseFDatasetError("F2 source artifact must not already approve training")
    if manifest.get("seed") != SOURCE_V3_SEED:
        raise PhaseFDatasetError(f"source seed must be {SOURCE_V3_SEED}")


def _unique_by_id(
    rows: Sequence[Mapping[str, Any]],
    name: str,
    *,
    id_key: str = "id",
) -> dict[str, Mapping[str, Any]]:
    indexed: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        record_id = str(row.get(id_key) or "")
        if not record_id or record_id in indexed:
            raise PhaseFDatasetError(f"{name} has a missing or duplicate {id_key}")
        indexed[record_id] = row
    return indexed


def _verify_sha256s(root: Path) -> None:
    sums_path = root / "SHA256SUMS"
    if not sums_path.is_file():
        raise PhaseFDatasetError(f"missing source hash inventory: {sums_path}")
    for line_number, line in enumerate(
        sums_path.read_text(encoding="utf-8").splitlines(),
        1,
    ):
        if not line.strip():
            continue
        try:
            expected, relative = line.split("  ", 1)
        except ValueError as exc:
            raise PhaseFDatasetError(
                f"{sums_path}:{line_number}: invalid SHA256SUMS row"
            ) from exc
        path = root / relative
        if not path.is_file():
            raise PhaseFDatasetError(
                f"source hash inventory file is missing: {relative}"
            )
        actual = _sha256_file(path)
        if actual != expected:
            raise PhaseFDatasetError(
                f"source artifact hash mismatch: {relative}: "
                f"expected={expected}, actual={actual}"
            )


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise PhaseFDatasetError(f"{path} must contain a JSON object")
    return value


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


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
    lines = [f"{digest}  {relative}" for relative, digest in _file_hashes(root).items()]
    manifest_path = root / "dataset_manifest.json"
    lines.append(
        f"{_sha256_file(manifest_path)}  {manifest_path.relative_to(root).as_posix()}"
    )
    (root / "SHA256SUMS").write_text(
        "\n".join(sorted(lines, key=lambda line: line.split("  ", 1)[1])) + "\n",
        encoding="utf-8",
    )
