"""Decision-only Phase F source dataset used to isolate semantic learning."""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from aegislm.datasets.phase_f import PhaseFDatasetError, load_jsonl, write_jsonl
from aegislm.datasets.source_audit import count_source_training_tokens
from aegislm.training.llamafactory import (
    build_dataset_info_entry,
    write_llamafactory_dataset,
)

SOURCE_DECISION_PROFILE = "phase-f-source-decision-v1"
SOURCE_DECISION_TRAIN_NAME = "phase_f_source_decision_v1_train"
SOURCE_DECISION_VALIDATION_NAME = "phase_f_source_decision_v1_validation"
SOURCE_DECISION_CUTOFF_LEN = 2048
SOURCE_DECISION_SYSTEM_PROMPT = """\
You are AegisLM, a defensive source-code vulnerability decision model.

Using only the requested CWE and supplied function, return exactly one compact
JSON object with one key:
{"assessment":"present"}
or
{"assessment":"not_observed"}
or
{"assessment":"uncertain"}

Choose present only when the scoped CWE condition is established by the supplied
function. Choose not_observed only when the scoped condition is not observed in
the supplied function. Choose uncertain when the supplied function is
insufficient for either decision. Do not add evidence, explanation, Markdown,
provenance, labels, record IDs, paths, or any other field."""

_ASSESSMENTS = frozenset({"present", "not_observed", "uncertain"})


def decision_target(assessment: str) -> dict[str, str]:
    """Build the minimal decision-only target."""
    if assessment not in _ASSESSMENTS:
        raise PhaseFDatasetError(f"invalid source decision assessment: {assessment}")
    return {"assessment": assessment}


def to_decision_training_record(row: Mapping[str, Any]) -> dict[str, Any]:
    """Convert one approved source training row to the diagnostic contract."""
    messages = _messages(row, expected_count=3)
    source_output = _json_object(messages[2]["content"], "assistant target")
    target = decision_target(str(source_output.get("assessment") or ""))
    return {
        "id": str(row["id"]),
        "messages": [
            {"role": "system", "content": SOURCE_DECISION_SYSTEM_PROMPT},
            {"role": "user", "content": str(messages[1]["content"])},
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


def to_decision_challenge_record(row: Mapping[str, Any]) -> dict[str, Any]:
    """Convert one blind source prompt without adding private gold."""
    messages = _messages(row, expected_count=2)
    return {
        "id": str(row["id"]),
        "messages": [
            {"role": "system", "content": SOURCE_DECISION_SYSTEM_PROMPT},
            {"role": "user", "content": str(messages[1]["content"])},
        ],
    }


def to_decision_gold_record(row: Mapping[str, Any]) -> dict[str, Any]:
    """Convert one private full-report gold row to a decision-only target."""
    expected = row.get("expected_output")
    if not isinstance(expected, Mapping):
        raise PhaseFDatasetError("source gold expected_output must be an object")
    return {
        "id": str(row["id"]),
        "expected_output": decision_target(str(expected.get("assessment") or "")),
    }


def build_decision_development_subset(
    rows: Sequence[Mapping[str, Any]],
    *,
    per_class: int,
    seed: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Strip answers and select a deterministic balanced development subset."""
    if per_class <= 0:
        raise PhaseFDatasetError("per_class must be positive")
    converted: list[tuple[dict[str, Any], dict[str, Any]]] = []
    seen_ids: set[str] = set()
    for row in rows:
        messages = _messages(row, expected_count=3)
        record_id = str(row["id"])
        if record_id in seen_ids:
            raise PhaseFDatasetError(
                f"decision development rows contain duplicate id: {record_id}"
            )
        seen_ids.add(record_id)
        target = _json_object(messages[2]["content"], "decision target")
        assessment = str(target.get("assessment") or "")
        if assessment not in {"present", "not_observed"}:
            raise PhaseFDatasetError(
                f"{record_id}: development gold must be a binary assessment"
            )
        converted.append(
            (
                {
                    "id": record_id,
                    "messages": [
                        {"role": "system", "content": str(messages[0]["content"])},
                        {"role": "user", "content": str(messages[1]["content"])},
                    ],
                },
                {
                    "id": record_id,
                    "expected_output": decision_target(assessment),
                },
            )
        )

    selected: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for assessment in ("present", "not_observed"):
        candidates = [
            pair
            for pair in converted
            if pair[1]["expected_output"]["assessment"] == assessment
        ]
        candidates.sort(
            key=lambda pair: hashlib.sha256(
                f"{seed}:decision-development:{pair[0]['id']}".encode()
            ).hexdigest()
        )
        if len(candidates) < per_class:
            raise PhaseFDatasetError(
                f"not enough {assessment} development rows: "
                f"{len(candidates)}<{per_class}"
            )
        selected.extend(candidates[:per_class])
    selected.sort(
        key=lambda pair: hashlib.sha256(
            f"{seed}:decision-development-order:{pair[0]['id']}".encode()
        ).hexdigest()
    )
    return (
        [challenge for challenge, _ in selected],
        [gold for _, gold in selected],
    )


def build_source_decision_artifact(
    source_dir: Path,
    output_dir: Path,
    *,
    tokenizer: Any,
    profile: str = SOURCE_DECISION_PROFILE,
    cutoff_len: int = SOURCE_DECISION_CUTOFF_LEN,
    train_dataset_name: str = SOURCE_DECISION_TRAIN_NAME,
    validation_dataset_name: str = SOURCE_DECISION_VALIDATION_NAME,
) -> dict[str, Any]:
    """Build and atomically freeze the classification-only canary dataset."""
    source_dir = source_dir.resolve()
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise PhaseFDatasetError(f"output directory already exists: {output_dir}")
    _verify_sha256s(source_dir)
    source_manifest = _json_object(
        (source_dir / "dataset_manifest.json").read_text(encoding="utf-8"),
        "source manifest",
    )
    if (
        source_manifest.get("status") != "approved_for_training"
        or source_manifest.get("approved_for_training") is not True
    ):
        raise PhaseFDatasetError("source dataset is not approved for training")

    train = [
        to_decision_training_record(row)
        for row in load_jsonl(source_dir / "train.jsonl")
    ]
    validation = [
        to_decision_training_record(row)
        for row in load_jsonl(source_dir / "validation.jsonl")
    ]
    challenge = [
        to_decision_challenge_record(row)
        for row in load_jsonl(source_dir / "challenge.jsonl")
    ]
    gold = [
        to_decision_gold_record(row) for row in load_jsonl(source_dir / "gold.jsonl")
    ]
    _validate_sets(train, validation, challenge, gold)

    token_counts = [
        count_source_training_tokens(
            tokenizer,
            row["messages"][:2],
            _json_object(row["messages"][2]["content"], "decision target"),
        )
        for row in [*train, *validation]
    ]
    maximum_tokens = max(token_counts, default=0)
    if maximum_tokens > cutoff_len:
        raise PhaseFDatasetError(
            f"decision dataset exceeds tokenizer cutoff: {maximum_tokens}>{cutoff_len}"
        )

    parent = output_dir.parent
    parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}-", dir=parent))
    try:
        write_jsonl(train, temporary / "train.jsonl")
        write_jsonl(validation, temporary / "validation.jsonl")
        write_jsonl(challenge, temporary / "challenge.jsonl")
        write_jsonl(gold, temporary / "gold.jsonl")
        write_llamafactory_dataset(
            [_to_llamafactory(row) for row in train],
            temporary / "llamafactory" / "train.jsonl",
        )
        write_llamafactory_dataset(
            [_to_llamafactory(row) for row in validation],
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
        label_counts = Counter(
            _json_object(row["messages"][2]["content"], "decision target")["assessment"]
            for row in [*train, *validation]
        )
        manifest = {
            "schema_version": "aegislm.phase-f-source-decision-manifest.v1",
            "profile": profile,
            "status": "approved_for_diagnostic_training",
            "approved_for_training": True,
            "diagnostic_only": True,
            "cutoff_len": cutoff_len,
            "maximum_tokens": maximum_tokens,
            "counts": {
                "train": len(train),
                "validation": len(validation),
                "challenge": len(challenge),
                "gold": len(gold),
                "labels": dict(sorted(label_counts.items())),
            },
            "source_artifact": {
                "profile": source_manifest.get("profile"),
                "dataset_manifest_sha256": _sha256_file(
                    source_dir / "dataset_manifest.json"
                ),
                "sha256s_sha256": _sha256_file(source_dir / "SHA256SUMS"),
            },
            "contract": {
                "system_prompt_sha256": hashlib.sha256(
                    SOURCE_DECISION_SYSTEM_PROMPT.encode()
                ).hexdigest(),
                "allowed_assessments": sorted(_ASSESSMENTS),
                "exact_keys": ["assessment"],
            },
            "llamafactory": {
                "train_dataset": train_dataset_name,
                "validation_dataset": validation_dataset_name,
            },
        }
        _write_json(temporary / "dataset_manifest.json", manifest)
        _write_hashes(temporary)
        temporary.replace(output_dir)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return manifest


def _messages(
    row: Mapping[str, Any], *, expected_count: int
) -> list[Mapping[str, Any]]:
    value = row.get("messages")
    if not isinstance(value, list) or len(value) != expected_count:
        raise PhaseFDatasetError(
            f"source row requires {expected_count} messages, got {type(value).__name__}"
        )
    roles = tuple(
        message.get("role") if isinstance(message, Mapping) else None
        for message in value
    )
    expected_roles = ("system", "user", "assistant")[:expected_count]
    if roles != expected_roles or not all(isinstance(item, Mapping) for item in value):
        raise PhaseFDatasetError(f"unexpected source message roles: {roles}")
    return value


def _json_object(value: Any, name: str) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise PhaseFDatasetError(f"{name} is invalid JSON: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise PhaseFDatasetError(f"{name} must be a JSON object")
    return value


def _validate_sets(
    train: Sequence[Mapping[str, Any]],
    validation: Sequence[Mapping[str, Any]],
    challenge: Sequence[Mapping[str, Any]],
    gold: Sequence[Mapping[str, Any]],
) -> None:
    sets = [
        {str(row["id"]) for row in rows}
        for rows in (train, validation, challenge, gold)
    ]
    if any(
        len(ids) != len(rows)
        for ids, rows in zip(sets, (train, validation, challenge, gold))
    ):
        raise PhaseFDatasetError("decision dataset contains duplicate ids")
    if sets[0] & sets[1] or sets[0] & sets[2] or sets[1] & sets[2]:
        raise PhaseFDatasetError("decision dataset split ids overlap")
    if sets[2] != sets[3]:
        raise PhaseFDatasetError("decision challenge and gold ids differ")
    expected_counts = (10000, 1000, 500, 500)
    actual_counts = tuple(len(rows) for rows in (train, validation, challenge, gold))
    if actual_counts != expected_counts:
        raise PhaseFDatasetError(
            f"decision dataset count mismatch: {actual_counts}!={expected_counts}"
        )


def _to_llamafactory(row: Mapping[str, Any]) -> dict[str, str]:
    messages = _messages(row, expected_count=3)
    return {
        "system": str(messages[0]["content"]),
        "instruction": str(messages[1]["content"]),
        "input": "",
        "output": str(messages[2]["content"]),
    }


def _verify_sha256s(root: Path) -> None:
    path = root / "SHA256SUMS"
    if not path.is_file():
        raise PhaseFDatasetError(f"missing source hash inventory: {path}")
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, relative = line.split("  ", 1)
        artifact = root / relative
        if not artifact.is_file() or _sha256_file(artifact) != expected:
            raise PhaseFDatasetError(f"source artifact hash mismatch: {relative}")


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
