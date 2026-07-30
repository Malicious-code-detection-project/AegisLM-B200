"""Compact source decision/evidence contract and deterministic report renderer."""

from __future__ import annotations

import json
import hashlib
import shutil
import tempfile
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator

from aegislm.datasets.source import (
    SOURCE_TASK_VARIANTS,
    SourceContractError,
    SourcePromptMessage,
    source_prompt_variant_id,
    validate_source_output,
    validate_source_record,
)
from aegislm.datasets.phase_f import PhaseFDatasetError, load_jsonl, write_jsonl
from aegislm.datasets.source_audit import count_source_training_tokens
from aegislm.schemas import SOURCE_COMPACT_EVIDENCE_OUTPUT_SCHEMA

SOURCE_COMPACT_PROFILE = "phase-f-source-compact-v1"
SOURCE_COMPACT_TRAIN_NAME = "phase_f_source_compact_v1_train"
SOURCE_COMPACT_VALIDATION_NAME = "phase_f_source_compact_v1_validation"
SOURCE_COMPACT_CUTOFF_LEN = 2048

SOURCE_COMPACT_EVIDENCE_SYSTEM_PROMPT = """You are AegisLM, a defensive source-code vulnerability analyst.

Return exactly one compact JSON object and no Markdown with:
- schema_version="aegislm.source-compact-evidence.v1"
- assessment: present, not_observed, or uncertain
- evidence_spans: the smallest sufficient set of exact substrings copied from the supplied function
- confidence: low, medium, or high

Use at most 8 unique evidence spans. present and not_observed require at least one
exact evidence span. uncertain requires an empty evidence_spans array. Use only
the requested CWE and supplied function. Do not add explanations, provenance,
labels, record IDs, paths, exploit steps, payloads, or any other field."""

_VALIDATOR = Draft202012Validator(SOURCE_COMPACT_EVIDENCE_OUTPUT_SCHEMA)


def validate_compact_evidence_output(
    output: Mapping[str, Any],
    *,
    source_code: str | None = None,
) -> list[str]:
    """Validate the compact schema and exact source-substring evidence."""
    errors = [
        _format_schema_error(error)
        for error in sorted(
            _VALIDATOR.iter_errors(dict(output)),
            key=lambda item: list(item.absolute_path),
        )
    ]
    if errors or source_code is None:
        return errors
    for index, span in enumerate(cast(Sequence[Any], output["evidence_spans"])):
        if str(span) not in source_code:
            errors.append(f"evidence_spans.{index} is not an exact source substring")
    return errors


def format_compact_evidence_prompt(
    record: Mapping[str, Any],
) -> list[SourcePromptMessage]:
    """Expose only the scoped CWE and supplied function to the model."""
    errors = validate_source_record(record)
    if errors:
        raise SourceContractError("; ".join(errors))
    task = cast(Mapping[str, Any], record["task"])
    code = cast(Mapping[str, Any], record["code"])
    visible = {
        "scope": {
            "target_cwe": task["target_cwe"],
            "boundary": "supplied_function",
        },
        "source_code": code["text"],
    }
    return [
        {"role": "system", "content": SOURCE_COMPACT_EVIDENCE_SYSTEM_PROMPT},
        {
            "role": "user",
            "content": "\n\n".join(
                [
                    SOURCE_TASK_VARIANTS[source_prompt_variant_id(record)],
                    json.dumps(visible, ensure_ascii=False, indent=2, sort_keys=True),
                    "Return only the compact source evidence JSON.",
                ]
            ),
        },
    ]


def to_compact_training_record(row: Mapping[str, Any]) -> dict[str, Any]:
    """Project one approved full-report training row into compact evidence."""
    messages = _messages(row, expected_count=3)
    source_code = _prompt_payload(str(messages[1]["content"]))["source_code"]
    output = _json_object(messages[2]["content"], "full-report target")
    target = project_full_report_target(output, source_code=str(source_code))
    return {
        "id": str(row["id"]),
        "messages": [
            {"role": "system", "content": SOURCE_COMPACT_EVIDENCE_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": _compact_user_content(str(messages[1]["content"])),
            },
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


def to_compact_challenge_record(row: Mapping[str, Any]) -> dict[str, Any]:
    """Convert a label-blind full-report challenge without exposing gold."""
    messages = _messages(row, expected_count=2)
    _prompt_payload(str(messages[1]["content"]))
    return {
        "id": str(row["id"]),
        "messages": [
            {"role": "system", "content": SOURCE_COMPACT_EVIDENCE_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": _compact_user_content(str(messages[1]["content"])),
            },
        ],
    }


def build_source_compact_artifact(
    source_dir: Path,
    output_dir: Path,
    *,
    tokenizer: Any,
    profile: str = SOURCE_COMPACT_PROFILE,
    cutoff_len: int = SOURCE_COMPACT_CUTOFF_LEN,
    expected_train_count: int = 10000,
    expected_validation_count: int = 1000,
    expected_development_count: int = 100,
) -> dict[str, Any]:
    """Build and atomically freeze compact train, validation, and dev records."""
    from aegislm.training.llamafactory import build_dataset_info_entry

    source_dir = source_dir.resolve()
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise PhaseFDatasetError(f"output directory already exists: {output_dir}")
    _verify_sha256s(source_dir)
    source_manifest = _load_object(source_dir / "dataset_manifest.json")
    if source_manifest.get("approved_for_training") is not True:
        raise PhaseFDatasetError("source multitask artifact is not approved")

    train = [
        to_compact_training_record(row)
        for row in load_jsonl(source_dir / "canonical" / "report-train.jsonl")
    ]
    validation = [
        to_compact_training_record(row)
        for row in load_jsonl(source_dir / "canonical" / "report-validation.jsonl")
    ]
    report_challenge = load_jsonl(source_dir / "development" / "report-challenge.jsonl")
    report_gold = _index(
        load_jsonl(source_dir / "development" / "report-gold.jsonl"),
        "report development gold",
    )
    challenge = [to_compact_challenge_record(row) for row in report_challenge]
    gold: list[dict[str, Any]] = []
    for row in report_challenge:
        record_id = str(row["id"])
        if record_id not in report_gold:
            raise PhaseFDatasetError(f"compact gold missing id: {record_id}")
        messages = _messages(row, expected_count=2)
        source_code = str(_prompt_payload(str(messages[1]["content"]))["source_code"])
        expected = report_gold[record_id].get("expected_output")
        if not isinstance(expected, Mapping):
            raise PhaseFDatasetError(f"{record_id}: invalid report gold")
        gold.append(
            {
                "id": record_id,
                "expected_output": project_full_report_target(
                    expected,
                    source_code=source_code,
                ),
            }
        )
    private_records = load_jsonl(source_dir / "development" / "private-records.jsonl")
    _validate_artifact_sets(
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
            _json_object(row["messages"][2]["content"], "compact target"),
        )
        for row in [*train, *validation]
    ]
    maximum_tokens = max(token_counts, default=0)
    if maximum_tokens > cutoff_len:
        raise PhaseFDatasetError(
            f"compact dataset exceeds tokenizer cutoff: {maximum_tokens}>{cutoff_len}"
        )

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
                dataset_name=SOURCE_COMPACT_TRAIN_NAME,
                file_name="llamafactory/train.jsonl",
            )
        )
        dataset_info.update(
            build_dataset_info_entry(
                dataset_name=SOURCE_COMPACT_VALIDATION_NAME,
                file_name="llamafactory/validation.jsonl",
            )
        )
        _write_json(temporary / "dataset_info.json", dataset_info)
        labels = Counter(
            _json_object(row["messages"][2]["content"], "compact target")["assessment"]
            for row in [*train, *validation]
        )
        manifest = {
            "schema_version": "aegislm.phase-f-source-compact-manifest.v1",
            "profile": profile,
            "status": "approved_for_compact_canary",
            "approved_for_training": True,
            "canary_only": True,
            "cutoff_len": cutoff_len,
            "maximum_tokens": maximum_tokens,
            "counts": {
                "train": len(train),
                "validation": len(validation),
                "development_challenge": len(challenge),
                "development_gold": len(gold),
                "labels": dict(sorted(labels.items())),
            },
            "contract": {
                "schema_version": "aegislm.source-compact-evidence.v1",
                "system_prompt_sha256": hashlib.sha256(
                    SOURCE_COMPACT_EVIDENCE_SYSTEM_PROMPT.encode()
                ).hexdigest(),
                "maximum_evidence_spans": 8,
                "exact_source_substrings": True,
                "deterministic_report_renderer": True,
            },
            "source_artifact": {
                "profile": source_manifest.get("profile"),
                "dataset_manifest_sha256": _sha256_file(
                    source_dir / "dataset_manifest.json"
                ),
                "sha256s_sha256": _sha256_file(source_dir / "SHA256SUMS"),
            },
            "development_policy": {
                "source_split": "validation",
                "assistant_removed_from_challenge": True,
                "gold_separated": True,
                "private_records_separated": True,
                "blind_challenge_used": False,
            },
            "llamafactory": {
                "train_dataset": SOURCE_COMPACT_TRAIN_NAME,
                "validation_dataset": SOURCE_COMPACT_VALIDATION_NAME,
            },
        }
        _write_json(temporary / "dataset_manifest.json", manifest)
        _write_hashes(temporary)
        temporary.replace(output_dir)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return manifest


def project_full_report_target(
    output: Mapping[str, Any],
    *,
    source_code: str,
) -> dict[str, Any]:
    """Project a validated v2 report target into the compact evidence contract."""
    errors = validate_source_output(output, source_code=source_code)
    if errors:
        raise SourceContractError("; ".join(errors))
    assessment = str(output["assessment"])
    ordered_items: list[Mapping[str, Any]] = []
    if assessment == "present":
        ordered_items.extend(cast(Sequence[Mapping[str, Any]], output["findings"]))
    ordered_items.extend(cast(Sequence[Mapping[str, Any]], output["assessment_basis"]))
    spans: list[str] = []
    confidences: list[str] = []
    for item in ordered_items:
        confidence = str(item.get("confidence") or "")
        if confidence:
            confidences.append(confidence)
        for span in cast(Sequence[Any], item.get("code_spans") or []):
            value = str(span)
            if value not in spans:
                spans.append(value)
            if len(spans) == 8:
                break
        if len(spans) == 8:
            break
    target = {
        "schema_version": "aegislm.source-compact-evidence.v1",
        "assessment": assessment,
        "evidence_spans": [] if assessment == "uncertain" else spans,
        "confidence": _minimum_confidence(confidences),
    }
    compact_errors = validate_compact_evidence_output(
        target,
        source_code=source_code,
    )
    if compact_errors:
        raise SourceContractError("; ".join(compact_errors))
    return target


def render_source_assessment(
    compact: Mapping[str, Any],
    *,
    target_cwe: str,
    source_code: str,
) -> dict[str, Any]:
    """Render a stable v2 report without asking the model for boilerplate prose."""
    errors = validate_compact_evidence_output(compact, source_code=source_code)
    if errors:
        raise SourceContractError("; ".join(errors))
    assessment = str(compact["assessment"])
    spans = list(cast(Sequence[str], compact["evidence_spans"]))
    confidence = str(compact["confidence"])
    if assessment == "present":
        relationship = (
            "The selected exact spans are the model-identified code-visible "
            "basis for the scoped CWE."
        )
        conclusion = (
            f"The supplied function contains code-visible evidence assessed as "
            f"{target_cwe}."
        )
    elif assessment == "not_observed":
        relationship = (
            "The selected exact spans are the model-identified defensive or "
            "non-triggering basis for the scoped CWE."
        )
        conclusion = (
            f"The scoped {target_cwe} condition was not observed in the supplied "
            "function."
        )
    else:
        relationship = "The supplied function did not provide sufficient evidence."
        conclusion = (
            f"The scoped {target_cwe} assessment is uncertain for the supplied "
            "function."
        )
    basis_spans = spans or [_first_nonempty_line(source_code)]
    basis = [
        {
            "code_spans": basis_spans,
            "relationship": relationship,
            "conclusion": conclusion,
            "confidence": confidence,
        }
    ]
    findings = (
        [
            {
                "code_spans": spans,
                "operation": (
                    "Code-visible operations selected for the scoped CWE assessment."
                ),
                "evidence": relationship,
                "confidence": confidence,
            }
        ]
        if assessment == "present"
        else []
    )
    report = {
        "schema_version": "aegislm.source-vulnerability-assessment.v2",
        "scope": {
            "target_cwe": target_cwe,
            "boundary": "supplied_function",
        },
        "assessment": assessment,
        "assessment_basis": basis,
        "findings": findings,
        "limitations": [
            "This assessment is limited to the requested CWE and supplied function.",
            "This result does not establish whole-program safety or exploitability.",
        ],
        "recommendations": [
            "Confirm the scoped result with deterministic analysis and human review."
        ],
    }
    report_errors = validate_source_output(report, source_code=source_code)
    if report_errors:
        raise SourceContractError("; ".join(report_errors))
    return report


def _minimum_confidence(values: Sequence[str]) -> str:
    rank = {"low": 0, "medium": 1, "high": 2}
    known = [value for value in values if value in rank]
    return min(known, key=rank.__getitem__) if known else "low"


def _first_nonempty_line(source_code: str) -> str:
    for line in source_code.splitlines():
        value = line.strip()
        if value:
            return value
    raise SourceContractError("source code has no non-empty line")


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


def _compact_user_content(content: str) -> str:
    marker = "Return only the required source vulnerability assessment JSON."
    if marker not in content:
        raise PhaseFDatasetError("source prompt completion instruction is missing")
    return content.replace(marker, "Return only the compact source evidence JSON.")


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


def _validate_artifact_sets(
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
            f"compact dataset count mismatch: {actual}, gold={len(gold)}"
        )
    train_ids = {str(row["id"]) for row in train}
    validation_ids = {str(row["id"]) for row in validation}
    challenge_ids = {str(row["id"]) for row in challenge}
    gold_ids = {str(row["id"]) for row in gold}
    private_ids = {str(row["id"]) for row in private_records}
    for name, ids, rows in (
        ("train", train_ids, train),
        ("validation", validation_ids, validation),
        ("challenge", challenge_ids, challenge),
        ("gold", gold_ids, gold),
        ("private records", private_ids, private_records),
    ):
        if len(ids) != len(rows):
            raise PhaseFDatasetError(f"compact {name} contains duplicate ids")
    if train_ids & validation_ids or train_ids & challenge_ids:
        raise PhaseFDatasetError("compact train ids overlap validation/development")
    if challenge_ids != gold_ids or challenge_ids != private_ids:
        raise PhaseFDatasetError("compact development ids do not match")
    for row in [*train, *validation]:
        messages = _messages(row, expected_count=3)
        source_code = str(_prompt_payload(str(messages[1]["content"]))["source_code"])
        target = _json_object(messages[2]["content"], "compact target")
        errors = validate_compact_evidence_output(target, source_code=source_code)
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


def _format_schema_error(error: Any) -> str:
    path = ".".join(str(item) for item in error.absolute_path)
    return f"{path}: {error.message}" if path else error.message
