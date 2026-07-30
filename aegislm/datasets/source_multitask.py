"""Build the Phase F source decision/report multitask canary artifact."""

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
from aegislm.training.llamafactory import build_dataset_info_entry

SOURCE_MULTITASK_PROFILE = "phase-f-source-multitask-v1"
REPORT_TRAIN_NAME = "phase_f_source_multitask_v1_report_train"
DECISION_TRAIN_NAME = "phase_f_source_multitask_v1_decision_train"
REPORT_VALIDATION_NAME = "phase_f_source_multitask_v1_report_validation"
DECISION_VALIDATION_NAME = "phase_f_source_multitask_v1_decision_validation"


def build_source_multitask_artifact(
    report_dir: Path,
    decision_dir: Path,
    canonical_records_path: Path,
    output_dir: Path,
    *,
    seed: int = 20260730,
    development_per_class: int = 50,
    expected_train_count: int = 10000,
    expected_validation_count: int = 1000,
) -> dict[str, Any]:
    """Pair approved contracts and atomically materialize Q1R7 inputs."""
    report_dir = report_dir.resolve()
    decision_dir = decision_dir.resolve()
    canonical_records_path = canonical_records_path.resolve()
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise PhaseFDatasetError(f"output directory already exists: {output_dir}")
    _verify_sha256s(report_dir)
    _verify_sha256s(decision_dir)
    report_manifest = _load_object(report_dir / "dataset_manifest.json")
    decision_manifest = _load_object(decision_dir / "dataset_manifest.json")
    if report_manifest.get("approved_for_training") is not True:
        raise PhaseFDatasetError("full-report source artifact is not approved")
    if decision_manifest.get("approved_for_training") is not True:
        raise PhaseFDatasetError("decision source artifact is not approved")

    report_train = load_jsonl(report_dir / "train.jsonl")
    report_validation = load_jsonl(report_dir / "validation.jsonl")
    decision_train = load_jsonl(decision_dir / "train.jsonl")
    decision_validation = load_jsonl(decision_dir / "validation.jsonl")
    _validate_contract_pair(
        report_train,
        decision_train,
        expected_count=expected_train_count,
        split="train",
    )
    _validate_contract_pair(
        report_validation,
        decision_validation,
        expected_count=expected_validation_count,
        split="validation",
    )
    canonical_rows = load_jsonl(canonical_records_path)
    canonical = {str(row["id"]): row for row in canonical_rows}
    if len(canonical) != len(canonical_rows):
        raise PhaseFDatasetError("canonical records contain duplicate ids")
    development_ids = _select_development_ids(
        report_validation,
        per_class=development_per_class,
        seed=seed,
    )
    development = _development_records(
        development_ids,
        report_by_id=_index(report_validation, "report validation"),
        decision_by_id=_index(decision_validation, "decision validation"),
        canonical_by_id=canonical,
    )

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{output_dir.name}-", dir=output_dir.parent)
    )
    try:
        _write_contract_shards(
            temporary,
            report_train=report_train,
            decision_train=decision_train,
            report_validation=report_validation,
            decision_validation=decision_validation,
        )
        for name, rows in development.items():
            write_jsonl(rows, temporary / "development" / f"{name}.jsonl")
        dataset_info: dict[str, Any] = {}
        for name, file_name in (
            (REPORT_TRAIN_NAME, "llamafactory/report-train.jsonl"),
            (DECISION_TRAIN_NAME, "llamafactory/decision-train.jsonl"),
            (REPORT_VALIDATION_NAME, "llamafactory/report-validation.jsonl"),
            (
                DECISION_VALIDATION_NAME,
                "llamafactory/decision-validation.jsonl",
            ),
        ):
            dataset_info.update(
                build_dataset_info_entry(
                    dataset_name=name,
                    file_name=file_name,
                )
            )
        _write_json(temporary / "dataset_info.json", dataset_info)
        manifest = {
            "schema_version": "aegislm.phase-f-source-multitask-manifest.v1",
            "profile": SOURCE_MULTITASK_PROFILE,
            "status": "approved_for_multitask_canary",
            "approved_for_training": True,
            "canary_only": True,
            "seed": seed,
            "counts": {
                "report_train": len(report_train),
                "decision_train": len(decision_train),
                "report_validation": len(report_validation),
                "decision_validation": len(decision_validation),
                "development": len(development_ids),
            },
            "mixing": {
                "strategy": "interleave_over",
                "train_probabilities": [0.75, 0.25],
                "contract_order": ["full_report", "decision"],
            },
            "sources": {
                "report_profile": report_manifest.get("profile"),
                "report_manifest_sha256": _sha256_file(
                    report_dir / "dataset_manifest.json"
                ),
                "report_sha256s_sha256": _sha256_file(report_dir / "SHA256SUMS"),
                "decision_profile": decision_manifest.get("profile"),
                "decision_manifest_sha256": _sha256_file(
                    decision_dir / "dataset_manifest.json"
                ),
                "decision_sha256s_sha256": _sha256_file(decision_dir / "SHA256SUMS"),
                "canonical_records_sha256": _sha256_file(canonical_records_path),
            },
            "development_policy": {
                "source_split": "validation",
                "per_class": development_per_class,
                "same_ids_for_both_contracts": True,
                "assistant_removed_from_challenges": True,
                "private_records_separated": True,
                "blind_challenge_used": False,
            },
            "llamafactory": {
                "report_train_dataset": REPORT_TRAIN_NAME,
                "decision_train_dataset": DECISION_TRAIN_NAME,
                "report_validation_dataset": REPORT_VALIDATION_NAME,
                "decision_validation_dataset": DECISION_VALIDATION_NAME,
            },
        }
        _write_json(temporary / "dataset_manifest.json", manifest)
        _write_hashes(temporary)
        temporary.replace(output_dir)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return manifest


def _validate_contract_pair(
    report_rows: Sequence[Mapping[str, Any]],
    decision_rows: Sequence[Mapping[str, Any]],
    *,
    expected_count: int,
    split: str,
) -> None:
    if len(report_rows) != expected_count or len(decision_rows) != expected_count:
        raise PhaseFDatasetError(
            f"{split} count mismatch: "
            f"report={len(report_rows)}, decision={len(decision_rows)}, "
            f"expected={expected_count}"
        )
    report = _index(report_rows, f"report {split}")
    decision = _index(decision_rows, f"decision {split}")
    if set(report) != set(decision):
        raise PhaseFDatasetError(f"{split} contract ids do not match")
    for record_id in sorted(report):
        report_messages = _messages(report[record_id])
        decision_messages = _messages(decision[record_id])
        if report_messages[1]["content"] != decision_messages[1]["content"]:
            raise PhaseFDatasetError(
                f"{record_id}: user content differs between contracts"
            )
        if _assessment(report_messages[2]["content"]) != _assessment(
            decision_messages[2]["content"]
        ):
            raise PhaseFDatasetError(
                f"{record_id}: assessment differs between contracts"
            )


def _select_development_ids(
    rows: Sequence[Mapping[str, Any]],
    *,
    per_class: int,
    seed: int,
) -> list[str]:
    if per_class <= 0:
        raise PhaseFDatasetError("development_per_class must be positive")
    by_label: dict[str, list[str]] = {"present": [], "not_observed": []}
    for row in rows:
        label = _assessment(_messages(row)[2]["content"])
        if label not in by_label:
            raise PhaseFDatasetError(
                f"{row.get('id')}: validation assessment must be binary"
            )
        by_label[label].append(str(row["id"]))
    selected: list[str] = []
    for label in ("present", "not_observed"):
        ordered = sorted(
            by_label[label],
            key=lambda record_id: hashlib.sha256(
                f"{seed}:multitask-development:{record_id}".encode()
            ).hexdigest(),
        )
        if len(ordered) < per_class:
            raise PhaseFDatasetError(
                f"not enough {label} validation rows: {len(ordered)}<{per_class}"
            )
        selected.extend(ordered[:per_class])
    return sorted(
        selected,
        key=lambda record_id: hashlib.sha256(
            f"{seed}:multitask-development-order:{record_id}".encode()
        ).hexdigest(),
    )


def _development_records(
    record_ids: Sequence[str],
    *,
    report_by_id: Mapping[str, Mapping[str, Any]],
    decision_by_id: Mapping[str, Mapping[str, Any]],
    canonical_by_id: Mapping[str, Mapping[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    output: dict[str, list[dict[str, Any]]] = {
        "report-challenge": [],
        "report-gold": [],
        "decision-challenge": [],
        "decision-gold": [],
        "private-records": [],
    }
    labels: Counter[str] = Counter()
    for record_id in record_ids:
        if record_id not in canonical_by_id:
            raise PhaseFDatasetError(
                f"canonical records missing development id: {record_id}"
            )
        report_messages = _messages(report_by_id[record_id])
        decision_messages = _messages(decision_by_id[record_id])
        report_target = _json_object(report_messages[2]["content"])
        decision_target = _json_object(decision_messages[2]["content"])
        canonical = dict(canonical_by_id[record_id])
        metadata = canonical.get("metadata")
        code = canonical.get("code")
        if not isinstance(metadata, Mapping) or not isinstance(code, Mapping):
            raise PhaseFDatasetError(f"{record_id}: invalid canonical record")
        label = str(metadata.get("label") or "")
        if label != report_target.get("assessment"):
            raise PhaseFDatasetError(f"{record_id}: canonical label mismatch")
        prompt_code = _prompt_source_code(str(report_messages[1]["content"]))
        if str(code.get("text") or "") != prompt_code:
            raise PhaseFDatasetError(f"{record_id}: canonical code mismatch")
        labels[label] += 1
        output["report-challenge"].append(
            {"id": record_id, "messages": [dict(item) for item in report_messages[:2]]}
        )
        output["report-gold"].append(
            {"id": record_id, "expected_output": report_target}
        )
        output["decision-challenge"].append(
            {
                "id": record_id,
                "messages": [dict(item) for item in decision_messages[:2]],
            }
        )
        output["decision-gold"].append(
            {"id": record_id, "expected_output": decision_target}
        )
        output["private-records"].append(canonical)
    if len(set(labels.values())) != 1 or set(labels) != {"present", "not_observed"}:
        raise PhaseFDatasetError(f"development labels are not balanced: {dict(labels)}")
    return output


def _write_contract_shards(
    root: Path,
    *,
    report_train: Sequence[Mapping[str, Any]],
    decision_train: Sequence[Mapping[str, Any]],
    report_validation: Sequence[Mapping[str, Any]],
    decision_validation: Sequence[Mapping[str, Any]],
) -> None:
    for name, rows in (
        ("report-train", report_train),
        ("decision-train", decision_train),
        ("report-validation", report_validation),
        ("decision-validation", decision_validation),
    ):
        write_jsonl(list(rows), root / "canonical" / f"{name}.jsonl")
        write_jsonl(
            [_to_llamafactory(row) for row in rows],
            root / "llamafactory" / f"{name}.jsonl",
        )


def _to_llamafactory(row: Mapping[str, Any]) -> dict[str, str]:
    messages = _messages(row)
    return {
        "system": str(messages[0]["content"]),
        "instruction": str(messages[1]["content"]),
        "input": "",
        "output": str(messages[2]["content"]),
    }


def _messages(row: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    messages = row.get("messages")
    if not isinstance(messages, list) or len(messages) != 3:
        raise PhaseFDatasetError(f"{row.get('id')}: expected three messages")
    roles = [
        item.get("role") if isinstance(item, Mapping) else None for item in messages
    ]
    if roles != ["system", "user", "assistant"]:
        raise PhaseFDatasetError(f"{row.get('id')}: invalid message roles")
    return messages


def _assessment(value: Any) -> str:
    return str(_json_object(value).get("assessment") or "")


def _prompt_source_code(content: str) -> str:
    start = content.find("{")
    if start < 0:
        raise PhaseFDatasetError("source prompt does not contain a JSON payload")
    try:
        payload, _ = json.JSONDecoder().raw_decode(content[start:])
    except json.JSONDecodeError as exc:
        raise PhaseFDatasetError(f"source prompt JSON is invalid: {exc.msg}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("source_code"), str):
        raise PhaseFDatasetError("source prompt payload is missing source_code")
    return str(payload["source_code"])


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise PhaseFDatasetError(f"invalid JSON: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise PhaseFDatasetError("expected a JSON object")
    return value


def _index(
    rows: Sequence[Mapping[str, Any]],
    name: str,
) -> dict[str, Mapping[str, Any]]:
    indexed = {str(row["id"]): row for row in rows}
    if len(indexed) != len(rows):
        raise PhaseFDatasetError(f"{name} contains duplicate ids")
    return indexed


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
    return _json_object(path.read_text(encoding="utf-8"))


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
