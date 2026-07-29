"""Conservative function-level extraction from the SARD Juliet C/C++ archive."""

from __future__ import annotations

import hashlib
import json
import random
import re
import zipfile
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from aegislm.datasets.source import (
    build_source_target,
    format_source_prompt,
    validate_source_record,
)
from aegislm.datasets.source_audit import count_source_training_tokens

SARD_JULIET_PROFILE = "phase-f-sard-grounded-v1"
SARD_JULIET_SOURCE = "NIST SARD Juliet C/C++ 1.3"
SARD_JULIET_REVISION = "2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3"
SARD_JULIET_URL = "https://samate.nist.gov/SARD/test-suites/112"
SARD_JULIET_LICENSE = "NIST SARD public-domain/CC0-1.0 dataset declaration"
SARD_JULIET_SEED = 20260728
_SINGLE_FILE = re.compile(
    r"^C/testcases/(?P<cwe_dir>CWE(?P<cwe>\d+)_.*?)/"
    r"(?:s\d+/)?(?P<stem>.+)_(?P<variant>0[1-9]|10)\.(?P<extension>c|cpp)$"
)
_FUNCTION = re.compile(
    r"(?m)^[ \t]*(?P<signature>[^\n;{}]*?\b"
    r"(?P<name>(?:[A-Za-z_]\w*_bad)|bad|good[A-Za-z0-9_]*)"
    r"\s*\([^;{}]*\)\s*)\{"
)
_COMMENT = re.compile(r"/\*.*?\*/|//[^\n]*", re.DOTALL)
_FLAW_COMMENT = re.compile(r"/\*.*?POTENTIAL\s+FLAW\s*:.*?\*/", re.DOTALL | re.I)
_FIX_COMMENT = re.compile(r"/\*.*?\bFIX\s*:.*?\*/", re.DOTALL | re.I)
_CODE_LEAKAGE = re.compile(
    r"\b(?:good[A-Za-z0-9_]*|bad[A-Za-z0-9_]*|CWE[_-]?\d+|Juliet|"
    r"testcase|OMITGOOD|OMITBAD)\b|POTENTIAL\s+FLAW|\bFIX\s*:",
    re.I,
)
_PROMPT_LEAKAGE = re.compile(
    r"\b(?:good[A-Za-z0-9_]*|bad[A-Za-z0-9_]*|Juliet|testcase|"
    r"OMITGOOD|OMITBAD)\b|POTENTIAL\s+FLAW|\bFIX\s*:|"
    r'"(?:label|gold|split|source_dataset|dataset_name|expected_output)"\s*:',
    re.I,
)


@dataclass(frozen=True)
class JulietFunction:
    """One model-safe Juliet function and its private supervision."""

    archive_path: str
    group_id: str
    source_sha256: str
    cwe: str
    label: Literal["present", "not_observed"]
    original_name: str
    code: str
    findings: tuple[dict[str, str], ...]


def iter_juliet_candidates(
    archive: Path,
) -> Iterable[tuple[str, bytes, re.Match[str]]]:
    """Yield conservative single-file Juliet variants without extracting the ZIP."""
    with zipfile.ZipFile(archive) as bundle:
        for name in sorted(bundle.namelist()):
            match = _SINGLE_FILE.fullmatch(name)
            if match is not None:
                yield name, bundle.read(name), match


def extract_juliet_functions(
    archive: Path,
) -> tuple[list[JulietFunction], list[dict[str, Any]]]:
    """Extract one grounded bad/good pair per eligible source file."""
    functions: list[JulietFunction] = []
    catalog: list[dict[str, Any]] = []
    for archive_path, payload, path_match in iter_juliet_candidates(archive):
        source_sha256 = hashlib.sha256(payload).hexdigest()
        group_id = hashlib.sha256(archive_path.encode()).hexdigest()
        cwe = f"CWE-{path_match.group('cwe')}"
        reason = "eligible"
        extracted: list[JulietFunction] = []
        try:
            source = payload.decode("utf-8")
            parsed = _extract_functions(source)
            bad = [item for item in parsed if _is_bad_name(item[0])]
            good = [item for item in parsed if _is_good_name(item[0])]
            bad_candidates: list[JulietFunction] = []
            for name, text in bad:
                if not _FLAW_COMMENT.search(text):
                    continue
                candidate = _build_function(
                    archive_path,
                    group_id,
                    source_sha256,
                    cwe,
                    "present",
                    name,
                    text,
                )
                if candidate is not None:
                    bad_candidates.append(candidate)
            good_candidates: list[JulietFunction] = []
            for name, text in good:
                if not _FIX_COMMENT.search(text):
                    continue
                candidate = _build_function(
                    archive_path,
                    group_id,
                    source_sha256,
                    cwe,
                    "not_observed",
                    name,
                    text,
                )
                if candidate is not None:
                    good_candidates.append(candidate)
            if not bad_candidates:
                reason = "grounded_bad_function_missing"
            elif not good_candidates:
                reason = "verified_good_function_missing"
            else:
                extracted = [
                    sorted(bad_candidates, key=lambda item: item.original_name)[0],
                    sorted(good_candidates, key=lambda item: item.original_name)[0],
                ]
        except UnicodeDecodeError:
            reason = "utf8_decode_failed"
        functions.extend(extracted)
        catalog.append(
            {
                "schema_version": "aegislm.raw-catalog.v2",
                "source_dataset": SARD_JULIET_SOURCE,
                "source_revision": SARD_JULIET_REVISION,
                "source_url": SARD_JULIET_URL,
                "license_or_terms": SARD_JULIET_LICENSE,
                "archive_path": archive_path,
                "source_sha256": source_sha256,
                "group_id": group_id,
                "cwe": cwe,
                "variant": path_match.group("variant"),
                "representation": "source_function",
                "contains_executable_payload": False,
                "extracted_function_count": len(extracted),
                "disposition": "eligible" if extracted else "quarantine",
                "disposition_reason": reason,
            }
        )
    return functions, catalog


def materialize_juliet_profile(
    functions: Sequence[JulietFunction],
    *,
    tokenizer: Any,
    seed: int = SARD_JULIET_SEED,
    cutoff_len: int = 2048,
    train_pairs: int = 5000,
    validation_pairs: int = 500,
    test_pairs: int = 250,
) -> dict[str, Any]:
    """Apply group-first quotas, F2 contract validation, and exact token gating."""
    by_group: dict[str, list[JulietFunction]] = {}
    for function in functions:
        by_group.setdefault(function.group_id, []).append(function)
    complete_groups = [
        values
        for values in by_group.values()
        if Counter(item.label for item in values)
        == Counter({"present": 1, "not_observed": 1})
    ]
    ordered_candidates = sorted(
        complete_groups,
        key=lambda values: hashlib.sha256(
            f"{seed}:{values[0].group_id}".encode()
        ).hexdigest(),
    )
    ordered: list[list[JulietFunction]] = []
    seen_code_hashes: set[str] = set()
    for group in ordered_candidates:
        group_code_hashes = {
            hashlib.sha256(item.code.encode()).hexdigest() for item in group
        }
        if seen_code_hashes & group_code_hashes:
            continue
        seen_code_hashes.update(group_code_hashes)
        ordered.append(group)
    required = train_pairs + validation_pairs + test_pairs
    selected = ordered[:required]
    assignments: dict[str, str] = {}
    boundaries = (train_pairs, train_pairs + validation_pairs)
    for index, group in enumerate(selected):
        split = (
            "train"
            if index < boundaries[0]
            else "validation"
            if index < boundaries[1]
            else "test"
        )
        assignments[group[0].group_id] = split

    accepted: dict[str, list[dict[str, Any]]] = {
        "train": [],
        "validation": [],
        "test": [],
    }
    manifest: list[dict[str, Any]] = []
    canonical_records: list[dict[str, Any]] = []
    exclusions: Counter[str] = Counter()
    target_hashes: Counter[str] = Counter()
    code_hashes: Counter[str] = Counter()
    maximum_tokens = 0
    for group in selected:
        staged: list[tuple[dict[str, Any], dict[str, Any], int, JulietFunction]] = []
        group_reason = ""
        split = assignments[group[0].group_id]
        for function in group:
            record = juliet_function_to_source_record(function, split=split)
            errors = validate_source_record(record)
            result = build_source_target(record, findings=function.findings)
            if errors or not result.eligible or result.target is None:
                group_reason = "source_contract_failed"
                break
            prompt = format_source_prompt(record)
            token_count = count_source_training_tokens(tokenizer, prompt, result.target)
            maximum_tokens = max(maximum_tokens, token_count)
            if token_count > cutoff_len:
                group_reason = "tokenizer_cutoff_exceeded"
                break
            staged.append((record, result.target, token_count, function))
        if group_reason:
            exclusions[group_reason] += 1
            continue
        for record, target, token_count, function in staged:
            row = {
                "record_id": record["id"],
                "group_id": function.group_id,
                "split": split,
                "label": function.label,
                "cwe": function.cwe,
                "source_sha256": function.source_sha256,
                "code_sha256": record["code"]["sha256"],
                "archive_path": function.archive_path,
                "evidence_level": "code_span_grounded",
                "token_count": token_count,
                "contains_executable_payload": False,
                "disposition": "eligible",
            }
            manifest.append(row)
            canonical_records.append(record)
            target_hashes[
                hashlib.sha256(
                    json.dumps(
                        target,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode()
                ).hexdigest()
            ] += 1
            code_hashes[str(record["code"]["sha256"])] += 1
            messages = [
                *format_source_prompt(record),
                {
                    "role": "assistant",
                    "content": json.dumps(
                        target,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                },
            ]
            accepted[split].append(
                {
                    "id": record["id"],
                    "messages": messages,
                    "code_sha256": record["code"]["sha256"],
                }
            )

    rng = random.Random(seed)
    for rows in accepted.values():
        rng.shuffle(rows)
    counts = {
        split: dict(Counter(row["label"] for row in manifest if row["split"] == split))
        for split in accepted
    }
    quota_pass = all(
        counts[split].get(label, 0) == quota
        for split, quota in (
            ("train", train_pairs),
            ("validation", validation_pairs),
            ("test", test_pairs),
        )
        for label in ("present", "not_observed")
    )
    exact_target_duplicate_count = sum(
        count - 1 for count in target_hashes.values() if count > 1
    )
    exact_code_duplicate_count = sum(
        count - 1 for count in code_hashes.values() if count > 1
    )
    record_count = len(manifest)
    model_visible_label_leakage_count = sum(
        bool(_PROMPT_LEAKAGE.search(message["content"]))
        for rows in accepted.values()
        for row in rows
        for message in row["messages"][:2]
    )
    exact_code_duplicate_rate = (
        exact_code_duplicate_count / record_count if record_count else 0.0
    )
    exact_target_duplicate_rate = (
        exact_target_duplicate_count / record_count if record_count else 0.0
    )
    maximum_exact_target_count = max(target_hashes.values(), default=0)
    maximum_exact_target_fraction = (
        maximum_exact_target_count / record_count if record_count else 0.0
    )
    quality_gates = {
        "model_visible_label_leakage": model_visible_label_leakage_count == 0,
        "exact_code_duplicate_rate": exact_code_duplicate_rate <= 0.05,
        "exact_target_duplicate_rate": exact_target_duplicate_rate <= 0.05,
        "maximum_exact_target_fraction": maximum_exact_target_count
        <= max(1, int(record_count * 0.02)),
        "tokenizer_cutoff": not exclusions["tokenizer_cutoff_exceeded"],
    }
    automated_pass = quota_pass and all(quality_gates.values())
    return {
        "profile": SARD_JULIET_PROFILE,
        "status": (
            "manual_review_required"
            if automated_pass
            else "evidence_supply_blocked"
            if not quota_pass
            else "automated_quality_gate_failed"
        ),
        "approved_for_training": False,
        "seed": seed,
        "cutoff_len": cutoff_len,
        "required_pairs": {
            "train": train_pairs,
            "validation": validation_pairs,
            "test": test_pairs,
        },
        "available_complete_pairs": len(complete_groups),
        "available_unique_complete_pairs": len(ordered),
        "selected_pairs_before_token_gate": len(selected),
        "eligible_counts": counts,
        "eligible_record_count": len(manifest),
        "excluded_group_counts": dict(exclusions),
        "maximum_observed_tokens": maximum_tokens,
        "model_visible_label_leakage_count": model_visible_label_leakage_count,
        "exact_code_duplicate_count": exact_code_duplicate_count,
        "exact_code_duplicate_rate": exact_code_duplicate_rate,
        "exact_target_duplicate_count": exact_target_duplicate_count,
        "exact_target_duplicate_rate": exact_target_duplicate_rate,
        "maximum_exact_target_fraction": maximum_exact_target_fraction,
        "maximum_exact_target_count": maximum_exact_target_count,
        "quality_gates": quality_gates,
        "automated_pass": automated_pass,
        "quota_pass": quota_pass,
        "manual_review": {
            "required_count": 100,
            "status": "not_started",
            "maximum_label_or_evidence_error_rate": 0.05,
        },
        "records": accepted,
        "manifest": manifest,
        "canonical_records": canonical_records,
    }


def juliet_function_to_source_record(
    function: JulietFunction,
    *,
    split: str,
) -> dict[str, Any]:
    """Create the private normalized F2 source record."""
    code_sha256 = hashlib.sha256(function.code.encode()).hexdigest()
    record = {
        "schema_version": "aegislm.source-vulnerability-record.v1",
        "id": f"sard-{function.group_id[:16]}-{function.label}",
        "code": {"text": function.code, "sha256": code_sha256},
        "task": {"target_cwe": function.cwe},
        "metadata": {
            "split": split,
            "source_dataset": SARD_JULIET_SOURCE,
            "label": function.label,
            "evidence_level": "code_span_grounded",
            "contains_executable_payload": False,
        },
    }
    return record


def summarize_juliet_manual_review(
    rows: Sequence[Mapping[str, Any]],
    *,
    required_count: int = 100,
    maximum_error_rate: float = 0.05,
) -> dict[str, Any]:
    """Validate the fixed manual sample and return its conservative decision."""
    if len(rows) != required_count:
        raise ValueError(
            f"manual review requires exactly {required_count} rows; got {len(rows)}"
        )
    missing = [
        str(row.get("id") or index)
        for index, row in enumerate(rows)
        if not isinstance(row.get("operator_label_error"), bool)
        or not isinstance(row.get("operator_evidence_error"), bool)
    ]
    if missing:
        raise ValueError(
            "manual review has unfinished boolean decisions: " + ", ".join(missing[:10])
        )
    error_count = sum(
        bool(row["operator_label_error"]) or bool(row["operator_evidence_error"])
        for row in rows
    )
    error_rate = error_count / required_count
    return {
        "required_count": required_count,
        "reviewed_count": len(rows),
        "error_count": error_count,
        "error_rate": error_rate,
        "maximum_label_or_evidence_error_rate": maximum_error_rate,
        "status": "pass" if error_rate <= maximum_error_rate else "fail",
        "pass": error_rate <= maximum_error_rate,
    }


def _extract_functions(source: str) -> list[tuple[str, str]]:
    functions: list[tuple[str, str]] = []
    for match in _FUNCTION.finditer(source):
        open_brace = match.end() - 1
        close_brace = _matching_brace(source, open_brace)
        if close_brace is not None:
            functions.append(
                (match.group("name"), source[match.start() : close_brace + 1])
            )
    return functions


def _matching_brace(source: str, opening: int) -> int | None:
    depth = 0
    state = "code"
    index = opening
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if char == "/" and next_char == "*":
                state = "block_comment"
                index += 2
                continue
            if char == "/" and next_char == "/":
                state = "line_comment"
                index += 2
                continue
            if char in {'"', "'"}:
                state = char
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return index
        elif state == "block_comment" and char == "*" and next_char == "/":
            state = "code"
            index += 2
            continue
        elif state == "line_comment" and char == "\n":
            state = "code"
        elif state in {'"', "'"}:
            if char == "\\":
                index += 2
                continue
            if char == state:
                state = "code"
        index += 1
    return None


def _build_function(
    archive_path: str,
    group_id: str,
    source_sha256: str,
    cwe: str,
    label: Literal["present", "not_observed"],
    original_name: str,
    original_code: str,
) -> JulietFunction | None:
    evidence_spans = (
        _following_statements(original_code, _FLAW_COMMENT)
        if label == "present"
        else []
    )
    sanitized = _sanitize_function(original_code, original_name)
    if not sanitized or _CODE_LEAKAGE.search(sanitized):
        return None
    findings: list[dict[str, str]] = []
    for span in evidence_spans:
        clean_span = _sanitize_fragment(span, original_name).strip()
        if clean_span and clean_span in sanitized:
            findings.append(
                {
                    "code_span": clean_span[:1000],
                    "operation": "code-visible operation on the vulnerable execution path",
                    "evidence": (
                        "This exact source operation is the code-visible basis "
                        "for the scoped assessment."
                    ),
                    "confidence": "high",
                }
            )
    if label == "present" and not findings:
        return None
    return JulietFunction(
        archive_path=archive_path,
        group_id=group_id,
        source_sha256=source_sha256,
        cwe=cwe,
        label=label,
        original_name=original_name,
        code=sanitized,
        findings=tuple(findings[:3]),
    )


def _following_statements(code: str, marker: re.Pattern[str]) -> list[str]:
    spans: list[str] = []
    for match in marker.finditer(code):
        remainder = _COMMENT.sub("", code[match.end() :])
        for line in remainder.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped in {"{", "}"}:
                continue
            spans.append(stripped)
            break
    return list(dict.fromkeys(spans))


def _sanitize_function(code: str, original_name: str) -> str:
    sanitized = _sanitize_fragment(code, original_name)
    lines = [
        line.rstrip()
        for line in sanitized.splitlines()
        if not line.lstrip().startswith("#")
    ]
    return "\n".join(lines).strip()


def _sanitize_fragment(value: str, original_name: str) -> str:
    value = _COMMENT.sub(lambda match: "\n" * match.group(0).count("\n"), value)
    value = re.sub(rf"\b{re.escape(original_name)}\b", "sample_function", value)
    return value


def _is_bad_name(name: str) -> bool:
    return name == "bad" or name.endswith("_bad")


def _is_good_name(name: str) -> bool:
    return name.startswith("good") and name != "good"
