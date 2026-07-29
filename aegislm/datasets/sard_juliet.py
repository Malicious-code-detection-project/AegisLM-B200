"""Conservative function-level extraction from the SARD Juliet C/C++ archive."""

from __future__ import annotations

import hashlib
import json
import math
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

SARD_JULIET_PROFILE = "phase-f-sard-grounded-v2"
SARD_JULIET_SOURCE = "NIST SARD Juliet C/C++ 1.3"
SARD_JULIET_REVISION = "2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3"
SARD_JULIET_URL = "https://samate.nist.gov/SARD/test-suites/112"
SARD_JULIET_LICENSE = "NIST SARD public-domain/CC0-1.0 dataset declaration"
SARD_JULIET_SEED = 20260728
MAX_EVIDENCE_SPANS = 10
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
    r"\b(?:[A-Za-z0-9_]*(?:good|bad)[A-Za-z0-9_]*|CWE[_-]?\d+|Juliet|"
    r"testcase|OMITGOOD|OMITBAD)\b|POTENTIAL\s+FLAW|\bFIX\s*:",
    re.I,
)
_PROMPT_LEAKAGE = re.compile(
    r"\b(?:[A-Za-z0-9_]*(?:good|bad)[A-Za-z0-9_]*|Juliet|testcase|"
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
    assessment_basis: tuple[dict[str, Any], ...]
    findings: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class _AnnotatedOperation:
    kind: Literal["flaw", "fix"]
    description: str
    code_spans: tuple[str, ...]


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
    semantic_basis_failure_count = 0
    for group in selected:
        staged: list[tuple[dict[str, Any], dict[str, Any], int, JulietFunction]] = []
        group_reason = ""
        split = assignments[group[0].group_id]
        for function in group:
            record = juliet_function_to_source_record(function, split=split)
            errors = validate_source_record(record)
            result = build_source_target(
                record,
                findings=function.findings,
                assessment_basis=function.assessment_basis,
            )
            if errors or not result.eligible or result.target is None:
                group_reason = "source_contract_failed"
                break
            semantic_basis_failure_count += len(
                _target_semantic_basis_errors(result.target)
            )
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
        for message in row["messages"]
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
        "semantic_basis": semantic_basis_failure_count == 0,
    }
    automated_pass = quota_pass and all(quality_gates.values())
    return {
        "profile": SARD_JULIET_PROFILE,
        "output_contract": "aegislm.source-vulnerability-assessment.v2",
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
        "semantic_basis_failure_count": semantic_basis_failure_count,
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
    unfinished = [
        str(row.get("id") or index)
        for index, row in enumerate(rows)
        if not isinstance(row.get("operator_label_error"), bool)
        or not isinstance(row.get("operator_evidence_error"), bool)
    ]
    reviewed = [
        row
        for row in rows
        if isinstance(row.get("operator_label_error"), bool)
        and isinstance(row.get("operator_evidence_error"), bool)
    ]
    error_count = sum(
        bool(row["operator_label_error"]) or bool(row["operator_evidence_error"])
        for row in reviewed
    )
    maximum_error_count = math.floor(required_count * maximum_error_rate)
    early_failure = bool(unfinished) and error_count > maximum_error_count
    if unfinished and not early_failure:
        raise ValueError(
            "manual review has unfinished boolean decisions: "
            + ", ".join(unfinished[:10])
        )
    error_rate = error_count / required_count
    return {
        "required_count": required_count,
        "reviewed_count": len(reviewed),
        "unfinished_count": len(unfinished),
        "error_count": error_count,
        "error_rate": error_rate,
        "observed_error_rate": error_count / len(reviewed) if reviewed else 0.0,
        "maximum_error_count": maximum_error_count,
        "maximum_label_or_evidence_error_rate": maximum_error_rate,
        "status": (
            "fail_early"
            if early_failure
            else "pass"
            if error_rate <= maximum_error_rate
            else "fail"
        ),
        "pass": not unfinished and error_rate <= maximum_error_rate,
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
    if cwe == "CWE-675":
        # The current exact-substring contract cannot distinguish two identical
        # CloseHandle(data) occurrences without adding source locations.
        return None
    identifier_mapping = _label_identifier_mapping(original_code, original_name)
    sanitized = _sanitize_function(original_code, identifier_mapping)
    if not sanitized or _CODE_LEAKAGE.search(sanitized):
        return None
    annotations = _annotated_operations(
        original_code,
        sanitized,
        identifier_mapping,
    )
    flaw_annotations = [item for item in annotations if item.kind == "flaw"]
    fix_annotations = [item for item in annotations if item.kind == "fix"]
    if label == "present" and not flaw_annotations:
        return None
    if label == "not_observed" and not fix_annotations:
        return None
    if label == "not_observed" and any(
        re.match(r"(?:don['’]?t|do\s+not)\b", item.description, re.I)
        for item in fix_annotations
    ):
        return None
    selected_annotations = (
        flaw_annotations
        if label == "present"
        else [*fix_annotations, *flaw_annotations]
    )
    annotated_spans = _select_annotated_spans(sanitized, selected_annotations)
    supporting_spans = _supporting_spans(
        sanitized,
        annotated_spans,
        limit=max(0, MAX_EVIDENCE_SPANS - len(annotated_spans)),
    )
    spans = _ordered_unique_spans(sanitized, [*annotated_spans, *supporting_spans])
    required_spans = _required_cwe_spans(cwe, label, sanitized, spans)
    spans = _merge_required_spans(sanitized, spans, required_spans)
    if not spans:
        return None
    if _cwe_evidence_errors(cwe, label, spans):
        return None
    flaw_description = _join_descriptions(flaw_annotations)
    fix_description = _join_descriptions(fix_annotations)
    if label == "present":
        relationship = flaw_description
        conclusion = (
            f"The selected setup and operation spans establish {cwe} within "
            f"the supplied function: {flaw_description}"
        )
        findings: tuple[dict[str, Any], ...] = (
            {
                "code_spans": spans,
                "operation": flaw_description,
                "evidence": conclusion,
                "confidence": "high",
            },
        )
    else:
        relationship = (
            f"Defensive condition: {fix_description} "
            f"Relevant operation: {flaw_description}"
            if flaw_description
            else f"Defensive condition: {fix_description}"
        )
        conclusion = (
            f"The selected defensive setup or check prevents the scoped {cwe} "
            f"condition within the supplied function: {fix_description}"
        )
        findings = ()
    assessment_basis = (
        {
            "code_spans": spans,
            "relationship": relationship,
            "conclusion": conclusion,
            "confidence": "high",
        },
    )
    return JulietFunction(
        archive_path=archive_path,
        group_id=group_id,
        source_sha256=source_sha256,
        cwe=cwe,
        label=label,
        original_name=original_name,
        code=sanitized,
        assessment_basis=assessment_basis,
        findings=findings,
    )


def _annotated_operations(
    original_code: str,
    sanitized_code: str,
    identifier_mapping: Mapping[str, str],
) -> list[_AnnotatedOperation]:
    operations: list[_AnnotatedOperation] = []
    for comment in _COMMENT.finditer(original_code):
        raw = comment.group(0)
        if re.search(r"POTENTIAL\s+FLAW\s*:", raw, re.I):
            kind: Literal["flaw", "fix"] = "flaw"
            description = re.sub(
                r"^.*?POTENTIAL\s+FLAW\s*:\s*",
                "",
                raw,
                flags=re.I | re.DOTALL,
            )
        elif re.search(r"\bFIX\s*:", raw, re.I):
            kind = "fix"
            description = re.sub(
                r"^.*?\bFIX\s*:\s*",
                "",
                raw,
                flags=re.I | re.DOTALL,
            )
        else:
            continue
        description = _clean_annotation(description)
        spans = [
            span
            for span in _following_operation_spans(
                original_code[comment.end() :],
                identifier_mapping,
                description=description,
            )
            if span in sanitized_code
        ]
        operations.append(
            _AnnotatedOperation(
                kind=kind,
                description=description,
                code_spans=tuple(spans),
            )
        )
    return operations


def _following_operation_spans(
    remainder: str,
    identifier_mapping: Mapping[str, str],
    *,
    description: str,
) -> list[str]:
    without_comments = _COMMENT.sub("", remainder)
    lines = without_comments.splitlines()
    primary_index: int | None = None
    primary = ""
    primary_end = 0
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped in {"{", "}"}:
            continue
        primary_index = index
        primary, primary_end = _logical_statement(
            lines,
            index,
            identifier_mapping,
        )
        break
    if primary_index is None or primary == ";":
        return []
    spans = [primary]
    if re.match(r"^(?:if|for|while|switch)\s*\(", primary):
        nested = _next_effect_span(
            lines,
            primary_end + 1,
            identifier_mapping,
        )
        if nested:
            spans.append(nested)
    elif re.search(
        r"(?:loop|iteration|initializ|without initializing)", description, re.I
    ):
        for index in range(primary_end + 1, min(len(lines), primary_end + 20)):
            candidate = lines[index].strip()
            if not re.match(r"^(?:for|while)\s*\(", candidate):
                continue
            control, control_end = _logical_statement(
                lines,
                index,
                identifier_mapping,
            )
            spans.append(control)
            nested = _next_effect_span(
                lines,
                control_end + 1,
                identifier_mapping,
            )
            if nested:
                spans.append(nested)
            break
        if re.search(r"initializ", description, re.I):
            for statement in _matching_statements(
                _sanitize_fragment(without_comments, identifier_mapping),
                r"\bdata(?:\s*\[[^\]]+\]|->[A-Za-z_]\w*)\s*"
                r"(?<![=!<>])=(?!=)",
                limit=3,
            ):
                spans.append(statement)
    if re.search(r"(?:read|input|environment|socket|console|file)", description, re.I):
        source, source_end = _next_matching_span(
            lines,
            primary_index,
            identifier_mapping,
            r"\b(?:recv|read|fgets|fgetws|fscanf|scanf|GETENV|getenv|"
            r"fread|ReadFile)\s*\(",
        )
        if source:
            spans.append(source)
            conversion, _ = _next_matching_span(
                lines,
                source_end + 1,
                identifier_mapping,
                r"(?:\b[A-Za-z_]\w*\s*=\s*(?:atoi|atol|strtol|strtoul)\s*\(|"
                r"\bsscanf\s*\()",
            )
            if conversion:
                spans.append(conversion)
    return list(dict.fromkeys(spans))[:5]


def _logical_statement(
    lines: Sequence[str],
    start: int,
    identifier_mapping: Mapping[str, str],
) -> tuple[str, int]:
    collected: list[str] = []
    balance = 0
    end = start
    for index in range(start, len(lines)):
        line = lines[index]
        collected.append(line)
        balance += line.count("(") - line.count(")")
        end = index
        if balance <= 0:
            break
    raw = "\n".join(collected).strip()
    return _sanitize_fragment(raw, identifier_mapping).strip(), end


def _next_effect_span(
    lines: Sequence[str],
    start: int,
    identifier_mapping: Mapping[str, str],
) -> str:
    for index in range(start, len(lines)):
        candidate = lines[index].strip()
        if not candidate or candidate in {"{", "}"}:
            continue
        candidate, _ = _logical_statement(lines, index, identifier_mapping)
        if candidate == ";":
            continue
        if _looks_like_effect(candidate):
            return candidate
    return ""


def _next_matching_span(
    lines: Sequence[str],
    start: int,
    identifier_mapping: Mapping[str, str],
    pattern: str,
) -> tuple[str, int]:
    for index in range(start, len(lines)):
        candidate = lines[index].strip()
        if not candidate or candidate in {"{", "}"}:
            continue
        statement, end = _logical_statement(lines, index, identifier_mapping)
        if re.search(pattern, statement):
            return statement, end
    return "", start


def _select_annotated_spans(
    code: str,
    annotations: Sequence[_AnnotatedOperation],
) -> list[str]:
    mandatory = [
        item.code_spans[-1]
        for item in annotations
        if item.code_spans and not _is_low_value_span(item.code_spans[-1])
    ]
    candidates = [
        span
        for item in annotations
        for span in item.code_spans
        if not _is_low_value_span(span)
    ]
    selected = list(dict.fromkeys(mandatory))[:MAX_EVIDENCE_SPANS]
    for span in candidates:
        if len(selected) >= MAX_EVIDENCE_SPANS:
            break
        if span not in selected:
            selected.append(span)
    return _ordered_unique_spans(code, selected)


def _is_low_value_span(span: str) -> bool:
    match = re.fullmatch(
        r"(?:int|size_t|long|short|unsigned\s+int)\s+"
        r"([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*);",
        span.strip(),
    )
    if match is None:
        return False
    names = {name.strip().lower() for name in match.group(1).split(",")}
    return not names & {"data", "source", "dest", "buffer", "password"}


def _required_cwe_spans(
    cwe: str,
    label: Literal["present", "not_observed"],
    code: str,
    selected: Sequence[str],
) -> list[str]:
    required: list[str] = []
    if cwe in {"CWE-121", "CWE-122"}:
        sinks = [
            span
            for span in selected
            if re.search(
                r"\b(?:memcpy|memmove|strcpy|strncpy|wcscpy|wcsncpy|strcat|"
                r"strncat)\s*\(|\b[A-Za-z_]\w*\s*\[[^\]]+\]\s*=",
                span,
            )
        ]
        if sinks:
            sink = sinks[-1]
            required.append(sink)
            destination = _destination_identifier(sink)
            if destination:
                destination_declaration = _last_statement_before(
                    code,
                    sink,
                    _array_declaration_pattern(destination),
                )
                if destination_declaration:
                    required.append(destination_declaration)
                assignment = _last_statement_before(
                    code,
                    sink,
                    rf"\b{re.escape(destination)}\s*=\s*([A-Za-z_]\w*)\s*;",
                )
                if assignment:
                    required.append(assignment)
                    match = re.search(
                        rf"\b{re.escape(destination)}\s*=\s*([A-Za-z_]\w*)\s*;",
                        assignment,
                    )
                    if match:
                        backing = match.group(1)
                        declaration = _last_statement_before(
                            code,
                            assignment,
                            rf"\b{re.escape(backing)}\s*\[[^\]]+\]\s*;",
                        )
                        if declaration:
                            required.append(declaration)
                destination_setup = _last_statement_before(
                    code,
                    sink,
                    rf"(?:\b{re.escape(destination)}\s*\[[^\]]+\]\s*"
                    r"(?:=[^;]*)?;|"
                    rf"\b{re.escape(destination)}\s*=\s*"
                    r"(?:new\b|(?:malloc|calloc|realloc|ALLOCA)\s*\())",
                )
                if destination_setup:
                    required.append(destination_setup)
            source = _source_identifier(sink)
            if source:
                source_declaration = _last_statement_before(
                    code,
                    sink,
                    _array_declaration_pattern(source),
                )
                if source_declaration:
                    required.append(source_declaration)
                source_setup = _last_statement_before(
                    code,
                    sink,
                    rf"\b{re.escape(source)}\s*(?:\[[^\]]+\])?\s*(?:=|;)",
                )
                if source_setup:
                    required.append(source_setup)
            if re.search(r"\b(?:strcat|strncat)\s*\(", sink):
                destination_init = _last_statement_before(
                    code,
                    sink,
                    rf"\b{re.escape(destination)}\s*\[\s*0\s*\]\s*"
                    r"=\s*(?:L)?'\\0'\s*;",
                )
                if destination_init:
                    required.append(destination_init)
            required.extend(
                _matching_statements_before(
                    code,
                    sink,
                    r"^(?:for|while)\s*\(",
                    limit=1,
                )
            )
    elif cwe == "CWE-457":
        required.extend(
            _matching_statements(
                code,
                r"\b(?:char|wchar_t|int|long|short|float|double|struct\s+\w+)"
                r"(?:\s*[*&])?\s+data(?:\s*\[[^\]]+\])?\s*(?:=|;)",
                limit=1,
            )
        )
        if label == "not_observed":
            required.extend(
                _matching_statements(
                    code,
                    r"(?:\bdata(?:\s*\[[^\]]+\]|->[A-Za-z_]\w*)?\s*"
                    r"(?<![=!<>])=(?!=)|"
                    r"\b(?:memset|memcpy|strcpy|wcscpy)\s*\(\s*data\b)",
                    limit=4,
                )
            )
        required.extend(
            _matching_statements(
                code,
                r"\b(?:print\w*|printf|fprintf|puts|fputs)\s*\([^;\n]*\bdata\b",
                limit=1,
            )
        )
        required.extend(
            _matching_statements(
                code,
                r"^(?:for|while)\s*\(",
                limit=2 if label == "not_observed" else 1,
            )
        )
    elif cwe == "CWE-606":
        loops = [
            span for span in selected if re.match(r"^(?:for|while)\s*\(", span)
        ] or _matching_statements(code, r"^(?:for|while)\s*\(", limit=100)
        loop = loops[-1] if loops else ""
        if loop:
            required.append(loop)
            bound_names = _loop_bound_identifiers(loop)
            bridge = _last_dataflow_statement_before(
                code,
                loop,
                bound_names,
                r"\b(?:sscanf|scanf|fscanf|atoi|atol|strtol|strtoul)\s*\(",
            )
            if bridge:
                required.append(bridge)
                upstream_names = _evidence_identifiers([bridge]) - bound_names
                source = _last_dataflow_statement_before(
                    code,
                    bridge,
                    upstream_names,
                    r"\b(?:recv|read|fgets|GETENV|getenv)\s*\(",
                )
                if source:
                    required.append(source)
            if label == "not_observed":
                bound_check = _last_dataflow_statement_before(
                    code,
                    loop,
                    bound_names,
                    r"^if\s*\(",
                )
                if bound_check:
                    required.append(bound_check)
        required.extend(
            _matching_statements(
                code,
                r"(?:\+\+|--|(?<![=!<>])\+=\s*1)",
                limit=1,
            )
        )
    elif cwe == "CWE-761":
        required.extend(
            _matching_statements(
                code,
                r"\bdata\s*(?:\+\+|--|\+=|-=)",
                limit=1,
            )
        )
        required.extend(
            _matching_statements(
                code,
                r"\b(?:free\s*\(\s*data\s*\)|delete(?:\s*\[\s*\])?\s+data\b)",
                limit=1,
            )
        )
    elif cwe == "CWE-126":
        required.extend(
            _matching_statements(
                code,
                r"\bdest\s*\[[^\]]+\]\s*(?:=|;)|\b(?:destLen|sourceLen)\b",
                limit=2,
            )
        )
        required.extend(
            _matching_statements(
                code,
                r"\b(?:memcpy|memmove)\s*\(|\bdest\s*\[[^\]]+\]\s*="
                r"|\bprint\w*\s*\(\s*buffer\s*\[",
                limit=1,
            )
        )
        required.extend(
            _matching_statements(
                code,
                r"\bdestLen\s*(?<![=!<>])=(?!=)",
                limit=1,
            )
        )
    elif cwe == "CWE-176":
        required.extend(
            _matching_statements(
                code,
                r"\bWideCharToMultiByte\s*\(",
                limit=2,
            )
        )
        if label == "not_observed":
            required.extend(
                _matching_statements(
                    code,
                    r"^if\s*\([^)]*\brequiredSize\b[^)]*\)",
                    limit=1,
                )
            )
    elif cwe == "CWE-590":
        required.extend(
            _matching_statements(
                code,
                r"\bdataBuffer\s*=\s*new\b|\bdata\s*=\s*dataBuffer\s*;",
                limit=2,
            )
        )
        required.extend(
            _matching_statements(
                code,
                r"\bdelete(?:\s*\[\s*\])?\s+data\b|\bfree\s*\(\s*data\s*\)",
                limit=1,
            )
        )
    elif cwe == "CWE-690":
        required.extend(
            _matching_statements(
                code,
                r"\bdata\s*=\s*(?:\([^)]*\)\s*)?"
                r"(?:malloc|calloc|realloc)\s*\(",
                limit=1,
            )
        )
        required.extend(
            _matching_statements(
                code,
                r"\b(?:memcpy|memmove|strcpy|strncpy|wcscpy|wcsncpy|"
                r"memset|wmemset)\s*\(\s*data\b|\bdata\s*\[[^\]]+\]\s*=",
                limit=1,
            )
        )
        if label == "not_observed":
            required.extend(
                _matching_statements(
                    code,
                    r"^if\s*\(\s*data\s*!=\s*NULL\s*\)",
                    limit=1,
                )
            )
    elif cwe == "CWE-321":
        required.extend(
            _matching_statements(
                code,
                r"\b(?:fgets|fgetws|scanf|fscanf)\s*\(",
                limit=1,
            )
        )
        required.extend(
            _matching_statements(
                code,
                r"\bCryptHashData\s*\([^;\n]*\bcryptoKey\b",
                limit=1,
            )
        )
    return list(dict.fromkeys(required))


def _destination_identifier(span: str) -> str:
    call = re.search(
        r"\b(?:memcpy|memmove|strcpy|strncpy|wcscpy|wcsncpy|strcat|strncat)"
        r"\s*\(\s*([A-Za-z_]\w*)",
        span,
    )
    if call:
        return call.group(1)
    indexed = re.search(r"\b([A-Za-z_]\w*)\s*\[[^\]]+\]\s*=", span)
    return indexed.group(1) if indexed else ""


def _source_identifier(span: str) -> str:
    call = re.search(
        r"\b(?:memcpy|memmove|strcpy|strncpy|wcscpy|wcsncpy|strcat|strncat)"
        r"\s*\(\s*[A-Za-z_]\w*\s*,\s*([A-Za-z_]\w*)",
        span,
    )
    if call:
        return call.group(1)
    indexed = re.search(
        r"\b[A-Za-z_]\w*\s*\[[^\]]+\]\s*=\s*([A-Za-z_]\w*)\s*\[",
        span,
    )
    return indexed.group(1) if indexed else ""


def _array_declaration_pattern(identifier: str) -> str:
    return (
        r"^(?:const\s+)?(?:struct\s+\w+|[A-Za-z_]\w*)"
        r"(?:\s+|\s*[*&]\s*)+"
        rf"{re.escape(identifier)}\s*\[[^\]]+\]\s*(?:=[^;]*)?;"
    )


def _matching_statements(
    code: str,
    pattern: str,
    *,
    limit: int,
) -> list[str]:
    matches: list[str] = []
    lines = code.splitlines()
    for index, line in enumerate(lines):
        statement, _ = _logical_statement(lines, index, {})
        if statement and re.search(pattern, statement):
            if statement not in matches:
                matches.append(statement)
            if len(matches) >= limit:
                break
    return matches


def _matching_statements_before(
    code: str,
    boundary: str,
    pattern: str,
    *,
    limit: int,
) -> list[str]:
    position = code.find(boundary)
    if position < 0:
        return []
    return _matching_statements(code[:position], pattern, limit=limit)


def _last_statement_before(code: str, boundary: str, pattern: str) -> str:
    position = code.find(boundary)
    if position < 0:
        return ""
    matches = _matching_statements(code[:position], pattern, limit=100)
    return matches[-1] if matches else ""


def _last_dataflow_statement_before(
    code: str,
    boundary: str,
    identifiers: set[str],
    operation_pattern: str,
) -> str:
    position = code.find(boundary)
    if position < 0:
        return ""
    candidates = _matching_statements(
        code[:position],
        operation_pattern,
        limit=100,
    )
    connected = [
        statement
        for statement in candidates
        if not identifiers
        or any(
            re.search(rf"\b{re.escape(identifier)}\b", statement)
            for identifier in identifiers
        )
    ]
    return connected[-1] if connected else ""


def _loop_bound_identifiers(loop: str) -> set[str]:
    comparison = re.search(
        r"(?:<|<=|>|>=)\s*([A-Za-z_]\w*)|"
        r"\b([A-Za-z_]\w*)\s*(?:<|<=|>|>=)",
        loop,
    )
    if not comparison:
        return set()
    names = {name for name in comparison.groups() if name}
    control = re.search(r"for\s*\(\s*([A-Za-z_]\w*)\s*=", loop)
    if control:
        names.discard(control.group(1))
    return names


def _merge_required_spans(
    code: str,
    current: Sequence[str],
    required: Sequence[str],
) -> list[str]:
    merged = list(dict.fromkeys(required))[:MAX_EVIDENCE_SPANS]
    for span in current:
        if len(merged) >= MAX_EVIDENCE_SPANS:
            break
        if span not in merged:
            merged.append(span)
    return _ordered_unique_spans(code, merged)


def _cwe_evidence_errors(
    cwe: str,
    label: Literal["present", "not_observed"],
    spans: Sequence[str],
) -> list[str]:
    joined = "\n".join(spans)
    errors: list[str] = []
    if cwe in {"CWE-121", "CWE-122"}:
        if not re.search(
            r"\b(?:memcpy|memmove|strcpy|strncpy|wcscpy|wcsncpy|strcat|"
            r"strncat)\s*\(|\b[A-Za-z_]\w*\s*\[[^\]]+\]\s*=",
            joined,
        ):
            errors.append("buffer_effect_missing")
        if not re.search(
            r"\[[^\]]+\]\s*;|\b(?:new|malloc|calloc|realloc|ALLOCA)\b",
            joined,
        ):
            errors.append("destination_capacity_missing")
    elif cwe == "CWE-457":
        if not re.search(r"\bdata\b", joined):
            errors.append("data_object_missing")
        if not re.search(
            r"\b(?:print\w*|printf|fprintf|puts|fputs)\s*\([^;\n]*\bdata\b",
            joined,
        ):
            errors.append("data_use_missing")
        if label == "not_observed" and not re.search(
            r"\bdata(?:\s*\[[^\]]+\]|->[A-Za-z_]\w*)?\s*"
            r"(?<![=!<>])=(?!=)|"
            r"\b(?:memset|memcpy|strcpy|wcscpy)\s*\(\s*data\b",
            joined,
        ):
            errors.append("initialization_missing")
    elif cwe == "CWE-606":
        if not re.search(
            r"\b(?:sscanf|scanf|fscanf|atoi|atol|strtol|strtoul)\s*\(",
            joined,
        ):
            errors.append("loop_bound_bridge_missing")
        if not re.search(r"^(?:for|while)\s*\(", joined, re.MULTILINE):
            errors.append("loop_missing")
        if label == "present" and not re.search(
            r"\b(?:recv|read|fgets|GETENV|getenv)\s*\(", joined
        ):
            errors.append("input_source_missing")
        if label == "not_observed" and not re.search(
            r"^if\s*\([^)]*(?:<|<=|>|>=)[^)]*\)",
            joined,
            re.MULTILINE,
        ):
            errors.append("loop_bound_check_missing")
    elif cwe == "CWE-761":
        if label == "present" and not re.search(r"\bdata\s*(?:\+\+|--|\+=|-=)", joined):
            errors.append("pointer_change_missing")
        if not re.search(
            r"\b(?:free\s*\(\s*data\s*\)|delete(?:\s*\[\s*\])?\s+data\b)",
            joined,
        ):
            errors.append("deallocation_missing")
    elif cwe == "CWE-426":
        if not re.search(
            r"\b(?:SYSTEM|_wsystem|system|wcscpy|strcpy)\s*\([^;\n]*"
            r"(?:L)?\"[^\"\n]+\"",
            joined,
        ):
            errors.append("executable_path_literal_missing")
    elif cwe == "CWE-590":
        if not re.search(r"\bdataBuffer\s*=\s*new\b", joined):
            errors.append("heap_allocation_missing")
        if not re.search(r"\bdata\s*=\s*dataBuffer\s*;", joined):
            errors.append("heap_pointer_link_missing")
        if not re.search(
            r"\b(?:delete(?:\s*\[\s*\])?\s+data\b|free\s*\(\s*data\s*\))",
            joined,
        ):
            errors.append("matching_deallocation_missing")
    elif cwe == "CWE-690":
        if not re.search(
            r"\b(?:memcpy|memmove|strcpy|strncpy|wcscpy|wcsncpy|memset|wmemset)"
            r"\s*\(\s*data\b|\bdata\s*\[[^\]]+\]\s*=",
            joined,
        ):
            errors.append("unchecked_pointer_use_missing")
        if label == "not_observed" and not re.search(
            r"^if\s*\(\s*data\s*!=\s*NULL\s*\)",
            joined,
            re.MULTILINE,
        ):
            errors.append("allocation_check_missing")
    elif cwe == "CWE-321":
        if not re.search(r"\b(?:fgets|fgetws|scanf|fscanf)\s*\(", joined):
            errors.append("runtime_key_input_missing")
        if not re.search(r"\bCryptHashData\s*\([^;\n]*\bcryptoKey\b", joined):
            errors.append("key_derivation_input_missing")
    return errors


def _supporting_spans(
    code: str,
    selected: Sequence[str],
    *,
    limit: int,
) -> list[str]:
    if not selected or limit <= 0:
        return []
    identifiers = _evidence_identifiers(selected)
    first_position = min(
        (code.find(span) for span in selected if code.find(span) >= 0),
        default=len(code),
    )
    lines: list[tuple[int, str]] = []
    position = 0
    for line in code.splitlines():
        stripped = line.strip()
        line_position = code.find(line, position)
        position = max(position, line_position + len(line))
        if (
            line_position < 0
            or line_position >= first_position
            or not stripped
            or stripped in {"{", "}"}
            or stripped in selected
            or _is_low_value_span(stripped)
        ):
            continue
        lines.append((line_position, stripped))
    candidates: list[tuple[int, int, str]] = []
    for line_position, stripped in reversed(lines):
        if not any(
            re.search(rf"\b{re.escape(name)}\b", stripped) for name in identifiers
        ):
            continue
        score = _setup_score(stripped)
        if not score:
            continue
        candidates.append((score, line_position, stripped))
        identifiers.update(_evidence_identifiers([stripped]))
        if len(candidates) >= 12:
            break
    selected_candidates = sorted(
        candidates,
        key=lambda item: (-item[0], -item[1]),
    )[:limit]
    return [span for _, _, span in selected_candidates]


def _ordered_unique_spans(code: str, spans: Sequence[str]) -> list[str]:
    unique = {
        span.strip()
        for span in spans
        if span.strip() and span.strip() != ";" and span.strip() in code
    }
    return sorted(unique, key=lambda span: code.find(span))


def _clean_annotation(value: str) -> str:
    value = re.sub(r"^/\*+|\*/$", "", value.strip(), flags=re.DOTALL)
    value = re.sub(r"^\s*\*\s?", "", value, flags=re.MULTILINE)
    value = re.sub(
        r"\b(?:bad\s*sink|badsink)\b",
        "risk operation",
        value,
        flags=re.I,
    )
    value = re.sub(
        r"\b(?:good\s*sink|goodsink)\b",
        "defensive operation",
        value,
        flags=re.I,
    )
    value = re.sub(
        r"\b(?:bad\s*source|badsource)\b",
        "risk setup",
        value,
        flags=re.I,
    )
    value = re.sub(
        r"\b(?:good\s*source|goodsource)\b",
        "defensive setup",
        value,
        flags=re.I,
    )
    value = re.sub(r"\bbad\b", "risk-prone", value, flags=re.I)
    value = re.sub(r"\bgood\b", "defensive", value, flags=re.I)
    return re.sub(r"\s+", " ", value).strip(" .") + "."


def _join_descriptions(annotations: Sequence[_AnnotatedOperation]) -> str:
    descriptions = list(
        dict.fromkeys(item.description for item in annotations if item.description)
    )
    return " ".join(descriptions)


def _looks_like_effect(line: str) -> bool:
    return bool(
        re.search(
            r"(?:\+\+|--|(?<![=!<>])=(?!=)|\b(?:free|delete|memcpy|memmove|"
            r"strcpy|strncpy|wcsncpy|print\w*|fclose)\s*\()",
            line,
        )
    )


def _looks_like_setup(line: str) -> bool:
    return _setup_score(line) > 0


def _setup_score(line: str) -> int:
    if re.search(r"(?<![=!<>])=(?!=)[^;]*(?:\+|-)\s*\d+", line):
        return 5
    if re.search(r"\b(?:malloc|calloc|realloc|ALLOCA|new)\b", line):
        return 4
    if re.search(
        r"(?:^\s*(?:const\s+)?(?:struct\s+\w+|[A-Za-z_]\w*(?:\s*[*&])?)"
        r"\s+[A-Za-z_]\w*\s*\[[^\]]+\]|"
        r"\b(?:char|wchar_t|int|long|short|float|double|size_t|struct|"
        r"twoIntsStruct)\b[^;]*;)",
        line,
    ):
        return 3
    if re.search(r"\b(?:fscanf|scanf|fgets|recv|read)\b", line):
        return 2
    if re.search(r"(?<![=!<>])=(?!=)", line):
        return 2
    return 0


def _evidence_identifiers(spans: Sequence[str]) -> set[str]:
    ignored = {
        "if",
        "for",
        "while",
        "sizeof",
        "int",
        "char",
        "wchar_t",
        "size_t",
        "void",
        "struct",
        "const",
        "long",
        "short",
        "float",
        "double",
        "null",
    }
    return {
        token
        for span in spans
        for token in re.findall(r"\b[A-Za-z_]\w*\b", span)
        if token.lower() not in ignored
    }


def _target_semantic_basis_errors(target: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    basis = target.get("assessment_basis")
    if not isinstance(basis, list) or not basis:
        return ["assessment_basis_missing"]
    all_spans: list[str] = []
    generic_markers = (
        "code-visible operation on the vulnerable execution path",
        "exact source operation is the code-visible basis",
    )
    for index, item in enumerate(basis):
        if not isinstance(item, Mapping):
            errors.append(f"assessment_basis.{index}.invalid")
            continue
        relationship = str(item.get("relationship") or "").strip()
        conclusion = str(item.get("conclusion") or "").strip()
        spans = item.get("code_spans")
        if len(relationship) < 12 or any(
            marker in relationship.lower() for marker in generic_markers
        ):
            errors.append(f"assessment_basis.{index}.relationship_not_specific")
        if len(conclusion) < 20:
            errors.append(f"assessment_basis.{index}.conclusion_not_specific")
        if not isinstance(spans, list) or not any(
            str(span).strip() not in {"", ";", "{", "}"} for span in spans
        ):
            errors.append(f"assessment_basis.{index}.meaningful_span_missing")
        elif isinstance(spans, list):
            all_spans.extend(str(span) for span in spans)
    scope = target.get("scope")
    cwe = str(scope.get("target_cwe") or "") if isinstance(scope, Mapping) else ""
    assessment = target.get("assessment")
    if assessment in {"present", "not_observed"}:
        errors.extend(
            f"assessment_basis.causal.{error}"
            for error in _cwe_evidence_errors(cwe, assessment, all_spans)
        )
    return errors


def _label_identifier_mapping(code: str, original_name: str) -> dict[str, str]:
    mapping = {original_name: "sample_function"}
    candidates = sorted(
        {
            token
            for token in re.findall(r"\b[A-Za-z_]\w*\b", code)
            if re.search(r"(?:good|bad)", token, re.I) and token != original_name
        },
        key=lambda token: (code.find(token), token),
    )
    for index, token in enumerate(candidates, 1):
        mapping[token] = f"candidate_symbol_{index}"
    return mapping


def _sanitize_function(code: str, identifier_mapping: Mapping[str, str]) -> str:
    sanitized = _sanitize_fragment(code, identifier_mapping)
    lines = [
        line.rstrip()
        for line in sanitized.splitlines()
        if not line.lstrip().startswith("#")
    ]
    return "\n".join(lines).strip()


def _sanitize_fragment(
    value: str,
    identifier_mapping: Mapping[str, str],
) -> str:
    value = _COMMENT.sub(lambda match: "\n" * match.group(0).count("\n"), value)
    for original, replacement in identifier_mapping.items():
        value = re.sub(rf"\b{re.escape(original)}\b", replacement, value)
    return value


def _is_bad_name(name: str) -> bool:
    return name == "bad" or name.endswith("_bad")


def _is_good_name(name: str) -> bool:
    return name.startswith("good") and name != "good"
