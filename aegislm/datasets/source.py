"""Source-vulnerability contracts, prompts, and conservative target building."""

from __future__ import annotations

import hashlib
import difflib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, TypedDict, cast

from jsonschema import Draft202012Validator

from aegislm.schemas import (
    SOURCE_EVIDENCE_LEVELS,
    SOURCE_VULNERABILITY_OUTPUT_SCHEMA,
    SOURCE_VULNERABILITY_OUTPUT_V1_SCHEMA,
    SOURCE_VULNERABILITY_RECORD_SCHEMA,
)

_RECORD_VALIDATOR = Draft202012Validator(SOURCE_VULNERABILITY_RECORD_SCHEMA)
_OUTPUT_VALIDATOR = Draft202012Validator(SOURCE_VULNERABILITY_OUTPUT_SCHEMA)
_OUTPUT_V1_VALIDATOR = Draft202012Validator(SOURCE_VULNERABILITY_OUTPUT_V1_SCHEMA)
_FORBIDDEN_PROMPT_KEYS = {
    "dataset",
    "dataset_name",
    "source",
    "source_dataset",
    "source_revision",
    "target",
    "label",
    "gold",
    "split",
    "expected_output",
    "is_vulnerable",
}
_GLOBAL_SAFETY_CLAIMS = (
    re.compile(
        r"\b(?:the|this)\s+(?:program|application|codebase)\s+is\s+(?:safe|secure)\b",
        re.I,
    ),
    re.compile(r"\bno vulnerabilities exist\b", re.I),
    re.compile(r"\bcompletely (?:safe|secure)\b", re.I),
    re.compile(r"\bfree of vulnerabilities\b", re.I),
)
SOURCE_TASK_VARIANTS = (
    "Assess the target CWE using only the supplied function.",
    "Determine whether the scoped CWE is observable in the supplied function.",
    "Review the supplied function for the requested CWE using only visible operations.",
    "Produce a scoped CWE assessment grounded only in the supplied function.",
)


class SourcePromptMessage(TypedDict):
    """Chat message accepted by source-vulnerability inference helpers."""

    role: Literal["system", "user"]
    content: str


class SourceContractError(ValueError):
    """Raised when a source record or output violates its contract."""


@dataclass(frozen=True)
class SourceTargetResult:
    """Conservative source target build result."""

    target: dict[str, Any] | None
    eligible: bool
    reason: str
    evidence_linked: bool


SOURCE_SYSTEM_PROMPT = """You are AegisLM, a defensive source-code vulnerability analyst.

Return exactly one JSON object and no Markdown. The object must contain:
- schema_version="aegislm.source-vulnerability-assessment.v2"
- scope: target_cwe and boundary="supplied_function"
- assessment: present, not_observed, or uncertain
- assessment_basis: related exact code_spans, their relationship, conclusion, confidence
- findings: related exact code_spans, operation, evidence, and confidence
- limitations: array of strings
- recommendations: array of strings

Use only the supplied function. Every item in code_spans must be copied exactly
from it. Explain the security relationship between the spans; naming one API or
repeating a generic statement is not sufficient evidence.
The assessment is scoped to the requested CWE and supplied function; it is not a
claim that the whole program is safe. Do not infer from provenance, dataset
identity, labels, record IDs, file paths, or split metadata. Do not emit ATT&CK
mapping, malware behavior fields, exploit steps, payloads, evasion, persistence,
credential theft, or other actionable offensive instructions."""


def validate_source_record(record: Mapping[str, Any]) -> list[str]:
    """Return schema and integrity errors for a normalized source record."""
    errors = _schema_errors(_RECORD_VALIDATOR, record)
    if errors:
        return errors
    code = cast(Mapping[str, Any], record["code"])
    actual_hash = hashlib.sha256(str(code["text"]).encode()).hexdigest()
    if code["sha256"] != actual_hash:
        errors.append("code.sha256 does not match code.text")
    if _find_forbidden_keys(record.get("task")):
        errors.append("task contains provenance or gold keys")
    return errors


def validate_source_output(
    output: Mapping[str, Any],
    *,
    source_code: str | None = None,
) -> list[str]:
    """Return source output schema and semantic errors."""
    validator = (
        _OUTPUT_VALIDATOR
        if output.get("schema_version") == "aegislm.source-vulnerability-assessment.v2"
        else _OUTPUT_V1_VALIDATOR
    )
    errors = _schema_errors(validator, output)
    if errors:
        return errors
    assessment = str(output["assessment"])
    findings = cast(list[Mapping[str, Any]], output["findings"])
    if source_code is not None:
        if validator is _OUTPUT_VALIDATOR:
            basis = cast(list[Mapping[str, Any]], output["assessment_basis"])
            errors.extend(_exact_span_errors("assessment_basis", basis, source_code))
            errors.extend(_exact_span_errors("findings", findings, source_code))
        else:
            for index, finding in enumerate(findings):
                span = str(finding["code_span"])
                if span not in source_code:
                    errors.append(
                        f"findings.{index}.code_span is not an exact source substring"
                    )
    if assessment == "not_observed" and _contains_global_safety_claim(output):
        errors.append("not_observed output makes a global safety claim")
    return errors


def format_source_prompt(
    record: Mapping[str, Any],
) -> list[SourcePromptMessage]:
    """Format only target CWE and supplied source code for the model."""
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
    variant_id = source_prompt_variant_id(record)
    return [
        {"role": "system", "content": SOURCE_SYSTEM_PROMPT},
        {
            "role": "user",
            "content": "\n\n".join(
                [
                    SOURCE_TASK_VARIANTS[variant_id],
                    json.dumps(visible, ensure_ascii=False, indent=2, sort_keys=True),
                    "Return only the required source vulnerability assessment JSON.",
                ]
            ),
        },
    ]


def build_source_target(
    record: Mapping[str, Any],
    *,
    findings: Sequence[Mapping[str, Any]] = (),
    assessment_basis: Sequence[Mapping[str, Any]] = (),
) -> SourceTargetResult:
    """Build a target only when the private label has trustworthy evidence."""
    record_errors = validate_source_record(record)
    if record_errors:
        raise SourceContractError("; ".join(record_errors))
    metadata = cast(Mapping[str, Any], record["metadata"])
    code = cast(Mapping[str, Any], record["code"])
    task = cast(Mapping[str, Any], record["task"])
    label = str(metadata["label"])
    evidence_level = str(metadata["evidence_level"])
    if evidence_level not in SOURCE_EVIDENCE_LEVELS:
        return SourceTargetResult(None, False, "evidence_level_not_grounded", False)

    source_code = str(code["text"])
    grounded_findings = _normalize_findings(findings, source_code)
    grounded_basis = _normalize_basis(assessment_basis, source_code)
    if not grounded_basis:
        grounded_basis = [
            {
                "code_spans": item["code_spans"],
                "relationship": item["operation"],
                "conclusion": item["evidence"],
                "confidence": item["confidence"],
            }
            for item in grounded_findings
        ]
    if label == "present" and not grounded_findings:
        return SourceTargetResult(None, False, "positive_code_span_missing", False)
    if not grounded_basis:
        return SourceTargetResult(None, False, "assessment_basis_missing", False)
    if label == "uncertain":
        return SourceTargetResult(None, False, "uncertain_not_supervised", False)

    scope_anchor = _scope_anchor(str(code["text"]))
    target = {
        "schema_version": "aegislm.source-vulnerability-assessment.v2",
        "scope": {
            "target_cwe": task["target_cwe"],
            "boundary": "supplied_function",
        },
        "assessment": label,
        "assessment_basis": grounded_basis,
        "findings": grounded_findings if label == "present" else [],
        "limitations": [
            "This assessment is limited to the requested CWE and supplied function.",
            (
                "The reviewed boundary includes these supplied code excerpts: "
                f"{scope_anchor}"
            ),
            "This result does not establish whole-program safety or exploitability.",
        ],
        "recommendations": [
            "Confirm the scoped result with deterministic analysis and human review."
        ],
    }
    target_errors = validate_source_output(target, source_code=str(code["text"]))
    if target_errors:
        raise SourceContractError("; ".join(target_errors))
    return SourceTargetResult(
        target,
        True,
        "eligible",
        bool(grounded_basis) and (label != "present" or bool(grounded_findings)),
    )


def source_prompt_variant_id(record: Mapping[str, Any]) -> int:
    """Return one of four deterministic, label-independent prompt variants."""
    code = record.get("code")
    code = code if isinstance(code, Mapping) else {}
    digest = str(code.get("sha256") or "")
    return int(digest[:8], 16) % len(SOURCE_TASK_VARIANTS)


def derive_patch_findings(
    vulnerable_code: str,
    fixed_code: str,
    *,
    maximum_findings: int = 3,
) -> list[dict[str, str]]:
    """Derive bounded exact spans changed by a verified before/fixed pair."""
    if not vulnerable_code or not fixed_code or vulnerable_code == fixed_code:
        return []
    before_lines = vulnerable_code.splitlines(keepends=True)
    after_lines = fixed_code.splitlines(keepends=True)
    matcher = difflib.SequenceMatcher(a=before_lines, b=after_lines, autojunk=False)
    findings: list[dict[str, str]] = []
    for tag, before_start, before_end, _, _ in matcher.get_opcodes():
        if tag not in {"replace", "delete"}:
            continue
        span = "".join(before_lines[before_start:before_end]).strip()
        if not span or span not in vulnerable_code:
            continue
        findings.append(
            {
                "code_span": span[:1000],
                "operation": "operation changed by the verified defensive patch",
                "evidence": (
                    "This exact source span is removed or replaced in the paired "
                    "fixed function."
                ),
                "confidence": "high",
            }
        )
        if len(findings) >= maximum_findings:
            break
    if findings:
        return findings

    character_matcher = difflib.SequenceMatcher(
        a=vulnerable_code,
        b=fixed_code,
        autojunk=False,
    )
    for tag, before_start, before_end, _, _ in character_matcher.get_opcodes():
        if tag in {"replace", "delete"}:
            span = vulnerable_code[before_start:before_end].strip()
            if span:
                return [
                    {
                        "code_span": span[:1000],
                        "operation": "expression changed by the verified defensive patch",
                        "evidence": (
                            "This exact expression differs from the paired fixed function."
                        ),
                        "confidence": "high",
                    }
                ]
    return []


def phase_f_record_to_source_record(
    record: Mapping[str, Any],
    manifest_row: Mapping[str, Any],
) -> dict[str, Any]:
    """Convert an F1 materialized row into the F2 private normalized record."""
    input_section = cast(Mapping[str, Any], record.get("input") or {})
    context = str(input_section.get("context") or "")
    marker = "Source-code excerpt:\n"
    code = context.split(marker, 1)[1].strip() if marker in context else context.strip()
    raw_cwe = str(manifest_row.get("cwe") or "").split(",", 1)[0].strip().upper()
    source_record = {
        "schema_version": "aegislm.source-vulnerability-record.v1",
        "id": str(record.get("id") or manifest_row.get("record_id") or ""),
        "code": {
            "text": code,
            "sha256": hashlib.sha256(code.encode()).hexdigest(),
        },
        "task": {"target_cwe": raw_cwe},
        "metadata": {
            "split": str(manifest_row.get("split") or "test"),
            "source_dataset": str(manifest_row.get("source_dataset") or "unknown"),
            "label": str(manifest_row.get("label_value") or "uncertain"),
            "evidence_level": str(manifest_row.get("evidence_level") or "unknown"),
            "contains_executable_payload": False,
        },
    }
    errors = validate_source_record(source_record)
    if errors:
        raise SourceContractError("; ".join(errors))
    return source_record


def _schema_errors(
    validator: Draft202012Validator,
    value: Mapping[str, Any],
) -> list[str]:
    return [
        _format_schema_error(error)
        for error in sorted(
            validator.iter_errors(dict(value)),
            key=lambda item: list(item.absolute_path),
        )
    ]


def _format_schema_error(error: Any) -> str:
    path = ".".join(str(item) for item in error.absolute_path)
    return f"{path}: {error.message}" if path else error.message


def _find_forbidden_keys(value: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return []
    return sorted(
        str(key) for key in value if str(key).lower() in _FORBIDDEN_PROMPT_KEYS
    )


def _contains_global_safety_claim(value: Mapping[str, Any]) -> bool:
    text = "\n".join(_iter_strings(value))
    return any(pattern.search(text) for pattern in _GLOBAL_SAFETY_CLAIMS)


def _exact_span_errors(
    field: str,
    items: Sequence[Mapping[str, Any]],
    source_code: str,
) -> list[str]:
    errors: list[str] = []
    for item_index, item in enumerate(items):
        for span_index, span in enumerate(cast(Sequence[Any], item["code_spans"])):
            if str(span) not in source_code:
                errors.append(
                    f"{field}.{item_index}.code_spans.{span_index} "
                    "is not an exact source substring"
                )
    return errors


def _normalize_findings(
    findings: Sequence[Mapping[str, Any]],
    source_code: str,
) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for item in findings:
        spans = _normalize_code_spans(item, source_code)
        operation = str(item.get("operation") or "").strip()
        evidence = str(item.get("evidence") or "").strip()
        if not spans or not operation or not evidence:
            continue
        normalized.append(
            {
                "code_spans": spans,
                "operation": operation,
                "evidence": evidence,
                "confidence": str(item.get("confidence") or "medium"),
            }
        )
    return normalized


def _normalize_basis(
    basis: Sequence[Mapping[str, Any]],
    source_code: str,
) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for item in basis:
        spans = _normalize_code_spans(item, source_code)
        relationship = str(item.get("relationship") or "").strip()
        conclusion = str(item.get("conclusion") or "").strip()
        if not spans or not relationship or not conclusion:
            continue
        normalized.append(
            {
                "code_spans": spans,
                "relationship": relationship,
                "conclusion": conclusion,
                "confidence": str(item.get("confidence") or "medium"),
            }
        )
    return normalized


def _normalize_code_spans(
    item: Mapping[str, Any],
    source_code: str,
) -> list[str]:
    raw_spans = item.get("code_spans")
    if isinstance(raw_spans, Sequence) and not isinstance(raw_spans, str):
        candidates = [str(span).strip() for span in raw_spans]
    else:
        candidates = [str(item.get("code_span") or "").strip()]
    return list(
        dict.fromkeys(
            span[:1000] for span in candidates if span and span in source_code
        )
    )[:10]


def _iter_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        result: list[str] = []
        for item in value.values():
            result.extend(_iter_strings(item))
        return result
    if isinstance(value, list):
        result = []
        for item in value:
            result.extend(_iter_strings(item))
        return result
    return []


def _scope_anchor(code: str) -> str:
    lines = [
        line.strip()
        for line in code.splitlines()
        if line.strip()
        and line.strip() not in {"{", "}"}
        and not line.strip().endswith("{")
    ]
    if lines and "(" in lines[0] and ")" in lines[0]:
        lines = lines[1:]
    body = "\n".join(lines) or code.strip()
    if len(body) <= 320:
        return body
    return f"{body[:160]} ... {body[-160:]}"
