"""Define the model-independent contract for source vulnerability assessment.

Pipeline position:
    normalized source record
    -> record validation
    -> label-blind model prompt
    -> evidence-grounded supervised target
    -> output schema and exact-span validation

This module owns the boundary between private dataset metadata and the content a
model is allowed to see. Labels, split assignments, dataset names, record IDs,
and provenance remain private. The prompt contains only the requested CWE and
the supplied function.

The validators in this module establish structural grounding: cited spans must
exist verbatim in the supplied source. They do not prove that those spans form a
causal vulnerability path. CWE-specific semantic validation and human review
remain separate gates.

This module does not parse arbitrary programming languages, execute source code,
or perform static analysis. ``derive_patch_findings`` only proposes evidence
candidates from an already verified before/fixed pair; its output is not
independent vulnerability gold.
"""

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
    """One model-visible system or user message in the source prompt."""

    role: Literal["system", "user"]
    content: str


class SourceContractError(ValueError):
    """Report a fail-closed source record, prompt, or target violation."""


@dataclass(frozen=True)
class SourceTargetResult:
    """Describe whether a record can become supervised training data.

    Attributes:
        target: Validated assistant JSON, or ``None`` when supervision is unsafe.
        eligible: Whether this record may continue through the data pipeline.
        reason: Stable machine-readable decision reason.
        evidence_linked: Whether required structural evidence fields survived
            normalization. This flag does not assert semantic causality.
    """

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
Use the smallest sufficient evidence set and never include more than 8 code_spans
in one assessment_basis or finding item.
The assessment is scoped to the requested CWE and supplied function; it is not a
claim that the whole program is safe. Do not infer from provenance, dataset
identity, labels, record IDs, file paths, or split metadata. Do not emit ATT&CK
mapping, malware behavior fields, exploit steps, payloads, evasion, persistence,
credential theft, or other actionable offensive instructions."""


def validate_source_record(record: Mapping[str, Any]) -> list[str]:
    """Return schema and integrity errors for a normalized private record.

    The record may contain private labels and provenance under ``metadata``.
    This function validates their storage contract; model visibility is enforced
    separately by :func:`format_source_prompt`.
    """
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
    expected_target_cwe: str | None = None,
) -> list[str]:
    """Return structural output errors and exact-span grounding failures.

    When ``source_code`` is supplied, every cited code span must be a verbatim
    substring of that function. Passing this check does not prove that the spans
    causally establish the requested CWE.

    ``expected_target_cwe`` binds the model output back to the requested task.
    A structurally valid answer for a different CWE is not a valid assessment.
    """
    validator = (
        _OUTPUT_VALIDATOR
        if output.get("schema_version") == "aegislm.source-vulnerability-assessment.v2"
        else _OUTPUT_V1_VALIDATOR
    )
    errors = _schema_errors(validator, output)
    if errors:
        return errors
    if expected_target_cwe is not None:
        scope = output.get("scope")
        actual_target_cwe = (
            scope.get("target_cwe") if isinstance(scope, Mapping) else None
        )
        if actual_target_cwe != expected_target_cwe:
            errors.append("scope.target_cwe does not match the requested target CWE")
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
    """Build a label-blind prompt from an allowlist of model-visible fields.

    Only ``task.target_cwe`` and ``code.text`` cross the model boundary. Do not
    replace this allowlist with serialization of the complete canonical record.

    Raises:
        SourceContractError: If the private record is invalid.
    """
    errors = validate_source_record(record)
    if errors:
        raise SourceContractError("; ".join(errors))
    task = cast(Mapping[str, Any], record["task"])
    code = cast(Mapping[str, Any], record["code"])
    # Security boundary: construct a new object instead of deleting private keys
    # from the original record. New metadata fields therefore remain private by
    # default.
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
    """Build supervised assistant JSON only from structurally grounded evidence.

    The private label controls the target but never enters the user prompt.
    Unsupported evidence levels, positive records without findings, and
    ``uncertain`` labels are returned as ineligible rather than being filled with
    synthetic evidence.

    Raises:
        SourceContractError: If the source record or constructed target violates
            its schema or exact-span contract.
    """
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
    # Normalization drops incomplete or invented spans. It establishes literal
    # grounding only; a later CWE-specific gate must judge semantic relevance.
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
            "This result does not establish whole-program safety or exploitability.",
        ],
        "recommendations": ["Confirm with deterministic analysis and human review."],
    }
    target_errors = validate_source_output(
        target,
        source_code=str(code["text"]),
        expected_target_cwe=str(task["target_cwe"]),
    )
    if target_errors:
        raise SourceContractError("; ".join(target_errors))
    return SourceTargetResult(
        target,
        True,
        "eligible",
        bool(grounded_basis) and (label != "present" or bool(grounded_findings)),
    )


def source_prompt_variant_id(record: Mapping[str, Any]) -> int:
    """Select a deterministic prompt variant without reading the private label.

    The code digest keeps repeated builds reproducible and prevents the prompt
    wording itself from directly encoding ``present`` or ``not_observed``.
    """
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
    """Propose bounded evidence spans from a verified before/fixed pair.

    Removed or replaced text is evidence *candidate* material. A patch may also
    contain formatting or refactoring changes, so callers must not treat this
    helper as proof that a span causes ``target_cwe``. See ``SRC-CONTRACT-06``.
    """
    if not vulnerable_code or not fixed_code or vulnerable_code == fixed_code:
        return []
    before_lines = vulnerable_code.splitlines(keepends=True)
    after_lines = fixed_code.splitlines(keepends=True)
    matcher = difflib.SequenceMatcher(a=before_lines, b=after_lines, autojunk=False)
    findings: list[dict[str, str]] = []
    # Prefer complete changed lines because they remain readable to reviewers and
    # can be checked as exact substrings of the vulnerable function.
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

    # Character-level fallback recovers a candidate from single-line edits. It is
    # deliberately a last resort because it carries even less semantic context.
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
    """Bridge a legacy Phase F materialized row into the canonical contract.

    ``manifest_row`` supplies private label, split, provenance, and evidence
    level. The returned record is still private and must pass through
    :func:`format_source_prompt` before it is sent to a model.
    """
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
    """Return deterministic, path-qualified JSON Schema errors."""
    return [
        _format_schema_error(error)
        for error in sorted(
            validator.iter_errors(dict(value)),
            key=lambda item: list(item.absolute_path),
        )
    ]


def _format_schema_error(error: Any) -> str:
    """Render one jsonschema error with its nested field path."""
    path = ".".join(str(item) for item in error.absolute_path)
    return f"{path}: {error.message}" if path else error.message


def _find_forbidden_keys(value: Any) -> list[str]:
    """Find private control-key names at the current mapping level."""
    if not isinstance(value, Mapping):
        return []
    return sorted(
        str(key) for key in value if str(key).lower() in _FORBIDDEN_PROMPT_KEYS
    )


def _contains_global_safety_claim(value: Mapping[str, Any]) -> bool:
    """Detect known English phrases that overstate a scoped negative result."""
    text = "\n".join(_iter_strings(value))
    return any(pattern.search(text) for pattern in _GLOBAL_SAFETY_CLAIMS)


def _exact_span_errors(
    field: str,
    items: Sequence[Mapping[str, Any]],
    source_code: str,
) -> list[str]:
    """Return an error for every cited span absent from the supplied source."""
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
    """Normalize complete findings whose spans occur in the source."""
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
    """Normalize complete assessment-basis items with exact source spans."""
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
    """Deduplicate and bound exact source spans from v1 or v2 input shapes."""
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
    """Flatten nested output strings for conservative phrase checks."""
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
