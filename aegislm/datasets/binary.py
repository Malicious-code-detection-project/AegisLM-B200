"""Safe normalized binary-analysis records and prompt formatting."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from copy import deepcopy
from typing import Any, Literal, TypedDict, cast

from jsonschema import Draft202012Validator

from aegislm.schemas import (
    BINARY_ANALYSIS_RECORD_SCHEMA,
    BINARY_ASSESSMENT_OUTPUT_SCHEMA,
    BINARY_ROLE_ASSESSMENT_OUTPUT_SCHEMA,
)

_BINARY_RECORD_VALIDATOR = Draft202012Validator(BINARY_ANALYSIS_RECORD_SCHEMA)
_BINARY_OUTPUT_VALIDATOR = Draft202012Validator(BINARY_ASSESSMENT_OUTPUT_SCHEMA)
_BINARY_ROLE_OUTPUT_VALIDATOR = Draft202012Validator(
    BINARY_ROLE_ASSESSMENT_OUTPUT_SCHEMA
)
_FORBIDDEN_PAYLOAD_KEYS = {
    "raw_bytes",
    "bytes",
    "byte_dump",
    "payload",
    "executable",
    "file_content",
}
_DECOMPILER_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", flags=re.DOTALL)
_SECURITY_OPERATION = re.compile(
    r"(?:"
    r"\b(?:memcpy|memmove|strcpy|strncpy|strcat|strncat|sprintf|snprintf|"
    r"printf|fprintf|scanf|fscanf|malloc|calloc|realloc|free|new|delete)\b"
    r"|(?:<<|>>|\+\+|--|\+=|-=|\*=)"
    r"|(?:\[[^\]]+\]\s*=)"
    r")",
    flags=re.IGNORECASE,
)
_TARGET_EVIDENCE_PATTERNS = {
    "CWE-23": re.compile(
        r"(?:fopen|open|remove|rename|strcat|strncat|realpath|"
        r"fgets|recv|read|getenv)",
        re.IGNORECASE,
    ),
    "CWE-36": re.compile(
        r"(?:fopen|open|remove|rename|strcat|strncat|realpath|"
        r"fgets|recv|read|getenv)",
        re.IGNORECASE,
    ),
    "CWE-78": re.compile(
        r"(?:system|popen|exec\w*|winexec|createprocess|command|cmd)",
        re.IGNORECASE,
    ),
    "CWE-120": re.compile(
        r"(?:(?:_*(?:w?mem|w?cs|str)(?:cpy|ncpy|cat|ncat)(?:_chk)?)|"
        r"sprintf|snprintf|fread|recv|copy|\[[^\]]+\])",
        re.IGNORECASE,
    ),
    "CWE-121": re.compile(
        r"(?:(?:_*(?:w?mem|w?cs|str)(?:cpy|ncpy|cat|ncat)(?:_chk)?)|"
        r"w?memset|\w*printf|fread|recv|\[[^\]]+\])",
        re.IGNORECASE,
    ),
    "CWE-122": re.compile(
        r"(?:malloc|calloc|realloc|new|"
        r"(?:_*(?:w?mem|w?cs|str)(?:cpy|ncpy|cat|ncat)(?:_chk)?)|"
        r"w?memset|\w*printf|fread|recv|\[[^\]]+\])",
        re.IGNORECASE,
    ),
    "CWE-124": re.compile(
        r"(?:(?:_*(?:w?mem|w?cs|str)(?:cpy|ncpy|cat|ncat)(?:_chk)?)|"
        r"sprintf|snprintf|"
        r"\[[^\]]*(?:[A-Za-z_]\w*|-\s*1|0xffffffff)[^\]]*\]|"
        r"\bdata\s*=\s*\w+\s*(?:\+\s*-\s*\d+|-\s*(?:1|2|4|8)))",
        re.IGNORECASE,
    ),
    "CWE-126": re.compile(
        r"(?:(?:_*(?:w?mem|w?cs|str)(?:cpy|ncpy|cat|ncat)(?:_chk)?)|"
        r"printf|print\w*line|fwrite|send|data(?:Bad|Good)Buffer|\[[^\]]+\])",
        re.IGNORECASE,
    ),
    "CWE-127": re.compile(
        r"(?:(?:_*(?:w?mem|w?cs|str)(?:cpy|ncpy|cat|ncat)(?:_chk)?)|"
        r"printf|print\w*line|"
        r"\[[^\]]*(?:[A-Za-z_]\w*|-\s*1|0xffffffff)[^\]]*\])",
        re.IGNORECASE,
    ),
    "CWE-134": re.compile(
        r"(?:\w*printf|syslog)",
        re.IGNORECASE,
    ),
    "CWE-190": re.compile(
        r"(?:\+\s*[A-Za-z0-9_(]|[A-Za-z0-9_)]\s*\+|\*|<<)",
        re.IGNORECASE,
    ),
    "CWE-191": re.compile(
        r"(?:-\s*[A-Za-z0-9_(]|[A-Za-z0-9_)]\s*-|--)",
        re.IGNORECASE,
    ),
    "CWE-194": re.compile(
        r"(?:\((?:u?int|u?long|u?short|u?char|size_t)|malloc|calloc|\[[^\]]+\])",
        re.IGNORECASE,
    ),
    "CWE-195": re.compile(
        r"(?:\((?:u?int|u?long|u?short|u?char|size_t)|memcpy|memmove|"
        r"strncpy|malloc|calloc|\[[^\]]+\])",
        re.IGNORECASE,
    ),
    "CWE-197": re.compile(
        r"(?:\((?:u?int|u?long|u?short|u?char)|SUB\d+|CONCAT\d+)",
        re.IGNORECASE,
    ),
    "CWE-369": re.compile(r"(?:/|%|div\b)", re.IGNORECASE),
    "CWE-400": re.compile(
        r"(?:while|for\s*\(|malloc|calloc|operator_new|new|"
        r"sleep|socket|connect|accept)",
        re.IGNORECASE,
    ),
    "CWE-401": re.compile(
        r"(?:malloc|calloc|realloc|strdup|operator_new|new\b)",
        re.IGNORECASE,
    ),
    "CWE-404": re.compile(
        r"(?:fopen|open\s*\(|fdopen|fclose|close\s*\()", re.IGNORECASE
    ),
    "CWE-427": re.compile(
        r"(?:system|popen|execl|execv|loadlibrary|createprocess|getenv|PATH)",
        re.IGNORECASE,
    ),
    "CWE-457": re.compile(
        r"(?:print\w*line|printf|memcpy|memmove|\*\s*[A-Za-z_]|"
        r"[A-Za-z_]\w*\s*\[[^\]]+\])",
        re.IGNORECASE,
    ),
    "CWE-464": re.compile(
        r"(?:memset|memcpy|strcpy|strncpy|\[[^\]]+\]\s*=)", re.IGNORECASE
    ),
    "CWE-588": re.compile(
        r"(?:printStructLine|->|\*\s*\([A-Za-z_].*\))", re.IGNORECASE
    ),
    "CWE-590": re.compile(r"(?:free|delete|operator_delete)", re.IGNORECASE),
    "CWE-606": re.compile(
        r"(?:while|for\s*\(|do\s*\{|fgets|scanf|recv)", re.IGNORECASE
    ),
    "CWE-617": re.compile(r"(?:assert|abort|__assert_fail)", re.IGNORECASE),
    "CWE-665": re.compile(
        r"(?:memcpy|memmove|strcpy|strncpy|print\w*line|printf)", re.IGNORECASE
    ),
    "CWE-672": re.compile(
        r"(?:free|delete|operator_delete|->|\*\s*[A-Za-z_])", re.IGNORECASE
    ),
    "CWE-680": re.compile(
        r"(?:malloc|calloc|realloc|operator_new|new|memset|memcpy|\*|<<)",
        re.IGNORECASE,
    ),
    "CWE-690": re.compile(
        r"(?:malloc|calloc|realloc|operator_new|new|->|\*\s*[A-Za-z_])",
        re.IGNORECASE,
    ),
    "CWE-761": re.compile(
        r"(?:free|delete|operator_delete|\+\+|--|\+=|-=)", re.IGNORECASE
    ),
    "CWE-762": re.compile(
        r"(?:malloc|calloc|realloc|operator_new|new|free|delete|operator_delete)",
        re.IGNORECASE,
    ),
    "CWE-773": re.compile(
        r"(?:fopen|open\s*\(|fdopen|socket|fclose|close\s*\()", re.IGNORECASE
    ),
    "CWE-775": re.compile(
        r"(?:fopen|open\s*\(|fdopen|socket|fclose|close\s*\()", re.IGNORECASE
    ),
    "CWE-789": re.compile(
        r"(?:malloc|calloc|realloc|operator_new|new|alloca|rand|scanf|fgets)",
        re.IGNORECASE,
    ),
}
_MEMORY_COPY = re.compile(
    r"\b(?:(?:_*(?:w?mem|w?cs|str)(?:cpy|ncpy|cat|ncat)(?:_chk)?)|"
    r"\w*printf|fread|recv|copy)\b",
    re.IGNORECASE,
)
_C_ALLOCATOR = re.compile(
    r"\b(?:malloc|calloc|realloc|strdup)\s*\(",
    re.IGNORECASE,
)
_CPP_ALLOCATOR = re.compile(r"\b(?:operator_new|new\b)", re.IGNORECASE)
_C_DEALLOCATOR = re.compile(r"\bfree\s*\(", re.IGNORECASE)
_CPP_DEALLOCATOR = re.compile(
    r"\b(?:operator_delete|delete\b)",
    re.IGNORECASE,
)


class BinaryPromptMessage(TypedDict):
    """Chat message accepted by model inference helpers."""

    role: Literal["system", "user"]
    content: str


class BinaryRecordValidationError(ValueError):
    """Raised when a normalized binary record violates its contract."""


BINARY_SYSTEM_PROMPT = """You are AegisLM, a defensive binary-analysis assistant.

Return exactly one JSON object and no Markdown. The object must contain:
- scope: target_cwe, binary_format, architecture
- assessment: present, not_observed, or uncertain
- findings: function_id, representation, observation, confidence
- limitations: array of strings
- recommendations: array of strings

Use only the supplied pseudo-C, bounded assembly evidence, and static features.
Do not infer from dataset provenance, labels, source symbols, or file paths.
The assessment is scoped to the target CWE and is not a claim that the whole
program is safe. Do not provide exploit, malware deployment, persistence,
credential theft, or evasion instructions."""

BINARY_ROLE_SYSTEM_PROMPT = """You are AegisLM, a defensive binary-analysis assistant.

Return exactly one JSON object and no Markdown. The object must contain:
- scope: target_cwe, binary_format, architecture
- assessment: present, not_observed, or uncertain
- findings: function_id, representation, evidence, relations, confidence
- evidence: evidence_id, role, code_span, explanation
- relations: from_evidence_id, to_evidence_id, relationship
- limitations: array of strings
- recommendations: array of strings

Every code_span must be copied exactly from the supplied evidence. Link each
source, control, bound, or remediation item to a supplied sink. Use only the
supplied pseudo-C, bounded assembly evidence, and static features. Do not infer
from dataset provenance, labels, source symbols, or file paths. The assessment
is scoped to the target CWE and is not a claim that the whole program is safe.
Do not provide exploit, malware deployment, persistence, credential theft, or
evasion instructions."""


def validate_binary_record(record: Mapping[str, Any]) -> None:
    """Validate schema and prohibit embedded executable/raw-byte payloads."""
    errors = sorted(
        _BINARY_RECORD_VALIDATOR.iter_errors(dict(record)),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        raise BinaryRecordValidationError(
            "; ".join(_format_schema_error(error) for error in errors)
        )
    forbidden_paths = _find_forbidden_payload_keys(record)
    if forbidden_paths:
        raise BinaryRecordValidationError(
            "raw executable or byte payload key(s) are forbidden: "
            + ", ".join(forbidden_paths)
        )


def validate_binary_output(output: Mapping[str, Any]) -> list[str]:
    """Return binary output schema errors; an empty list means valid."""
    return [
        _format_schema_error(error)
        for error in sorted(
            _BINARY_OUTPUT_VALIDATOR.iter_errors(dict(output)),
            key=lambda item: list(item.absolute_path),
        )
    ]


def validate_binary_output_for_record(
    output: Mapping[str, Any],
    record: Mapping[str, Any],
) -> list[str]:
    """Validate schema, scope, function IDs, and model-visible evidence linkage."""
    errors = validate_binary_output(output)
    if errors:
        return errors
    validate_binary_record(record)
    artifact = cast(Mapping[str, Any], record["artifact"])
    task = cast(Mapping[str, Any], record["task"])
    analysis = cast(Mapping[str, Any], record["analysis"])
    scope = cast(Mapping[str, Any], output["scope"])
    expected_scope = {
        "target_cwe": task["target_cwe"],
        "binary_format": artifact["format"],
        "architecture": artifact["architecture"],
    }
    for key, expected in expected_scope.items():
        if scope.get(key) != expected:
            errors.append(f"scope.{key}: does not match the supplied record")

    functions = {
        str(item["function_id"]): cast(Mapping[str, Any], item)
        for item in cast(list[Mapping[str, Any]], analysis["functions"])
    }
    assessment = str(output["assessment"])
    findings = cast(list[Mapping[str, Any]], output["findings"])
    if assessment == "present" and not findings:
        errors.append("findings: present assessment requires observable evidence")
    for index, finding in enumerate(findings):
        function_id = str(finding["function_id"])
        function = functions.get(function_id)
        if function is None:
            errors.append(
                f"findings.{index}.function_id: not present in supplied evidence"
            )
            continue
        representation = str(finding["representation"])
        observation = str(finding["observation"])
        if not _observation_is_grounded(
            observation,
            function,
            representation=representation,
        ):
            errors.append(
                f"findings.{index}.observation: no exact supplied evidence fragment"
            )
    return errors


def validate_binary_role_output_for_record(
    output: Mapping[str, Any],
    record: Mapping[str, Any],
) -> list[str]:
    """Validate the v2 role graph, exact spans, scope, and linked sink evidence."""
    errors = [
        _format_schema_error(error)
        for error in sorted(
            _BINARY_ROLE_OUTPUT_VALIDATOR.iter_errors(dict(output)),
            key=lambda item: list(item.absolute_path),
        )
    ]
    if errors:
        return errors
    validate_binary_record(record)
    artifact = cast(Mapping[str, Any], record["artifact"])
    task = cast(Mapping[str, Any], record["task"])
    analysis = cast(Mapping[str, Any], record["analysis"])
    scope = cast(Mapping[str, Any], output["scope"])
    expected_scope = {
        "target_cwe": task["target_cwe"],
        "binary_format": artifact["format"],
        "architecture": artifact["architecture"],
    }
    for key, expected in expected_scope.items():
        if scope.get(key) != expected:
            errors.append(f"scope.{key}: does not match the supplied record")

    functions = {
        str(item["function_id"]): cast(Mapping[str, Any], item)
        for item in cast(list[Mapping[str, Any]], analysis["functions"])
    }
    assessment = str(output["assessment"])
    findings = cast(list[Mapping[str, Any]], output["findings"])
    if assessment in {"present", "not_observed"} and not findings:
        errors.append(
            f"findings: {assessment} assessment requires linked role evidence"
        )
    required_source_roles = (
        {"source", "control", "bound"}
        if assessment == "present"
        else {"control", "bound", "remediation"}
    )
    relationship_by_role = {
        "source": "flows_to",
        "control": "constrains",
        "bound": "bounds",
        "remediation": "remediates",
    }
    for finding_index, finding in enumerate(findings):
        prefix = f"findings.{finding_index}"
        function_id = str(finding["function_id"])
        function = functions.get(function_id)
        if function is None:
            errors.append(f"{prefix}.function_id: not present in supplied evidence")
            continue
        representation = str(finding["representation"])
        evidence = cast(list[Mapping[str, Any]], finding["evidence"])
        by_id: dict[str, Mapping[str, Any]] = {}
        for evidence_index, item in enumerate(evidence):
            evidence_id = str(item["evidence_id"])
            if evidence_id in by_id:
                errors.append(
                    f"{prefix}.evidence.{evidence_index}.evidence_id: duplicate"
                )
            by_id[evidence_id] = item
            code_span = str(item["code_span"])
            if not _evidence_span_is_grounded(
                code_span,
                function,
                representation=representation,
            ):
                errors.append(
                    f"{prefix}.evidence.{evidence_index}.code_span: "
                    "not an exact supplied evidence span"
                )
        relations = cast(list[Mapping[str, Any]], finding["relations"])
        linked_source_roles: set[str] = set()
        for relation_index, relation in enumerate(relations):
            relation_prefix = f"{prefix}.relations.{relation_index}"
            from_id = str(relation["from_evidence_id"])
            to_id = str(relation["to_evidence_id"])
            source = by_id.get(from_id)
            target = by_id.get(to_id)
            if source is None:
                errors.append(f"{relation_prefix}.from_evidence_id: unknown")
            if target is None:
                errors.append(f"{relation_prefix}.to_evidence_id: unknown")
            if source is None or target is None:
                continue
            source_role = str(source["role"])
            target_role = str(target["role"])
            relationship = str(relation["relationship"])
            if target_role != "sink":
                errors.append(f"{relation_prefix}: relation must terminate at a sink")
            expected_relationship = relationship_by_role.get(source_role)
            if expected_relationship != relationship:
                errors.append(
                    f"{relation_prefix}.relationship: incompatible with "
                    f"{source_role} role"
                )
            if target_role == "sink" and expected_relationship == relationship:
                linked_source_roles.add(source_role)
        if "sink" not in {str(item["role"]) for item in evidence}:
            errors.append(f"{prefix}.evidence: missing sink role")
        if assessment in {"present", "not_observed"} and not (
            linked_source_roles & required_source_roles
        ):
            errors.append(f"{prefix}.relations: no required role is linked to a sink")
    return errors


def compact_binary_record(
    record: Mapping[str, Any],
    *,
    maximum_assembly_instructions: int = 24,
    maximum_imports: int = 32,
    maximum_strings: int = 16,
) -> dict[str, Any]:
    """Remove non-semantic bulk without tokenizer truncation.

    Pseudo-C statements remain intact apart from decompiler comments and blank
    lines. ELF section inventories and source-bearing symbols are not useful
    target evidence, so the model-facing B1 record omits them while the frozen
    audit pool remains unchanged.
    """
    validate_binary_record(record)
    compacted = deepcopy(dict(record))
    analysis = cast(dict[str, Any], compacted["analysis"])
    functions = cast(list[dict[str, Any]], analysis["functions"])
    for function in functions:
        pseudo_c = _DECOMPILER_BLOCK_COMMENT.sub("", str(function["pseudo_c"]))
        function["pseudo_c"] = "\n".join(
            line.strip() for line in pseudo_c.splitlines() if line.strip()
        )
        function["assembly_evidence"] = list(
            function["assembly_evidence"][:maximum_assembly_instructions]
        )
        features = cast(dict[str, Any], function["static_features"])
        features["imports"] = list(features["imports"][:maximum_imports])
        features["strings"] = list(features["strings"][:maximum_strings])
        features["sections"] = []
        features["symbols"] = []
    warnings = list(analysis["warnings"])
    compaction_warning = (
        "Non-semantic metadata was structurally compacted; tokenizer truncation "
        "was not applied."
    )
    analysis["warnings"] = [compaction_warning, *warnings[:1]]
    validate_binary_record(compacted)
    return compacted


def build_binary_target(record: Mapping[str, Any]) -> dict[str, Any]:
    """Build one code-grounded binary SFT target from a reviewed record."""
    validate_binary_record(record)
    analysis = cast(Mapping[str, Any], record["analysis"])
    task = cast(Mapping[str, Any], record["task"])
    metadata = cast(Mapping[str, Any], record["metadata"])
    assessment = str(metadata["label"])
    function = cast(Mapping[str, Any], cast(list[Any], analysis["functions"])[0])
    if assessment == "present" and not binary_target_relation_visible(
        str(task["target_cwe"]),
        str(function["pseudo_c"]),
    ):
        raise BinaryRecordValidationError(
            f"{task['target_cwe']} has no observable target relation"
        )
    evidence = _select_pseudo_c_evidence(
        str(function["pseudo_c"]),
        target_cwe=str(task["target_cwe"]),
        require_target_operation=assessment == "present",
    )
    return _build_binary_target_from_evidence(record, evidence)


def build_binary_pair_targets(
    present_record: Mapping[str, Any],
    fixed_record: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build contrast-grounded targets from one aligned compiler pair."""
    validate_binary_record(present_record)
    validate_binary_record(fixed_record)
    if present_record["metadata"]["label"] != "present":
        raise BinaryRecordValidationError("first pair record must be present")
    if fixed_record["metadata"]["label"] != "not_observed":
        raise BinaryRecordValidationError("second pair record must be not_observed")
    present_scope = (
        present_record["task"]["target_cwe"],
        present_record["artifact"]["format"],
        present_record["artifact"]["architecture"],
        present_record["artifact"]["compiler"],
        present_record["artifact"]["optimization"],
    )
    fixed_scope = (
        fixed_record["task"]["target_cwe"],
        fixed_record["artifact"]["format"],
        fixed_record["artifact"]["architecture"],
        fixed_record["artifact"]["compiler"],
        fixed_record["artifact"]["optimization"],
    )
    if present_scope != fixed_scope:
        raise BinaryRecordValidationError("binary pair scope or variant mismatch")
    present_function = cast(
        Mapping[str, Any],
        cast(list[Any], present_record["analysis"]["functions"])[0],
    )
    fixed_function = cast(
        Mapping[str, Any],
        cast(list[Any], fixed_record["analysis"]["functions"])[0],
    )
    target_cwe = str(present_record["task"]["target_cwe"])
    present_pseudo = str(present_function["pseudo_c"])
    fixed_pseudo = str(fixed_function["pseudo_c"])
    if not binary_target_relation_visible(target_cwe, present_pseudo):
        raise BinaryRecordValidationError(
            f"{target_cwe} has no observable target relation"
        )
    present_evidence = _select_pseudo_c_evidence(
        present_pseudo,
        target_cwe=target_cwe,
        require_target_operation=True,
        comparison_pseudo_c=fixed_pseudo,
    )
    fixed_evidence = _select_pseudo_c_evidence(
        fixed_pseudo,
        target_cwe=target_cwe,
        require_target_operation=False,
        comparison_pseudo_c=present_pseudo,
        prefer_fixed_controls=True,
    )
    return (
        _build_binary_target_from_evidence(present_record, present_evidence),
        _build_binary_target_from_evidence(fixed_record, fixed_evidence),
    )


def build_binary_pair_role_targets(
    present_record: Mapping[str, Any],
    fixed_record: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build v2 targets whose supporting roles are explicitly linked to a sink.

    The v1 target deliberately remains available for reproduction. This builder
    is stricter: a pair is excluded when the supplied pseudo-C cannot show both
    the target operation and the role needed to justify the scoped assessment.
    """
    (
        target_cwe,
        present_function,
        fixed_function,
    ) = _validate_and_unpack_binary_pair(present_record, fixed_record)
    present_pseudo = str(present_function["pseudo_c"])
    fixed_pseudo = str(fixed_function["pseudo_c"])
    if not binary_target_relation_visible(target_cwe, present_pseudo):
        raise BinaryRecordValidationError(
            f"{target_cwe} has no observable target relation"
        )
    present_roles = _select_role_evidence(
        present_pseudo,
        target_cwe=target_cwe,
        assessment="present",
        comparison_pseudo_c=fixed_pseudo,
    )
    fixed_roles = _select_role_evidence(
        fixed_pseudo,
        target_cwe=target_cwe,
        assessment="not_observed",
        comparison_pseudo_c=present_pseudo,
    )
    return (
        _build_binary_role_target(present_record, present_roles),
        _build_binary_role_target(fixed_record, fixed_roles),
    )


def _validate_and_unpack_binary_pair(
    present_record: Mapping[str, Any],
    fixed_record: Mapping[str, Any],
) -> tuple[str, Mapping[str, Any], Mapping[str, Any]]:
    validate_binary_record(present_record)
    validate_binary_record(fixed_record)
    if present_record["metadata"]["label"] != "present":
        raise BinaryRecordValidationError("first pair record must be present")
    if fixed_record["metadata"]["label"] != "not_observed":
        raise BinaryRecordValidationError("second pair record must be not_observed")
    scope_keys = (
        ("task", "target_cwe"),
        ("artifact", "format"),
        ("artifact", "architecture"),
        ("artifact", "compiler"),
        ("artifact", "optimization"),
    )
    present_scope = tuple(present_record[parent][key] for parent, key in scope_keys)
    fixed_scope = tuple(fixed_record[parent][key] for parent, key in scope_keys)
    if present_scope != fixed_scope:
        raise BinaryRecordValidationError("binary pair scope or variant mismatch")
    present_function = cast(
        Mapping[str, Any],
        cast(list[Any], present_record["analysis"]["functions"])[0],
    )
    fixed_function = cast(
        Mapping[str, Any],
        cast(list[Any], fixed_record["analysis"]["functions"])[0],
    )
    return str(present_record["task"]["target_cwe"]), present_function, fixed_function


def _build_binary_role_target(
    record: Mapping[str, Any],
    role_evidence: Sequence[tuple[str, str]],
) -> dict[str, Any]:
    artifact = cast(Mapping[str, Any], record["artifact"])
    analysis = cast(Mapping[str, Any], record["analysis"])
    task = cast(Mapping[str, Any], record["task"])
    metadata = cast(Mapping[str, Any], record["metadata"])
    function = cast(Mapping[str, Any], cast(list[Any], analysis["functions"])[0])
    counters: dict[str, int] = {}
    evidence: list[dict[str, str]] = []
    sink_id = ""
    for role, code_span in role_evidence:
        counters[role] = counters.get(role, 0) + 1
        evidence_id = f"{role}-{counters[role]}"
        if role == "sink" and not sink_id:
            sink_id = evidence_id
        evidence.append(
            {
                "evidence_id": evidence_id,
                "role": role,
                "code_span": code_span,
                "explanation": _role_explanation(
                    str(task["target_cwe"]),
                    str(metadata["label"]),
                    role,
                ),
            }
        )
    if not sink_id:
        raise BinaryRecordValidationError("role evidence has no sink")
    relationship_by_role = {
        "source": "flows_to",
        "control": "constrains",
        "bound": "bounds",
        "remediation": "remediates",
    }
    relations = [
        {
            "from_evidence_id": item["evidence_id"],
            "to_evidence_id": sink_id,
            "relationship": relationship_by_role[item["role"]],
        }
        for item in evidence
        if item["role"] != "sink"
    ]
    target: dict[str, Any] = {
        "scope": {
            "target_cwe": task["target_cwe"],
            "binary_format": artifact["format"],
            "architecture": artifact["architecture"],
        },
        "assessment": metadata["label"],
        "findings": [
            {
                "function_id": function["function_id"],
                "representation": "pseudo_c",
                "evidence": evidence,
                "relations": relations,
                "confidence": "high",
            }
        ],
        "limitations": [
            "The assessment is limited to the target CWE and supplied function.",
            "Static decompilation may omit runtime context and compiler intent.",
        ],
        "recommendations": [
            "Confirm the scoped result with deterministic binary analysis and "
            "human review."
        ],
    }
    errors = validate_binary_role_output_for_record(target, record)
    if errors:
        raise BinaryRecordValidationError("; ".join(errors))
    return target


def _role_explanation(target_cwe: str, assessment: str, role: str) -> str:
    descriptions = {
        "source": "This supplied operation or value reaches the scoped sink.",
        "control": "This supplied condition constrains the scoped sink.",
        "bound": "This supplied size or index bound is compared with the scoped sink.",
        "remediation": "This supplied operation is the pair-visible remediation.",
        "sink": "This supplied operation is the scoped target-CWE sink.",
    }
    qualifier = (
        "The linked roles expose the target relation."
        if assessment == "present"
        else "The linked control or remediation limits only this target relation."
    )
    return f"{descriptions[role]} {qualifier} Target: {target_cwe}."


def _select_role_evidence(
    pseudo_c: str,
    *,
    target_cwe: str,
    assessment: Literal["present", "not_observed"],
    comparison_pseudo_c: str,
) -> list[tuple[str, str]]:
    statements = _pseudo_c_statements(pseudo_c)
    comparison_statements = set(_pseudo_c_statements(comparison_pseudo_c))
    if not statements:
        raise BinaryRecordValidationError("pseudo-C has no model-visible statements")
    target_pattern = _TARGET_EVIDENCE_PATTERNS.get(target_cwe)
    target_scores = [
        _target_evidence_score(target_cwe, line, target_pattern=target_pattern)
        for line in statements
    ]
    control_scores = [
        (
            _fixed_control_evidence_score(target_cwe, line)
            if line not in comparison_statements
            else 0
        )
        for line in statements
    ]
    sink_index = _role_sink_index(target_cwe, statements, target_scores)
    if sink_index is None:
        raise BinaryRecordValidationError(f"{target_cwe} has no role-linked sink")
    required = _target_specific_role_indices(
        target_cwe,
        statements,
        sink_index=sink_index,
        assessment=assessment,
        comparison_statements=comparison_statements,
        control_scores=control_scores,
    )
    if not required:
        required = _generic_role_indices(
            statements,
            sink_index=sink_index,
            assessment=assessment,
            comparison_statements=comparison_statements,
            control_scores=control_scores,
        )
    if not required:
        raise BinaryRecordValidationError(
            f"{target_cwe} {assessment} has no role linked to its sink"
        )
    role_lines = [(role, statements[index]) for role, index in required]
    role_lines.append(("sink", statements[sink_index]))
    return list(dict.fromkeys(role_lines))


def _pseudo_c_statements(pseudo_c: str) -> list[str]:
    lines = [
        line.strip()
        for line in _DECOMPILER_BLOCK_COMMENT.sub("", pseudo_c).splitlines()
        if line.strip() and line.strip() not in {"{", "}"}
    ]
    return list(
        dict.fromkeys(
            line
            for line in lines
            if line.endswith(";")
            or _SECURITY_OPERATION.search(line)
            or line.startswith(("if (", "for (", "while (", "do {"))
        )
    )


def _role_sink_index(
    target_cwe: str,
    statements: Sequence[str],
    target_scores: Sequence[int],
) -> int | None:
    candidates = [
        index
        for index, score in enumerate(target_scores)
        if score > 0
        and not _looks_like_declaration(statements[index])
        and not statements[index].startswith(("if (", "for (", "while (", "do {"))
    ]
    if target_cwe in {"CWE-121", "CWE-122", "CWE-124", "CWE-126", "CWE-127"}:
        memory = [
            index for index in candidates if _MEMORY_COPY.search(statements[index])
        ]
        if memory:
            candidates = memory
    if target_cwe in {"CWE-194", "CWE-195"}:
        converted_memory = [
            index
            for index in candidates
            if re.search(
                r"(?:memcpy|memmove|strncpy|malloc|calloc|realloc)[^;]*"
                r"\bdata\b",
                statements[index],
                flags=re.IGNORECASE,
            )
        ]
        if converted_memory:
            candidates = converted_memory
    if target_cwe == "CWE-690":
        uses = [
            index
            for index in candidates
            if not (
                _C_ALLOCATOR.search(statements[index])
                or _CPP_ALLOCATOR.search(statements[index])
            )
            and re.search(r"(?:->|\[[^\]]+\]|\*\s*[A-Za-z_])", statements[index])
        ]
        if uses:
            candidates = uses
    if not candidates:
        return None
    return max(candidates, key=lambda index: (target_scores[index], -index))


def _target_specific_role_indices(
    target_cwe: str,
    statements: Sequence[str],
    *,
    sink_index: int,
    assessment: Literal["present", "not_observed"],
    comparison_statements: set[str],
    control_scores: Sequence[int],
) -> list[tuple[str, int]]:
    sink = statements[sink_index]
    if target_cwe in {"CWE-121", "CWE-122"}:
        capacity = _memory_capacity_index(statements, sink)
        if capacity is None:
            return []
        role = "bound" if assessment == "present" else "remediation"
        return [(role, capacity)]
    if target_cwe in {"CWE-124", "CWE-127"}:
        offset = _negative_offset_or_guard_index(
            statements,
            sink,
            require_negative=assessment == "present",
        )
        if offset is None:
            return []
        return [(("bound" if assessment == "present" else "control"), offset)]
    if target_cwe == "CWE-126":
        return _buffer_selection_role_indices(
            statements,
            sink_index=sink_index,
            assessment=assessment,
        )
    if target_cwe == "CWE-134":
        return _format_string_role_indices(
            statements,
            sink_index=sink_index,
            assessment=assessment,
        )
    if target_cwe in {"CWE-190", "CWE-191"}:
        if assessment == "not_observed":
            guard = _numeric_guard_index(statements, statements[sink_index])
            return [("control", guard)] if guard is not None else []
        sources = _numeric_source_indices(
            statements,
            statements[sink_index],
            comparison_statements=comparison_statements,
        )
        return [("source", index) for index in sources]
    if target_cwe in {"CWE-194", "CWE-195"}:
        if assessment == "not_observed":
            controls = [
                index
                for index, score in enumerate(control_scores)
                if score >= 40 and index != sink_index
            ]
            return [("remediation", controls[0])] if controls else []
        sources = _conversion_source_indices(
            statements,
            statements[sink_index],
            comparison_statements=comparison_statements,
        )
        return [("source", index) for index in sources]
    if target_cwe == "CWE-457":
        return _initialization_role_indices(
            statements,
            sink_index=sink_index,
            assessment=assessment,
        )
    if target_cwe == "CWE-690":
        allocator = _linked_allocator_index(statements, sink)
        if allocator is None:
            return []
        if assessment == "present":
            return [("source", allocator)]
        guard = _null_guard_index(statements, sink)
        if guard is None:
            return []
        return [("control", guard), ("remediation", allocator)]
    if assessment == "not_observed":
        controls = [
            index
            for index, score in enumerate(control_scores)
            if score >= 40 and index != sink_index
        ]
        if controls:
            return [("remediation", controls[0])]
    return []


def _generic_role_indices(
    statements: Sequence[str],
    *,
    sink_index: int,
    assessment: Literal["present", "not_observed"],
    comparison_statements: set[str],
    control_scores: Sequence[int],
) -> list[tuple[str, int]]:
    sink_ids = _stable_evidence_identifiers(statements[sink_index])
    candidates: list[tuple[int, int]] = []
    for index, line in enumerate(statements):
        if index == sink_index or _looks_like_declaration(line):
            continue
        overlap = len(sink_ids & _stable_evidence_identifiers(line))
        contrast = int(line not in comparison_statements)
        control = control_scores[index]
        if overlap or control >= 40:
            candidates.append((index, overlap * 20 + contrast * 10 + control))
    if not candidates:
        return []
    index = max(candidates, key=lambda item: (item[1], -item[0]))[0]
    if assessment == "not_observed":
        if control_scores[index] < 40:
            return []
        role = "control" if statements[index].startswith("if (") else "remediation"
    else:
        role = "control" if statements[index].startswith("if (") else "source"
    return [(role, index)]


def _memory_capacity_index(statements: Sequence[str], sink: str) -> int | None:
    call = re.search(r"\b\w+\s*\(\s*([A-Za-z_]\w*)\s*,", sink)
    destination = call.group(1) if call else ""
    if not destination:
        assignment = re.search(r"\b([A-Za-z_]\w*)\s*\[[^\]]+\]\s*=", sink)
        destination = assignment.group(1) if assignment else ""
    if not destination:
        return None
    patterns = (
        re.compile(
            rf"\b{re.escape(destination)}\s*\[\s*(?:0x[0-9a-f]+|\d+)\s*\]",
            flags=re.IGNORECASE,
        ),
        re.compile(
            rf"\b{re.escape(destination)}\b\s*=\s*(?:\([^)]*\)\s*)?"
            r"(?:malloc|calloc|realloc|new\b)[^;]*",
            flags=re.IGNORECASE,
        ),
    )
    return next(
        (
            index
            for index, line in enumerate(statements)
            if any(pattern.search(line) for pattern in patterns)
        ),
        None,
    )


def _negative_offset_or_guard_index(
    statements: Sequence[str],
    sink: str,
    *,
    require_negative: bool,
) -> int | None:
    sink_ids = _stable_evidence_identifiers(sink)
    negative = re.compile(
        r"(?:\+\s*-\s*(?:1|2|4|8)|-\s*(?:1|2|4|8)|0xffffffff)",
        flags=re.IGNORECASE,
    )
    guard = re.compile(r"(?:>=\s*0|>\s*0|<\s*(?:0x[0-9a-f]+|\d+))")
    pattern = negative if require_negative else guard
    return next(
        (
            index
            for index, line in enumerate(statements)
            if pattern.search(line)
            and bool(sink_ids & _stable_evidence_identifiers(line))
        ),
        None,
    )


def _buffer_selection_role_indices(
    statements: Sequence[str],
    *,
    sink_index: int,
    assessment: Literal["present", "not_observed"],
) -> list[tuple[str, int]]:
    sink = statements[sink_index]
    arguments = re.search(
        r"\b(?:memcpy|memmove|strncpy|wcsncpy)\s*\(\s*"
        r"[^,]+,\s*([A-Za-z_]\w*)",
        sink,
        flags=re.IGNORECASE,
    )
    if not arguments:
        return []
    source_variable = arguments.group(1)
    selection = next(
        (
            (index, match.group(1))
            for index, line in enumerate(statements)
            if (
                match := re.search(
                    rf"\b{re.escape(source_variable)}\s*=\s*"
                    r"([A-Za-z_]\w*(?:Buffer)?)\s*;",
                    line,
                    flags=re.IGNORECASE,
                )
            )
        ),
        None,
    )
    if selection is None:
        return []
    selection_index, buffer_name = selection
    capacity_index = next(
        (
            index
            for index, line in enumerate(statements)
            if re.search(
                rf"\b{re.escape(buffer_name)}\s*\[\s*"
                r"(?:0x[0-9a-f]+|\d+)\s*\]",
                line,
                flags=re.IGNORECASE,
            )
        ),
        None,
    )
    if capacity_index is None:
        return []
    selection_role = "source" if assessment == "present" else "remediation"
    return [(selection_role, selection_index), ("bound", capacity_index)]


def _format_string_role_indices(
    statements: Sequence[str],
    *,
    sink_index: int,
    assessment: Literal["present", "not_observed"],
) -> list[tuple[str, int]]:
    sink = statements[sink_index]
    if assessment == "not_observed":
        if re.search(
            r"\b\w*printf\s*\([^;]*,\s*L?\"[^\"\\]*(?:\\.[^\"\\]*)*\"",
            sink,
            flags=re.IGNORECASE,
        ):
            return [("remediation", sink_index)]
        literal_assignment = next(
            (
                index
                for index, line in enumerate(statements)
                if re.search(
                    r"(?:strcpy|strncpy|wcscpy|wcsncpy)\s*\([^;]*"
                    r"L?\"[^\"\\]*(?:\\.[^\"\\]*)*\"",
                    line,
                    flags=re.IGNORECASE,
                )
                and bool(
                    _stable_evidence_identifiers(sink)
                    & _stable_evidence_identifiers(line)
                )
            ),
            None,
        )
        return (
            [("remediation", literal_assignment)]
            if literal_assignment is not None
            else []
        )
    sink_ids = _stable_evidence_identifiers(sink)
    input_index = next(
        (
            index
            for index, line in enumerate(statements)
            if re.search(
                r"(?:fgets|fgetws|recv|read|scanf)\s*\(",
                line,
                flags=re.IGNORECASE,
            )
            and bool(sink_ids & _stable_evidence_identifiers(line))
        ),
        None,
    )
    return [("source", input_index)] if input_index is not None else []


def _numeric_source_indices(
    statements: Sequence[str],
    sink: str,
    *,
    comparison_statements: set[str],
) -> list[int]:
    sink_ids = _stable_evidence_identifiers(sink)
    external = [
        index
        for index, line in enumerate(statements)
        if re.search(
            r"(?:fscanf|scanf|recv|read|fgets|atoi|strto\w*)\s*\(",
            line,
            flags=re.IGNORECASE,
        )
        and bool(sink_ids & _stable_evidence_identifiers(line))
    ]
    if external:
        return external[-2:]
    assignments = [
        index
        for index, line in enumerate(statements)
        if line not in comparison_statements
        and any(
            re.match(rf"^{re.escape(identifier)}\s*=", line) for identifier in sink_ids
        )
        and not re.search(r"=\s*0\s*;", line)
    ]
    return assignments[-1:]


def _numeric_guard_index(statements: Sequence[str], sink: str) -> int | None:
    sink_ids = _stable_evidence_identifiers(sink)
    return next(
        (
            index
            for index, line in enumerate(statements)
            if line.startswith("if (")
            and re.search(r"(?:<|>|<=|>=|==|!=)", line)
            and bool(sink_ids & _stable_evidence_identifiers(line))
        ),
        None,
    )


def _conversion_source_indices(
    statements: Sequence[str],
    sink: str,
    *,
    comparison_statements: set[str],
) -> list[int]:
    sink_ids = _stable_evidence_identifiers(sink)
    conversions = [
        index
        for index, line in enumerate(statements)
        if line not in comparison_statements
        and bool(sink_ids & _stable_evidence_identifiers(line))
        and (
            re.search(
                r"=\s*\((?:u?char|u?short|u?int|u?long|size_t)\)",
                line,
                flags=re.IGNORECASE,
            )
            or re.search(
                r"^(?:data|size|length)\s*=\s*-\s*(?:0x[0-9a-f]+|\d+)",
                line,
                flags=re.IGNORECASE,
            )
            or re.search(
                r"(?:fscanf|scanf|recv|read|atoi|strto\w*)\s*\(",
                line,
                flags=re.IGNORECASE,
            )
        )
    ]
    return conversions[-2:]


def _initialization_role_indices(
    statements: Sequence[str],
    *,
    sink_index: int,
    assessment: Literal["present", "not_observed"],
) -> list[tuple[str, int]]:
    sink_ids = _stable_evidence_identifiers(statements[sink_index])
    writes = [
        index
        for index, line in enumerate(statements)
        if index != sink_index
        and "=" in line
        and bool(sink_ids & _stable_evidence_identifiers(line.split("=", 1)[0]))
    ]
    loops = [
        index
        for index, line in enumerate(statements)
        if line.startswith(("for (", "while ("))
    ]
    if not writes:
        return []
    write_loop = next(
        (index for index in reversed(loops) if index < writes[0]),
        None,
    )
    read_loop = next(
        (index for index in reversed(loops) if index < sink_index),
        None,
    )
    if write_loop is None or read_loop is None or write_loop == read_loop:
        return []
    roles: list[tuple[str, int]] = [("source", writes[0])]
    roles.extend(("bound", index) for index in (write_loop, read_loop))
    if assessment == "not_observed":
        roles[0] = ("remediation", writes[0])
    return roles


def _linked_allocator_index(statements: Sequence[str], sink: str) -> int | None:
    sink_ids = _stable_evidence_identifiers(sink)
    return next(
        (
            index
            for index, line in enumerate(statements)
            if (_C_ALLOCATOR.search(line) or _CPP_ALLOCATOR.search(line))
            and bool(sink_ids & _stable_evidence_identifiers(line))
        ),
        None,
    )


def _null_guard_index(statements: Sequence[str], sink: str) -> int | None:
    sink_ids = _stable_evidence_identifiers(sink)
    return next(
        (
            index
            for index, line in enumerate(statements)
            if line.startswith("if (")
            and re.search(r"(?:==|!=)\s*(?:NULL|0)\b", line, flags=re.IGNORECASE)
            and bool(sink_ids & _stable_evidence_identifiers(line))
        ),
        None,
    )


def _build_binary_target_from_evidence(
    record: Mapping[str, Any],
    evidence: Sequence[str],
) -> dict[str, Any]:
    artifact = cast(Mapping[str, Any], record["artifact"])
    analysis = cast(Mapping[str, Any], record["analysis"])
    task = cast(Mapping[str, Any], record["task"])
    metadata = cast(Mapping[str, Any], record["metadata"])
    assessment = str(metadata["label"])
    function = cast(Mapping[str, Any], cast(list[Any], analysis["functions"])[0])
    observation = "Observed supplied pseudo-C: " + "; ".join(
        f"`{line}`" for line in evidence
    )
    if assessment == "not_observed":
        observation += (
            ". Within the supplied function, this does not establish the target "
            "CWE relation."
        )
    target: dict[str, Any] = {
        "scope": {
            "target_cwe": task["target_cwe"],
            "binary_format": artifact["format"],
            "architecture": artifact["architecture"],
        },
        "assessment": assessment,
        "findings": [
            {
                "function_id": function["function_id"],
                "representation": "pseudo_c",
                "observation": observation,
                "confidence": "high",
            }
        ],
        "limitations": [
            "The assessment is limited to the target CWE and supplied function.",
            "Static decompilation may omit runtime context and compiler intent.",
        ],
        "recommendations": [
            "Confirm the scoped result with deterministic binary analysis and "
            "human review."
        ],
    }
    errors = validate_binary_output_for_record(target, record)
    if errors:
        raise BinaryRecordValidationError("; ".join(errors))
    return target


def binary_target_relation_visible(target_cwe: str, pseudo_c: str) -> bool:
    """Return whether pseudo-C exposes a conservative target-specific relation."""
    text = _DECOMPILER_BLOCK_COMMENT.sub("", pseudo_c)
    if target_cwe in {"CWE-23", "CWE-36"}:
        return bool(
            re.search(
                r"(?:fopen|open\s*\(|remove\s*\(|rename\s*\(|realpath)",
                text,
                flags=re.IGNORECASE,
            )
        )
    if target_cwe == "CWE-78":
        return bool(
            re.search(
                r"(?:system|popen|exec\w*|winexec|createprocess)\s*\(",
                text,
                flags=re.IGNORECASE,
            )
        )
    if target_cwe == "CWE-120":
        return bool(_MEMORY_COPY.search(text))
    if target_cwe == "CWE-121":
        return bool(
            _MEMORY_COPY.search(text)
            and re.search(
                r"(?:char|wchar_t|int|struct|double|float)\s+"
                r"\w+\s*\[\s*\d+\s*\]",
                text,
                flags=re.IGNORECASE,
            )
        )
    if target_cwe == "CWE-122":
        return bool(
            _MEMORY_COPY.search(text)
            and (_C_ALLOCATOR.search(text) or _CPP_ALLOCATOR.search(text))
        )
    if target_cwe == "CWE-124":
        return bool(
            (
                _MEMORY_COPY.search(text)
                and re.search(
                    r"(?:\+\s*-\s*(?:1|2|4|8)|-\s*(?:1|2|4|8)|"
                    r"0xffffffff)",
                    text,
                    flags=re.IGNORECASE,
                )
            )
            or (
                re.search(r"\b\w+\s*<\s*\d+", text)
                and re.search(
                    r"\[[^\]]*[A-Za-z_]\w*[^\]]*\]\s*=",
                    text,
                )
            )
        )
    if target_cwe == "CWE-126":
        return bool(
            _MEMORY_COPY.search(text)
            or re.search(
                r"(?:print\w*Line|fwrite|send)\s*\(",
                text,
                flags=re.IGNORECASE,
            )
            or re.search(
                r"\w+\s*\[[^\]]+\]\s*=\s*\w+\s*\[[^\]]+\]",
                text,
                flags=re.IGNORECASE,
            )
        )
    if target_cwe == "CWE-127":
        return bool(
            (
                _MEMORY_COPY.search(text)
                or re.search(r"print\w*Line\s*\(", text, flags=re.IGNORECASE)
            )
            and re.search(
                r"(?:\+\s*-\s*(?:1|2|4|8)|-\s*(?:1|2|4|8)|"
                r"0xffffffff|buffer\s*\[\s*data\s*\])",
                text,
                flags=re.IGNORECASE,
            )
        )
    if target_cwe == "CWE-134":
        return bool(
            re.search(
                r"\b(?:\w*printf|syslog)\s*\(",
                text,
                flags=re.IGNORECASE,
            )
        )
    if target_cwe == "CWE-190":
        return bool(
            re.search(
                r"\b(?:result|data)\b[^;]*(?:\+|\*|<<)[^;]*;",
                text,
                flags=re.IGNORECASE,
            )
        )
    if target_cwe == "CWE-191":
        return bool(
            re.search(
                r"\b(?:result|data)\b[^;]*(?:--|\+\s*-\s*1|-\s*1)[^;]*;",
                text,
                flags=re.IGNORECASE,
            )
        )
    if target_cwe in {"CWE-194", "CWE-195", "CWE-197"}:
        return bool(
            re.search(
                r"\bdata\b[^;]*(?:\(?"
                r"(?:char|short|int|long)\)?|SUB\d+|CONCAT\d+)",
                text,
                flags=re.IGNORECASE,
            )
            or (
                target_cwe == "CWE-195"
                and re.search(
                    r"(?:malloc|calloc|realloc|memcpy|memmove)"
                    r"[^;]*\((?:u?int|u?long|u?short|u?char|size_t)"
                    r"\)[^;]*\bdata\b",
                    text,
                    flags=re.IGNORECASE,
                )
            )
        )
    if target_cwe == "CWE-369":
        return bool(
            re.search(
                r"\b(?:result|data)\b[^;]*(?:/|%)[^;]*;",
                text,
                flags=re.IGNORECASE,
            )
        )
    if target_cwe == "CWE-400":
        return bool(
            re.search(
                r"(?:while\s*\(|for\s*\(|malloc|calloc|new|u?sleep|socket|"
                r"connect|accept)",
                text,
                flags=re.IGNORECASE,
            )
        )
    if target_cwe == "CWE-401":
        return bool(
            (_C_ALLOCATOR.search(text) or _CPP_ALLOCATOR.search(text))
            and not (_C_DEALLOCATOR.search(text) or _CPP_DEALLOCATOR.search(text))
        )
    if target_cwe == "CWE-404":
        return bool(
            re.search(r"(?:fopen|open\s*\()", text, flags=re.IGNORECASE)
            and re.search(r"(?:fclose|close\s*\()", text, flags=re.IGNORECASE)
        )
    if target_cwe == "CWE-427":
        return bool(
            re.search(
                r"(?:system|popen|execl|execv|loadlibrary|createprocess)",
                text,
                flags=re.IGNORECASE,
            )
        )
    if target_cwe == "CWE-457":
        return bool(
            re.search(
                r"\b(?:print\w*Line|printf)\s*\([^;]*(?:\*?data|dataUninit)",
                text,
                flags=re.IGNORECASE,
            )
            or (
                (_C_ALLOCATOR.search(text) or _CPP_ALLOCATOR.search(text))
                and re.search(
                    r"print\w*Line\s*\([^;]*(?:\*|\+\s*\(long\)|\[)",
                    text,
                    flags=re.IGNORECASE,
                )
            )
        )
    if target_cwe == "CWE-464":
        return bool(
            re.search(
                r"(?:memset|memcpy|strcpy|strncpy|\[[^\]]+\]\s*=)",
                text,
                flags=re.IGNORECASE,
            )
        )
    if target_cwe == "CWE-588":
        return bool(
            re.search(
                r"(?:printStructLine|->|\*\s*\([A-Za-z_].*\))",
                text,
                flags=re.IGNORECASE,
            )
        )
    if target_cwe == "CWE-590":
        return bool(
            (_C_DEALLOCATOR.search(text) or _CPP_DEALLOCATOR.search(text))
            and re.search(r"(?:local_|\[[^\]]+\]|&)", text)
        )
    if target_cwe == "CWE-606":
        return bool(
            re.search(r"(?:while\s*\(|for\s*\()", text)
            and re.search(
                r"(?:fgets|scanf|recv|data)",
                text,
                flags=re.IGNORECASE,
            )
        )
    if target_cwe == "CWE-617":
        return bool(
            re.search(
                r"(?:assert|abort|__assert_fail)",
                text,
                flags=re.IGNORECASE,
            )
        )
    if target_cwe == "CWE-665":
        return bool(
            re.search(
                r"(?:memcpy|memmove|strcpy|strncpy|print\w*Line|printf)",
                text,
                flags=re.IGNORECASE,
            )
        )
    if target_cwe == "CWE-672":
        return bool(
            (_C_DEALLOCATOR.search(text) or _CPP_DEALLOCATOR.search(text))
            and re.search(
                r"(?:print|->|\*\s*[A-Za-z_])",
                text,
                flags=re.IGNORECASE,
            )
        )
    if target_cwe == "CWE-680":
        return bool(
            re.search(
                r"\b(?:data|result)\b[^;]*(?:\*|<<)[^;]*;",
                text,
                flags=re.IGNORECASE,
            )
            and re.search(
                r"(?:malloc|calloc|memset|memcpy)",
                text,
                flags=re.IGNORECASE,
            )
        )
    if target_cwe == "CWE-690":
        return bool(
            (_C_ALLOCATOR.search(text) or _CPP_ALLOCATOR.search(text))
            and re.search(r"(?:->|\*\s*[A-Za-z_]|\[[^\]]+\]\s*=)", text)
        )
    if target_cwe == "CWE-761":
        return bool(
            (_C_DEALLOCATOR.search(text) or _CPP_DEALLOCATOR.search(text))
            and re.search(r"(?:\+\+|--|\+=|-=)", text)
        )
    if target_cwe == "CWE-762":
        return bool(
            (_C_ALLOCATOR.search(text) and _CPP_DEALLOCATOR.search(text))
            or (_CPP_ALLOCATOR.search(text) and _C_DEALLOCATOR.search(text))
        )
    if target_cwe in {"CWE-773", "CWE-775"}:
        return bool(
            re.search(
                r"(?:fopen|open\s*\(|socket)",
                text,
                flags=re.IGNORECASE,
            )
        )
    if target_cwe == "CWE-789":
        return bool(
            (_C_ALLOCATOR.search(text) or _CPP_ALLOCATOR.search(text))
            and re.search(
                r"(?:rand|scanf|fgets|recv|strtoul|atoi|input|data)",
                text,
                flags=re.IGNORECASE,
            )
        )
    pattern = _TARGET_EVIDENCE_PATTERNS.get(target_cwe)
    return bool(pattern and pattern.search(text))


def format_binary_prompt(
    record: Mapping[str, Any],
) -> list[BinaryPromptMessage]:
    """Format model-visible evidence while withholding labels and provenance."""
    validate_binary_record(record)
    artifact = cast(Mapping[str, Any], record["artifact"])
    analysis = cast(Mapping[str, Any], record["analysis"])
    task = cast(Mapping[str, Any], record["task"])
    visible = {
        "scope": {
            "target_cwe": task["target_cwe"],
            "binary_format": artifact["format"],
            "architecture": artifact["architecture"],
            "compiler": artifact["compiler"],
            "optimization": artifact["optimization"],
            "stripped": artifact["stripped"],
        },
        "functions": analysis["functions"],
        "extraction_warnings": analysis["warnings"],
    }
    return [
        {"role": "system", "content": BINARY_SYSTEM_PROMPT},
        {
            "role": "user",
            "content": "\n\n".join(
                [
                    "Assess the target CWE using only the normalized binary evidence.",
                    json.dumps(visible, ensure_ascii=False, indent=2, sort_keys=True),
                    "Return only the required binary assessment JSON object.",
                ]
            ),
        },
    ]


def format_binary_role_prompt(
    record: Mapping[str, Any],
) -> list[BinaryPromptMessage]:
    """Format the same withheld record with the v2 role-output instructions."""
    messages = format_binary_prompt(record)
    messages[0] = {"role": "system", "content": BINARY_ROLE_SYSTEM_PROMPT}
    messages[1] = {
        "role": "user",
        "content": messages[1]["content"].replace(
            "required binary assessment JSON object",
            "required role-structured binary assessment JSON object",
        ),
    }
    return messages


def _find_forbidden_payload_keys(
    value: Any,
    *,
    prefix: str = "",
) -> list[str]:
    paths: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            name = str(key)
            path = f"{prefix}.{name}" if prefix else name
            if name.lower() in _FORBIDDEN_PAYLOAD_KEYS:
                paths.append(path)
            paths.extend(_find_forbidden_payload_keys(item, prefix=path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            paths.extend(
                _find_forbidden_payload_keys(item, prefix=f"{prefix}[{index}]")
            )
    return paths


def _select_pseudo_c_evidence(
    pseudo_c: str,
    *,
    target_cwe: str,
    require_target_operation: bool,
    maximum_lines: int = 4,
    comparison_pseudo_c: str | None = None,
    prefer_fixed_controls: bool = False,
) -> list[str]:
    lines = [
        line.strip()
        for line in pseudo_c.splitlines()
        if line.strip()
        and line.strip() not in {"{", "}"}
        and not line.strip().startswith("/*")
    ]
    statements = list(
        dict.fromkeys(
            line
            for line in lines
            if line.endswith(";")
            or _SECURITY_OPERATION.search(line)
            or line.startswith(("if (", "for (", "while ("))
        )
    )
    target_pattern = _TARGET_EVIDENCE_PATTERNS.get(target_cwe)
    base_scores = [
        _target_evidence_score(target_cwe, line, target_pattern=target_pattern)
        for line in statements
    ]
    comparison_statements = (
        {
            line.strip()
            for line in comparison_pseudo_c.splitlines()
            if line.strip() and line.strip() not in {"{", "}"}
        }
        if comparison_pseudo_c is not None
        else set()
    )
    scores = []
    fixed_control_scores: list[int] = []
    for line, base_score in zip(statements, base_scores, strict=True):
        score = base_score
        if score > 0 and line not in comparison_statements:
            score += 12
        fixed_control_score = 0
        if prefer_fixed_controls and line not in comparison_statements:
            fixed_control_score = _fixed_control_evidence_score(target_cwe, line)
            score = max(score, fixed_control_score)
        scores.append(score)
        fixed_control_scores.append(fixed_control_score)
    required_target_score = {
        "CWE-121": 28,
        "CWE-122": 28,
        "CWE-124": 28,
        "CWE-126": 28,
        "CWE-127": 28,
    }.get(target_cwe, 10)
    if require_target_operation and max(base_scores, default=0) < required_target_score:
        raise BinaryRecordValidationError(
            f"{target_cwe} has no target-specific pseudo-C operation"
        )
    ranked = sorted(
        (
            (index, line)
            for index, line in enumerate(statements)
            if not require_target_operation or scores[index] > 0
        ),
        key=lambda item: (
            -scores[item[0]],
            not bool(_SECURITY_OPERATION.search(item[1])),
            item[0],
        ),
    )
    if prefer_fixed_controls:
        required_role_indices = _fixed_pair_role_evidence_indices(
            target_cwe,
            statements,
            comparison_statements=comparison_statements,
            base_scores=base_scores,
            fixed_control_scores=fixed_control_scores,
        )
        if not required_role_indices:
            raise BinaryRecordValidationError(
                f"{target_cwe} fixed pair has no observable remediation evidence"
            )
        fixed_ranked = sorted(
            (
                (index, line)
                for index, line in enumerate(statements)
                if fixed_control_scores[index] >= 40
            ),
            key=lambda item: (-fixed_control_scores[item[0]], item[0]),
        )
        selected = [statements[index] for index in required_role_indices]
        selected.extend(
            line
            for _, line in fixed_ranked
            if line not in selected and len(selected) < maximum_lines
        )
        if not selected:
            selected = [line for _, line in ranked[:maximum_lines]]
    else:
        selected = [line for _, line in ranked[:maximum_lines]]
    if not selected:
        selected = lines[:1]
    if not selected:
        raise BinaryRecordValidationError("pseudo-C has no model-visible evidence")
    return selected


def _target_evidence_score(
    target_cwe: str,
    line: str,
    *,
    target_pattern: re.Pattern[str] | None,
) -> int:
    declaration = _looks_like_declaration(line)
    if target_pattern is None or not target_pattern.search(line):
        if target_cwe in {"CWE-124", "CWE-127"} and re.search(
            r"\bdata\s*(?:>=|>)\s*0|\bdata\s*<\s*\d+",
            line,
            flags=re.IGNORECASE,
        ):
            return 18
        return 0

    lowered = line.lower()
    memory_copy = _MEMORY_COPY.search(line)
    variable_index = re.search(
        r"\[[^\]]*[a-z_][a-z0-9_]*[^\]]*\]",
        line,
        flags=re.IGNORECASE,
    )
    constant_index = re.search(r"\[\s*(?:0x[0-9a-f]+|\d+)\s*\]", line)
    negative_offset = re.search(
        r"(?:\+\s*-\s*(?:1|2|4|8)|-\s*(?:1|2|4|8)|0xffffffff)",
        line,
        flags=re.IGNORECASE,
    )

    if target_cwe in {"CWE-121", "CWE-122"}:
        if memory_copy:
            return 30
        if re.search(r"\bw?memset\s*\(", line, flags=re.IGNORECASE):
            return 28
        if variable_index:
            return 20
        return 4 if constant_index else 10
    if target_cwe == "CWE-126":
        if re.search(r"\bdata\s*=\s*dataBadBuffer\s*;", line, flags=re.IGNORECASE):
            return 36
        if re.search(
            r"\w+\s*\[[^\]]+\]\s*=\s*data\s*\[[^\]]+\]",
            line,
            flags=re.IGNORECASE,
        ):
            return 34
        if re.search(
            r"\w+\s*\[[^\]]+\]\s*=\s*\*\s*\([^;]+\)",
            line,
            flags=re.IGNORECASE,
        ):
            return 34
        if memory_copy:
            return 30
        return 8 if constant_index else 18
    if target_cwe in {"CWE-124", "CWE-127"}:
        if negative_offset and re.search(
            r"\bdata\b|[A-Za-z_]\w*\s*=\s*[A-Za-z_]\w*",
            line,
            flags=re.IGNORECASE,
        ):
            return 35
        if memory_copy and negative_offset:
            return 35
        if variable_index:
            return 28
        if memory_copy:
            return 16
        return 3 if constant_index else 10
    if target_cwe in {"CWE-23", "CWE-36"}:
        if re.search(
            r"(?:fopen|open|remove|rename|realpath)\s*\(",
            line,
            flags=re.IGNORECASE,
        ):
            return 35
        if re.search(
            r"(?:fgets|recv|read|getenv)\s*\(",
            line,
            flags=re.IGNORECASE,
        ):
            return 32
        if re.search(r"(?:strcat|strncat)\s*\(", line, flags=re.IGNORECASE):
            return 28
        return 0
    if target_cwe == "CWE-190":
        return (
            32
            if not declaration
            and re.search(r"\b(?:data|result)\b|print\w*line", lowered)
            and re.search(r"(?:\+|\*|<<)", line)
            else 0
        )
    if target_cwe == "CWE-191":
        return (
            32
            if re.search(r"\b(?:data|result)\b|print\w*line", lowered)
            and re.search(r"(?:--|-\s*\d|\+\s*-\s*\d)", line)
            else 0
        )
    if target_cwe in {"CWE-194", "CWE-195", "CWE-197"}:
        if declaration:
            return 0
        if target_cwe == "CWE-195" and re.search(
            r"(?:malloc|calloc|realloc|memcpy|memmove)[^;]*\bdata\b",
            line,
            flags=re.IGNORECASE,
        ):
            return 35
        if re.search(
            r"(?:\((?:u?int|u?long|u?short|u?char|size_t)\)|SUB\d+|CONCAT\d+)",
            line,
            flags=re.IGNORECASE,
        ):
            return 30
        return 0
    if target_cwe == "CWE-134":
        return 32
    if target_cwe == "CWE-400":
        if re.search(r"(?:u?sleep|while\s*\(|for\s*\()", line, re.IGNORECASE):
            return 34
        if re.search(r"(?:recv|fgets|scanf|atoi)\s*\(", line, re.IGNORECASE):
            return 30
        if re.search(
            r"(?:socket|connect|accept|malloc|calloc|new)\b",
            line,
            re.IGNORECASE,
        ):
            return 24
        return 0
    if target_cwe == "CWE-789":
        if _C_ALLOCATOR.search(line) or _CPP_ALLOCATOR.search(line):
            return 36
        if re.search(
            r"(?:recv|fgets|scanf|strtoul|atoi)\s*\(",
            line,
            flags=re.IGNORECASE,
        ):
            return 32
        return 0
    if target_cwe == "CWE-401":
        return 30
    if target_cwe == "CWE-457":
        if declaration:
            return 0
        return (
            32
            if re.search(
                r"(?:print\w*line|\w*printf|memcpy|memmove)\s*\(",
                line,
                flags=re.IGNORECASE,
            )
            else 18
            if re.search(r"(?:\*\s*[A-Za-z_]|\[[^\]]+\])", line)
            else 0
        )
    if target_cwe == "CWE-588":
        if declaration:
            return 0
        return (
            32
            if re.search(r"(?:printStructLine|->)", line, flags=re.IGNORECASE)
            else 20
            if re.search(r"\*\s*\([A-Za-z_]", line)
            else 0
        )
    if target_cwe == "CWE-672":
        if _C_DEALLOCATOR.search(line) or _CPP_DEALLOCATOR.search(line):
            return 35
        if declaration:
            return 0
        return (
            28
            if re.search(
                r"(?:print\w*line|\w*printf|->|\[[^\]]+\]|\*\s*[A-Za-z_])",
                line,
                flags=re.IGNORECASE,
            )
            else 0
        )
    if target_cwe == "CWE-680":
        if declaration:
            return 0
        if re.search(r"\b(?:data|result)\b", line, flags=re.IGNORECASE) and re.search(
            r"(?:\*|<<)", line
        ):
            return 34
        if _C_ALLOCATOR.search(line) or _CPP_ALLOCATOR.search(line):
            return 24
        return 0
    if target_cwe == "CWE-690":
        if _C_ALLOCATOR.search(line) or _CPP_ALLOCATOR.search(line):
            return 34
        if declaration:
            return 0
        return 26 if re.search(r"(?:->|\[[^\]]+\]\s*=|\*\s*[A-Za-z_])", line) else 0
    if target_cwe == "CWE-762":
        return 30
    return 20


def _fixed_control_evidence_score(target_cwe: str, line: str) -> int:
    """Score pair-unique operations that justify a scoped not-observed label."""
    if _looks_like_declaration(line):
        return 0
    if target_cwe in {"CWE-23", "CWE-36"}:
        if re.search(
            r"(?:strcpy|strncpy|strcat|strncat|wcscpy|wcsncpy|"
            r"wcscat|wcsncat|builtin_w?csncpy)"
            r"\s*\([^;]*\"[^\"\\]*(?:\\.[^\"\\]*)*\"",
            line,
            flags=re.IGNORECASE,
        ):
            return 46
        if re.search(r"(?:realpath|canonical)", line, flags=re.IGNORECASE):
            return 44
    if target_cwe in {"CWE-124", "CWE-127"}:
        if re.search(
            r"\bdata\s*=\s*(?:dataBuffer|dataGoodBuffer|\w*Good\w*)\s*;",
            line,
            flags=re.IGNORECASE,
        ):
            return 48
        if (_C_ALLOCATOR.search(line) or _CPP_ALLOCATOR.search(line)) and re.search(
            r"(?:0x[0-9a-f]+|\d+)", line, flags=re.IGNORECASE
        ):
            return 44
        if line.startswith("if (") and re.search(
            r"(?:>=\s*0|>\s*0|<\s*(?:0x[0-9a-f]+|\d+))",
            line,
            flags=re.IGNORECASE,
        ):
            return 46
    if target_cwe in {"CWE-121", "CWE-122"}:
        if _MEMORY_COPY.search(line) and re.search(
            r"\bsizeof\s*\(", line, flags=re.IGNORECASE
        ):
            return 48
        if re.search(
            r"\bw?memset\s*\([^;]*(?:0x[0-9a-f]+|\d+)\s*\)",
            line,
            flags=re.IGNORECASE,
        ):
            return 46
        if (_C_ALLOCATOR.search(line) or _CPP_ALLOCATOR.search(line)) and re.search(
            r"(?:0x[0-9a-f]+|\d+)", line, flags=re.IGNORECASE
        ):
            return 44
    if target_cwe in {"CWE-126", "CWE-127"} and re.search(
        r"\bdata\s*=\s*(?:dataGoodBuffer|\w*Good\w*)\s*;",
        line,
        flags=re.IGNORECASE,
    ):
        return 48
    if target_cwe == "CWE-400":
        if line.startswith("if (") and re.search(
            r"(?:count|size|length|data).*(?:<|>|<=|>=)",
            line,
            flags=re.IGNORECASE,
        ):
            return 46
        if re.search(
            r"\b(?:count|size|length|data)\s*=\s*(?:0x[0-9a-f]+|\d+)\s*;",
            line,
            flags=re.IGNORECASE,
        ):
            return 42
    if target_cwe == "CWE-78":
        if re.search(
            r"\b(?:data|data_buf|dataBuffer)(?:\._\w+)?\s*=\s*"
            r"(?:__?LC\w*|_UNK_\w+|L?\"[^\"\\]*(?:\\.[^\"\\]*)*\")\s*;",
            line,
            flags=re.IGNORECASE,
        ):
            return 48
        if re.search(
            r"(?:strcpy|strncpy|wcscpy|wcsncpy|wcscat|strcat)"
            r"\s*\([^;]*(?:__?LC\w*|L?\"[^\"\\]*(?:\\.[^\"\\]*)*\")",
            line,
            flags=re.IGNORECASE,
        ):
            return 44
    if target_cwe == "CWE-401" and (
        _C_DEALLOCATOR.search(line) or _CPP_DEALLOCATOR.search(line)
    ):
        return 48
    if target_cwe in {"CWE-194", "CWE-195", "CWE-197"}:
        if re.search(
            r"\bdata\s*=\s*(?:0x[0-9a-f]+|\d+)\s*;",
            line,
            flags=re.IGNORECASE,
        ):
            return 46
        if line.startswith("if (") and re.search(
            r"\bdata\b.*(?:>=\s*0|>\s*0|<\s*\d+)",
            line,
            flags=re.IGNORECASE,
        ):
            return 42
    if target_cwe == "CWE-134":
        if re.search(
            r"\b\w*printf\s*\([^;]*\"(?:%s|%ls)\"",
            line,
            flags=re.IGNORECASE,
        ):
            return 48
        if re.search(
            r"(?:strcpy|strncpy|wcscpy|wcsncpy)\s*\([^;]*"
            r"\"[^\"\\]*(?:\\.[^\"\\]*)*\"",
            line,
            flags=re.IGNORECASE,
        ):
            return 44
    if target_cwe == "CWE-457" and re.search(
        r"\bdata\s*=\s*(?:L?\"|0x[0-9a-f]+|\d+|malloc|calloc|new\b)",
        line,
        flags=re.IGNORECASE,
    ):
        return 46
    if target_cwe == "CWE-457" and re.search(
        r"\*\s*[A-Za-z_]\w*\s*=\s*(?:_LC\w*|_LCPI\w*|"
        r"0x[0-9a-f]+|\d+|L?\"[^\"\\]*(?:\\.[^\"\\]*)*\")\s*;",
        line,
        flags=re.IGNORECASE,
    ):
        return 48
    if target_cwe == "CWE-457" and re.search(
        r"(?:\w+\s*\[[^\]]+\]\s*\.\s*\w+|\w+\s*\[[^\]]+\])"
        r"\s*=\s*(?:\w+|0x[0-9a-f]+|\d+)\s*;",
        line,
        flags=re.IGNORECASE,
    ):
        return 46
    if target_cwe == "CWE-457" and re.search(
        r"^\*\s*\([^=]+\)\s*=\s*(?:\([^)]+\))?\s*"
        r"(?:\w+|0x[0-9a-f]+|\d+)\s*;",
        line,
        flags=re.IGNORECASE,
    ):
        return 48
    if target_cwe in {"CWE-590", "CWE-762"} and (
        _C_ALLOCATOR.search(line)
        or _CPP_ALLOCATOR.search(line)
        or _C_DEALLOCATOR.search(line)
        or _CPP_DEALLOCATOR.search(line)
    ):
        return 46
    if target_cwe in {"CWE-190", "CWE-191", "CWE-680"}:
        if line.startswith("if (") and re.search(
            r"\b(?:data|result)\b.*(?:<|>|==|!=)",
            line,
            flags=re.IGNORECASE,
        ):
            return 46
    if (
        target_cwe == "CWE-606"
        and line.startswith("if (")
        and re.search(
            r"\b(?:n|count|data)\b.*(?:<|>|<=|>=)\s*(?:0x[0-9a-f]+|\d+)",
            line,
            flags=re.IGNORECASE,
        )
    ):
        return 46
    if target_cwe == "CWE-789":
        if line.startswith("if (") and re.search(
            r"(?:99|100|0x64).*(?:<|>)|(?:<|>).*?(?:99|100|0x64)",
            line,
            flags=re.IGNORECASE,
        ):
            return 48
        if (_C_ALLOCATOR.search(line) or _CPP_ALLOCATOR.search(line)) and re.search(
            r"(?:0x[0-9a-f]+|\d+)", line, flags=re.IGNORECASE
        ):
            return 42
    if target_cwe in {"CWE-404", "CWE-775"} and re.search(
        r"(?:fclose|close)\s*\(", line, flags=re.IGNORECASE
    ):
        return 46
    if target_cwe in {"CWE-590", "CWE-672", "CWE-761", "CWE-762"} and re.search(
        r"(?:free|delete|operator_delete)\b", line, flags=re.IGNORECASE
    ):
        return 42
    if line.startswith("if (") and re.search(r"(?:<|>|==|!=|<=|>=)", line):
        return 24
    if re.search(
        r"=\s*(?:0x[0-9a-f]+|\d+|L?\"[^\"\\]*(?:\\.[^\"\\]*)*\")\s*;",
        line,
        flags=re.IGNORECASE,
    ):
        return 18
    return 0


def _bounded_memory_control_indices(statements: Sequence[str]) -> list[int]:
    """Find a visible destination-capacity and bounded-copy relationship."""
    buffers: dict[str, tuple[int, int]] = {}
    empty_buffers: dict[str, int] = {}
    for index, line in enumerate(statements):
        declaration = re.match(
            r"^(?:char|wchar_t|undefined\d*)\s+([A-Za-z_]\w*)\s*"
            r"\[\s*(0x[0-9a-f]+|\d+)\s*\]\s*;$",
            line,
            flags=re.IGNORECASE,
        )
        if declaration:
            buffers[declaration.group(1)] = (
                int(declaration.group(2), 0),
                index,
            )
        emptied = re.match(
            r"^([A-Za-z_]\w*)\s*\[\s*0\s*\]\s*=\s*(?:L)?'\\0'\s*;$",
            line,
            flags=re.IGNORECASE,
        )
        if emptied:
            empty_buffers[emptied.group(1)] = index

    for sink_index, line in enumerate(statements):
        bounded = re.search(
            r"\b(memcpy|memmove|strncpy|wcsncpy|strncat|wcsncat)\s*\(\s*"
            r"([A-Za-z_]\w*)\s*,[^,]+,\s*(0x[0-9a-f]+|\d+)\s*\)",
            line,
            flags=re.IGNORECASE,
        )
        if not bounded:
            continue
        operation, destination, raw_bound = bounded.groups()
        capacity = buffers.get(destination)
        if capacity is None:
            continue
        capacity_value, declaration_index = capacity
        bound = int(raw_bound, 0)
        is_append = operation.lower() in {"strncat", "wcsncat"}
        if capacity_value < bound or (is_append and destination not in empty_buffers):
            continue
        evidence = [declaration_index]
        if is_append:
            evidence.append(empty_buffers[destination])
        evidence.append(sink_index)
        return evidence
    return []


def _fixed_pair_role_evidence_indices(
    target_cwe: str,
    statements: Sequence[str],
    *,
    comparison_statements: set[str],
    base_scores: Sequence[int],
    fixed_control_scores: Sequence[int],
) -> list[int]:
    """Return the fixed-side remediation and constrained-operation evidence."""
    strong_controls = sorted(
        (index for index, score in enumerate(fixed_control_scores) if score >= 40),
        key=lambda index: (-fixed_control_scores[index], index),
    )
    contrastive_targets = sorted(
        (
            index
            for index in range(len(statements))
            if base_scores[index] >= 16
            and statements[index] not in comparison_statements
        ),
        key=lambda index: (-base_scores[index], index),
    )
    strong_control = bool(strong_controls)
    contrastive_target = bool(contrastive_targets)
    required: list[int] = []

    def add(indexes: Sequence[int]) -> None:
        if indexes and indexes[0] not in required:
            required.append(indexes[0])

    def matching(pattern: re.Pattern[str]) -> list[int]:
        return [index for index, line in enumerate(statements) if pattern.search(line)]

    if strong_control:
        add(strong_controls)
    elif contrastive_target:
        add(contrastive_targets)

    memory_sinks = [
        index
        for index, line in enumerate(statements)
        if _MEMORY_COPY.search(line)
        or re.search(
            r"\w+\s*\[[^\]]+\]\s*=\s*\w+\s*\[[^\]]+\]",
            line,
            flags=re.IGNORECASE,
        )
    ]
    if target_cwe in {"CWE-121", "CWE-122"}:
        if strong_control and memory_sinks:
            add(memory_sinks)
            return required
        bounded_control = _bounded_memory_control_indices(statements)
        return bounded_control
    if target_cwe in {"CWE-124", "CWE-126", "CWE-127"}:
        if not memory_sinks or not (strong_control or contrastive_target):
            return []
        add(memory_sinks)
        return required
    if target_cwe in {"CWE-23", "CWE-36"}:
        path_sinks = matching(
            re.compile(
                r"(?:fopen|open|remove|rename|realpath|"
                r"(?:filebuf|ifstream|ofstream)::open)\s*\(",
                flags=re.IGNORECASE,
            )
        )
        if not strong_control or not path_sinks:
            return []
        add(path_sinks)
        return required
    if target_cwe == "CWE-78":
        command_sinks = matching(
            re.compile(
                r"(?:system|popen|exec\w*|winexec|createprocess)\s*\(",
                flags=re.IGNORECASE,
            )
        )
        if not strong_control or not command_sinks:
            return []
        add(command_sinks)
        return required
    if target_cwe == "CWE-134":
        format_sinks = matching(re.compile(r"\b\w*printf\s*\(", flags=re.IGNORECASE))
        if not strong_control or not format_sinks:
            return []
        add(format_sinks)
        return required
    if target_cwe in {"CWE-401", "CWE-590", "CWE-762"}:
        allocators = [
            index
            for index, line in enumerate(statements)
            if _C_ALLOCATOR.search(line) or _CPP_ALLOCATOR.search(line)
        ]
        deallocators = [
            index
            for index, line in enumerate(statements)
            if _C_DEALLOCATOR.search(line) or _CPP_DEALLOCATOR.search(line)
        ]
        if not strong_control or not allocators or not deallocators:
            return []
        add(allocators)
        add(deallocators)
        return required
    if target_cwe == "CWE-457":
        assignments: list[tuple[int, str]] = []
        for index, line in enumerate(statements):
            assignment = re.search(
                r"\b([A-Za-z_]\w*)\s*=\s*"
                r"(?:L?\"[^\"\\]*(?:\\.[^\"\\]*)*\"|"
                r"0x[0-9a-f]+|\d+|malloc\s*\(|calloc\s*\(|new\b)",
                line,
                flags=re.IGNORECASE,
            )
            if assignment and fixed_control_scores[index] >= 40:
                assignments.append((index, assignment.group(1)))
        for control_index, variable in assignments:
            linked_sinks = [
                index
                for index, line in enumerate(statements)
                if re.search(
                    r"(?:print\w*line|\w*printf|memcpy|memmove)\s*\([^;]*"
                    rf"\b{re.escape(variable)}\b",
                    line,
                    flags=re.IGNORECASE,
                )
            ]
            if linked_sinks:
                return list(dict.fromkeys([control_index, linked_sinks[0]]))

        memory_writes = [
            index
            for index, line in enumerate(statements)
            if fixed_control_scores[index] >= 40
            and "=" in line
            and (re.match(r"^\s*\*", line) or re.search(r"\w+\s*\[[^\]]+\]", line))
        ]
        read_sinks = matching(
            re.compile(
                r"(?:print\w*line|\w*printf|memcpy|memmove)\s*\(",
                flags=re.IGNORECASE,
            )
        )
        linked_memory_roles: list[int] = []
        used_sinks: set[int] = set()
        for write_index in memory_writes:
            write_lhs = statements[write_index].split("=", 1)[0]
            write_identifiers = _stable_evidence_identifiers(write_lhs)
            for sink_index in read_sinks:
                if sink_index in used_sinks:
                    continue
                if write_identifiers & _stable_evidence_identifiers(
                    statements[sink_index]
                ):
                    linked_memory_roles.extend([write_index, sink_index])
                    used_sinks.add(sink_index)
                    break
            if len(linked_memory_roles) >= 4:
                break
        if linked_memory_roles:
            return list(dict.fromkeys(linked_memory_roles))[:4]

        direct_literal_reads = []
        for index, line in enumerate(statements):
            literal_read = re.search(
                r"\b((?:print\w*line|\w*printf))\s*\(\s*"
                r"(?:L?\"[^\"\\]*(?:\\.[^\"\\]*)*\"|"
                r"0x[0-9a-f]+|\d+)\s*\)",
                line,
                flags=re.IGNORECASE,
            )
            if not literal_read:
                continue
            function_name = literal_read.group(1)
            if any(
                re.search(
                    rf"\b{re.escape(function_name)}\s*\(",
                    comparison,
                    flags=re.IGNORECASE,
                )
                for comparison in comparison_statements
            ):
                direct_literal_reads.append(index)
        return direct_literal_reads[:1]
    if target_cwe in {"CWE-400", "CWE-606", "CWE-789"}:
        resource_sinks = matching(
            re.compile(
                r"(?:u?sleep|while\s*\(|for\s*\(|malloc|calloc|"
                r"operator_new|new\b)",
                flags=re.IGNORECASE,
            )
        )
        if not strong_control or not resource_sinks:
            return []
        add(resource_sinks)
        return required
    return required if strong_control or contrastive_target else []


def _stable_evidence_identifiers(line: str) -> set[str]:
    """Extract non-temporary identifiers for fixed write/read linkage."""
    ignored = {
        "char",
        "double",
        "float",
        "int",
        "long",
        "short",
        "signed",
        "size_t",
        "undefined",
        "unsigned",
        "void",
        "wchar_t",
    }
    return {
        identifier
        for identifier in re.findall(r"\b[A-Za-z_]\w*\b", line)
        if identifier.lower() not in ignored
        and not re.fullmatch(r"i(?:_\d+)?", identifier, flags=re.IGNORECASE)
        and not re.fullmatch(r"undefined\d*", identifier, flags=re.IGNORECASE)
        and not identifier.lower().startswith("print")
    }


def _looks_like_declaration(line: str) -> bool:
    """Reject bare decompiler declarations as vulnerability evidence."""
    return bool(
        re.match(
            r"^\s*(?:(?:const|volatile|signed|unsigned)\s+)*"
            r"(?:void|char|short|int|long|float|double|size_t|"
            r"u?int\d*_t|undefined\d*|[A-Za-z_]\w*(?:<[^;]+>)?)"
            r"\s+[*&\s]*[A-Za-z_]\w*(?:\s*\[[^\]]*\])?\s*;\s*$",
            line,
        )
    )


def _observation_is_grounded(
    observation: str,
    function: Mapping[str, Any],
    *,
    representation: str,
) -> bool:
    if representation == "pseudo_c":
        source = str(function["pseudo_c"])
        fragments = [
            line.strip()
            for line in source.splitlines()
            if len(line.strip()) >= 4 and line.strip() not in {"{", "}"}
        ]
    elif representation == "assembly":
        fragments = [
            str(value).strip()
            for value in cast(list[Any], function["assembly_evidence"])
            if len(str(value).strip()) >= 4
        ]
    else:
        features = cast(Mapping[str, Any], function["static_features"])
        fragments = [
            str(value).strip()
            for values in features.values()
            for value in cast(list[Any], values)
            if len(str(value).strip()) >= 4
        ]
    return any(fragment in observation for fragment in fragments)


def _evidence_span_is_grounded(
    code_span: str,
    function: Mapping[str, Any],
    *,
    representation: str,
) -> bool:
    if representation == "pseudo_c":
        return code_span in str(function["pseudo_c"])
    if representation == "assembly":
        return code_span in {
            str(value).strip()
            for value in cast(list[Any], function["assembly_evidence"])
        }
    if representation == "static_feature":
        features = cast(Mapping[str, Any], function["static_features"])
        return code_span in {
            str(value).strip()
            for values in features.values()
            for value in cast(list[Any], values)
        }
    return False


def _format_schema_error(error: Any) -> str:
    path = ".".join(str(item) for item in error.absolute_path)
    return f"{path}: {error.message}" if path else error.message
