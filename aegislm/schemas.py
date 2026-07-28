"""JSON contracts for AegisLM dataset records and model outputs."""

from __future__ import annotations

RISK_LEVELS = ("low", "medium", "high", "critical", "unknown")
CONFIDENCE_LEVELS = ("low", "medium", "high")
SOURCE_TYPES = (
    "nvd",
    "cisa_kev",
    "mitre_attack",
    "public_cti",
    "public_security_dataset",
    "nurilab_synthetic",
    "nurilab_analysis",
)
SPLITS = ("train", "validation", "test", "fixture")
SAFETY_LEVELS = ("metadata_only", "synthetic", "redacted", "restricted")
BINARY_ASSESSMENTS = ("present", "not_observed", "uncertain")
BINARY_FORMATS = ("PE", "ELF")
BINARY_REPRESENTATIONS = ("pseudo_c", "assembly", "static_feature")

OUTPUT_CONTRACT_SCHEMA: dict[str, object] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "AegisLM Phase C Output Contract",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "summary",
        "behavior_explanation",
        "risk_level",
        "malware_like_behaviors",
        "attack_mapping",
        "recommendations",
        "limitations",
    ],
    "properties": {
        "summary": {"type": "string", "minLength": 1},
        "behavior_explanation": {"type": "string", "minLength": 1},
        "risk_level": {"type": "string", "enum": list(RISK_LEVELS)},
        "malware_like_behaviors": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["behavior", "evidence", "confidence"],
                "properties": {
                    "behavior": {"type": "string", "minLength": 1},
                    "evidence": {"type": "string", "minLength": 1},
                    "confidence": {"type": "string", "enum": list(CONFIDENCE_LEVELS)},
                },
            },
        },
        "attack_mapping": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["tactic", "technique_id", "technique_name", "evidence"],
                "properties": {
                    "tactic": {"type": "string", "minLength": 1},
                    "technique_id": {"type": "string", "minLength": 1},
                    "technique_name": {"type": "string", "minLength": 1},
                    "evidence": {"type": "string", "minLength": 1},
                },
            },
        },
        "recommendations": {
            "type": "array",
            "items": {"type": "string", "minLength": 1},
        },
        "limitations": {
            "type": "array",
            "items": {"type": "string", "minLength": 1},
        },
    },
}

DATASET_RECORD_SCHEMA: dict[str, object] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "AegisLM Phase C Dataset Record",
    "type": "object",
    "additionalProperties": False,
    "required": ["id", "source", "input", "expected_output", "metadata"],
    "properties": {
        "id": {"type": "string", "minLength": 1},
        "source": {
            "type": "object",
            "additionalProperties": False,
            "required": ["type", "name", "url", "license_or_terms", "retrieved_at"],
            "properties": {
                "type": {"type": "string", "enum": list(SOURCE_TYPES)},
                "name": {"type": "string", "minLength": 1},
                "url": {"type": ["string", "null"]},
                "license_or_terms": {"type": ["string", "null"]},
                "retrieved_at": {
                    "type": ["string", "null"],
                    "pattern": r"^\d{4}-\d{2}-\d{2}$",
                },
            },
        },
        "input": {
            "type": "object",
            "additionalProperties": False,
            "required": ["task", "context", "signals"],
            "properties": {
                "task": {"type": "string", "minLength": 1},
                "context": {"type": "string", "minLength": 1},
                "signals": {"type": "object"},
            },
        },
        "expected_output": OUTPUT_CONTRACT_SCHEMA,
        "metadata": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "split",
                "safety_level",
                "contains_executable_payload",
                "notes",
            ],
            "properties": {
                "split": {"type": "string", "enum": list(SPLITS)},
                "safety_level": {"type": "string", "enum": list(SAFETY_LEVELS)},
                "contains_executable_payload": {"type": "boolean"},
                "notes": {"type": "array", "items": {"type": "string"}},
            },
        },
    },
}

BINARY_ANALYSIS_RECORD_SCHEMA: dict[str, object] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "aegislm.binary-analysis-record.v1",
    "title": "AegisLM Normalized Binary Analysis Record v1",
    "type": "object",
    "additionalProperties": False,
    "required": ["schema_version", "id", "artifact", "analysis", "task", "metadata"],
    "properties": {
        "schema_version": {"const": "aegislm.binary-analysis-record.v1"},
        "id": {"type": "string", "minLength": 1},
        "artifact": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "sha256",
                "format",
                "architecture",
                "compiler",
                "optimization",
                "stripped",
                "external_artifact_ref",
            ],
            "properties": {
                "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "format": {"type": "string", "enum": list(BINARY_FORMATS)},
                "architecture": {"type": "string", "minLength": 1},
                "compiler": {"type": ["string", "null"]},
                "optimization": {"type": ["string", "null"]},
                "stripped": {"type": "boolean"},
                "external_artifact_ref": {"type": ["string", "null"]},
            },
        },
        "analysis": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "analyzer",
                "analyzer_version",
                "decompiler",
                "decompiler_version",
                "functions",
                "warnings",
            ],
            "properties": {
                "analyzer": {"type": "string", "minLength": 1},
                "analyzer_version": {"type": "string", "minLength": 1},
                "decompiler": {"type": "string", "minLength": 1},
                "decompiler_version": {"type": "string", "minLength": 1},
                "functions": {
                    "type": "array",
                    "minItems": 1,
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": [
                            "function_id",
                            "function_hash",
                            "pseudo_c",
                            "assembly_evidence",
                            "static_features",
                        ],
                        "properties": {
                            "function_id": {"type": "string", "minLength": 1},
                            "function_hash": {
                                "type": "string",
                                "pattern": "^[0-9a-f]{64}$",
                            },
                            "pseudo_c": {"type": "string", "minLength": 1},
                            "assembly_evidence": {
                                "type": "array",
                                "items": {"type": "string", "minLength": 1},
                            },
                            "static_features": {
                                "type": "object",
                                "additionalProperties": False,
                                "required": [
                                    "imports",
                                    "sections",
                                    "strings",
                                    "symbols",
                                ],
                                "properties": {
                                    "imports": {
                                        "type": "array",
                                        "items": {"type": "string", "minLength": 1},
                                    },
                                    "sections": {
                                        "type": "array",
                                        "items": {"type": "string", "minLength": 1},
                                    },
                                    "strings": {
                                        "type": "array",
                                        "items": {"type": "string", "minLength": 1},
                                    },
                                    "symbols": {
                                        "type": "array",
                                        "items": {"type": "string", "minLength": 1},
                                    },
                                },
                            },
                        },
                    },
                },
                "warnings": {
                    "type": "array",
                    "items": {"type": "string", "minLength": 1},
                },
            },
        },
        "task": {
            "type": "object",
            "additionalProperties": False,
            "required": ["target_cwe"],
            "properties": {
                "target_cwe": {"type": "string", "pattern": "^CWE-[0-9]+$"},
            },
        },
        "metadata": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "split",
                "source_dataset",
                "label",
                "compiler_group_id",
                "contains_executable_payload",
            ],
            "properties": {
                "split": {"type": "string", "enum": list(SPLITS)},
                "source_dataset": {"type": "string", "minLength": 1},
                "label": {"type": "string", "enum": list(BINARY_ASSESSMENTS)},
                "compiler_group_id": {"type": "string", "minLength": 1},
                "contains_executable_payload": {"const": False},
            },
        },
    },
}

BINARY_ASSESSMENT_OUTPUT_SCHEMA: dict[str, object] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "aegislm.binary-assessment-output.v1",
    "title": "AegisLM Binary Assessment Output v1",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "scope",
        "assessment",
        "findings",
        "limitations",
        "recommendations",
    ],
    "properties": {
        "scope": {
            "type": "object",
            "additionalProperties": False,
            "required": ["target_cwe", "binary_format", "architecture"],
            "properties": {
                "target_cwe": {"type": "string", "pattern": "^CWE-[0-9]+$"},
                "binary_format": {"type": "string", "enum": list(BINARY_FORMATS)},
                "architecture": {"type": "string", "minLength": 1},
            },
        },
        "assessment": {"type": "string", "enum": list(BINARY_ASSESSMENTS)},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "function_id",
                    "representation",
                    "observation",
                    "confidence",
                ],
                "properties": {
                    "function_id": {"type": "string", "minLength": 1},
                    "representation": {
                        "type": "string",
                        "enum": list(BINARY_REPRESENTATIONS),
                    },
                    "observation": {"type": "string", "minLength": 1},
                    "confidence": {"type": "string", "enum": list(CONFIDENCE_LEVELS)},
                },
            },
        },
        "limitations": {
            "type": "array",
            "minItems": 1,
            "items": {"type": "string", "minLength": 1},
        },
        "recommendations": {
            "type": "array",
            "items": {"type": "string", "minLength": 1},
        },
    },
}
