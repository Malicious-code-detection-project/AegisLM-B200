from __future__ import annotations

import hashlib

import pytest

from aegislm.datasets.binary_v2 import (
    BINARY_V2_OUTPUT_CONTRACT,
    build_binary_role_manual_review,
    render_binary_role_manual_review,
)
from aegislm.datasets.phase_f import PhaseFDatasetError


def _record(
    pair_id: str,
    label: str,
    target_cwe: str,
    pseudo_c: str,
) -> dict:
    opaque = hashlib.sha256(f"{pair_id}:{label}".encode()).hexdigest()[:16]
    return {
        "schema_version": "aegislm.binary-analysis-record.v1",
        "id": f"{pair_id}-{label}-gcc-o0",
        "artifact": {
            "sha256": hashlib.sha256(
                f"{pair_id}:{label}:artifact".encode()
            ).hexdigest(),
            "format": "ELF",
            "architecture": "x86_64",
            "compiler": "gcc",
            "optimization": "O0",
            "stripped": True,
            "external_artifact_ref": None,
        },
        "analysis": {
            "analyzer": "fixture",
            "analyzer_version": "1",
            "decompiler": "fixture",
            "decompiler_version": "1",
            "functions": [
                {
                    "function_id": "function-1",
                    "function_hash": hashlib.sha256(
                        f"{pair_id}:{label}:function".encode()
                    ).hexdigest(),
                    "pseudo_c": pseudo_c,
                    "assembly_evidence": [],
                    "static_features": {
                        "imports": [],
                        "sections": [],
                        "strings": [],
                        "symbols": [],
                    },
                }
            ],
            "warnings": ["fixture"],
        },
        "task": {"target_cwe": target_cwe},
        "metadata": {
            "split": "test",
            "source_dataset": "fixture",
            "label": label,
            "compiler_group_id": f"binary-group-{opaque}",
            "contains_executable_payload": False,
        },
    }


def _inputs() -> tuple[list[dict], dict]:
    definitions = {
        "pair-memory": (
            "CWE-121",
            "char dst[8];\nmemcpy(dst, src, 32);",
            "char dst[32];\nmemcpy(dst, src, 8);",
        ),
        "pair-null": (
            "CWE-690",
            "data = malloc(32);\n*data = 1;",
            "data = malloc(32);\nif (data == NULL) return;\n*data = 1;",
        ),
    }
    records = [
        _record(pair_id, label, target_cwe, present if label == "present" else fixed)
        for pair_id, (target_cwe, present, fixed) in definitions.items()
        for label in ("present", "not_observed")
    ]
    gate = {
        "gate_pass": True,
        "output_contract": BINARY_V2_OUTPUT_CONTRACT,
        "accepted_pair_ids": list(definitions),
        "accepted_pair_variants": {pair_id: ["gcc-O0"] for pair_id in definitions},
    }
    return records, gate


def test_binary_v2_review_is_stratified_reproducible_and_renderable() -> None:
    records, gate = _inputs()

    first = build_binary_role_manual_review(
        records,
        gate,
        review_records=4,
    )
    second = build_binary_role_manual_review(
        records,
        gate,
        review_records=4,
    )
    rendered = render_binary_role_manual_review(first["rows"])

    assert first == second
    assert len(first["rows"]) == 4
    assert first["manifest"]["cwe_pair_counts"] == {
        "CWE-121": 1,
        "CWE-690": 1,
    }
    assert "Target role graph" in rendered
    assert "operator_evidence_error" in rendered
    assert "private_label" not in first["rows"][0]["expected_output"]


def test_binary_v2_review_rejects_unpassed_or_wrong_contract_gate() -> None:
    records, gate = _inputs()
    gate["gate_pass"] = False

    with pytest.raises(PhaseFDatasetError, match="passed or review-eligible"):
        build_binary_role_manual_review(records, gate, review_records=4)

    gate["review_eligible"] = True
    assert (
        build_binary_role_manual_review(records, gate, review_records=4)["manifest"][
            "review_record_count"
        ]
        == 4
    )

    gate["gate_pass"] = True
    gate["output_contract"] = "aegislm.binary-assessment-output.v1"
    with pytest.raises(PhaseFDatasetError, match="v2 output contract"):
        build_binary_role_manual_review(records, gate, review_records=4)
