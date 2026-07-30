from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path
from typing import Any

import pytest

from aegislm.datasets.phase_f import PhaseFDatasetError, write_jsonl, write_parquet
from aegislm.datasets.sard_juliet import (
    extract_juliet_functions,
    materialize_juliet_profile,
)
from aegislm.datasets.source_v3 import promote_source_v3


class _Tokenizer:
    name_or_path = "test-qwen-tokenizer"

    def apply_chat_template(self, _messages: Any, **_kwargs: Any) -> list[int]:
        return list(range(200))


def _archive(tmp_path: Path, count: int = 3) -> Path:
    archive = tmp_path / "juliet.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        for index in range(count):
            bundle.writestr(
                (
                    "C/testcases/CWE190_Integer_Overflow/s01/"
                    f"CWE190_Integer_Overflow__int_add_{index + 1:02d}.c"
                ),
                f"""
void CWE190_Integer_Overflow__int_add_{index + 1:02d}_bad()
{{
    int data = 2147483647 - {index};
    /* POTENTIAL FLAW: adding one may overflow */
    data = data + 1;
    printIntLine(data);
}}

static void goodB2G1()
{{
    int data = 2147483647 - {index};
    int dataGoodLimit = 2147483647;
    /* FIX: check the bound before adding */
    if (data < dataGoodLimit)
    {{
        data = data + 1;
    }}
    printIntLine(data);
}}

void CWE190_Integer_Overflow__int_add_{index + 1:02d}_good()
{{
    goodB2G1();
}}
""",
            )
    return archive


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_hashes(root: Path) -> None:
    files = sorted(
        path for path in root.rglob("*") if path.is_file() and path.name != "SHA256SUMS"
    )
    (root / "SHA256SUMS").write_text(
        "".join(
            f"{_sha256(path)}  {path.relative_to(root).as_posix()}\n" for path in files
        ),
        encoding="utf-8",
    )


def _approved_f2_artifact(tmp_path: Path) -> Path:
    source = tmp_path / "phase-f-sard-grounded-v2"
    functions, catalog = extract_juliet_functions(_archive(tmp_path))
    profile = materialize_juliet_profile(
        functions,
        tokenizer=_Tokenizer(),
        train_pairs=1,
        validation_pairs=1,
        test_pairs=1,
    )
    write_parquet(catalog, source / "raw_catalog.parquet")
    write_parquet(profile["manifest"], source / "eligible_manifest.parquet")
    write_jsonl(profile["canonical_records"], source / "private" / "records.jsonl")
    write_jsonl(profile["records"]["train"], source / "train.jsonl")
    write_jsonl(profile["records"]["validation"], source / "validation.jsonl")
    test_rows = profile["records"]["test"]
    write_jsonl(
        [{"id": row["id"], "messages": row["messages"][:2]} for row in test_rows],
        source / "challenge.jsonl",
    )
    write_jsonl(
        [
            {
                "id": row["id"],
                "expected_output": json.loads(row["messages"][2]["content"]),
            }
            for row in test_rows
        ],
        source / "gold.jsonl",
    )
    review_rows = [
        {
            "id": f"review-{index:03d}",
            "operator_label_error": False,
            "operator_evidence_error": False,
        }
        for index in range(100)
    ]
    write_jsonl(review_rows, source / "manual_review_100.jsonl")
    manifest = {
        key: value
        for key, value in profile.items()
        if key not in {"records", "manifest", "canonical_records"}
    }
    manual = {
        "required_count": 100,
        "reviewed_count": 100,
        "unfinished_count": 0,
        "error_count": 0,
        "error_rate": 0.0,
        "observed_error_rate": 0.0,
        "maximum_error_count": 5,
        "maximum_label_or_evidence_error_rate": 0.05,
        "status": "pass",
        "pass": True,
    }
    manifest.update(
        {
            "status": "ready_for_source_v3_integration",
            "approved_for_source_v3_integration": True,
            "approved_for_training": False,
            "manual_review": manual,
        }
    )
    (source / "dataset_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _write_hashes(source)
    return source


def test_promotes_approved_source_with_separate_gold_and_training_contract(
    tmp_path: Path,
) -> None:
    source = _approved_f2_artifact(tmp_path)
    output = tmp_path / "phase-f-source-v3"

    manifest = promote_source_v3(source, output, tokenizer=_Tokenizer())

    assert manifest["status"] == "approved_for_training"
    assert manifest["approved_for_training"] is True
    assert manifest["counts"]["train"] == 2
    assert manifest["counts"]["validation"] == 2
    assert manifest["counts"]["challenge"] == 2
    assert manifest["quality_gates"]["canonical_materialized_round_trip"] is True
    challenge = json.loads((output / "challenge.jsonl").read_text().splitlines()[0])
    gold = json.loads((output / "gold.jsonl").read_text().splitlines()[0])
    assert set(challenge) == {"id", "messages"}
    assert set(gold) == {"id", "expected_output"}
    assert len(challenge["messages"]) == 2
    dataset_info = json.loads((output / "dataset_info.json").read_text())
    assert dataset_info["phase_f_source_v3_train"]["file_name"] == (
        "llamafactory/train.jsonl"
    )
    assert (output / "SHA256SUMS").is_file()


def test_promotion_supports_an_isolated_data_revision_namespace(
    tmp_path: Path,
) -> None:
    source = _approved_f2_artifact(tmp_path)
    output = tmp_path / "phase-f-source-v4"

    manifest = promote_source_v3(
        source,
        output,
        tokenizer=_Tokenizer(),
        profile="phase-f-source-v4",
        train_dataset_name="phase_f_source_v4_train",
        validation_dataset_name="phase_f_source_v4_validation",
    )

    assert manifest["profile"] == "phase-f-source-v4"
    assert manifest["llamafactory"]["train_dataset"] == "phase_f_source_v4_train"
    dataset_info = json.loads((output / "dataset_info.json").read_text())
    assert set(dataset_info) == {
        "phase_f_source_v4_train",
        "phase_f_source_v4_validation",
    }


def test_promotion_is_deterministic_for_the_same_frozen_input(
    tmp_path: Path,
) -> None:
    source = _approved_f2_artifact(tmp_path)
    first = tmp_path / "first"
    second = tmp_path / "second"

    promote_source_v3(source, first, tokenizer=_Tokenizer())
    promote_source_v3(source, second, tokenizer=_Tokenizer())

    assert (first / "SHA256SUMS").read_bytes() == (second / "SHA256SUMS").read_bytes()


def test_rejects_a_tampered_f2_artifact(tmp_path: Path) -> None:
    source = _approved_f2_artifact(tmp_path)
    with (source / "train.jsonl").open("a", encoding="utf-8") as stream:
        stream.write("{}\n")

    with pytest.raises(PhaseFDatasetError, match="hash mismatch"):
        promote_source_v3(
            source,
            tmp_path / "phase-f-source-v3",
            tokenizer=_Tokenizer(),
        )
