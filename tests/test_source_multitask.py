from __future__ import annotations

import hashlib
import json
from pathlib import Path

from aegislm.datasets.phase_f import load_jsonl
from aegislm.datasets.source_multitask import build_source_multitask_artifact


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_source(root: Path, rows: list[dict], profile: str) -> None:
    root.mkdir()
    for split in ("train", "validation"):
        (root / f"{split}.jsonl").write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
            encoding="utf-8",
        )
    (root / "dataset_manifest.json").write_text(
        json.dumps({"profile": profile, "approved_for_training": True}) + "\n",
        encoding="utf-8",
    )
    files = sorted(root.glob("*"))
    (root / "SHA256SUMS").write_text(
        "".join(f"{_sha256(path)}  {path.name}\n" for path in files),
        encoding="utf-8",
    )


def _row(record_id: str, assessment: str, *, decision: bool) -> dict:
    target = (
        {"assessment": assessment}
        if decision
        else {
            "assessment": assessment,
            "assessment_basis": [],
            "findings": [],
            "limitations": ["scoped"],
            "recommendations": ["review"],
            "scope": {
                "boundary": "supplied_function",
                "target_cwe": "CWE-1",
            },
        }
    )
    user = (
        "Assess the supplied function.\n\n"
        + json.dumps(
            {
                "scope": {
                    "boundary": "supplied_function",
                    "target_cwe": "CWE-1",
                },
                "source_code": "int value = 0;",
            },
            indent=2,
        )
        + "\n\nReturn only JSON."
    )
    return {
        "id": record_id,
        "messages": [
            {"role": "system", "content": "decision" if decision else "report"},
            {"role": "user", "content": user},
            {"role": "assistant", "content": json.dumps(target, sort_keys=True)},
        ],
    }


def test_multitask_artifact_pairs_contracts_and_hides_development_gold(
    tmp_path: Path,
) -> None:
    report_rows = [
        _row("positive", "present", decision=False),
        _row("negative", "not_observed", decision=False),
    ]
    decision_rows = [
        _row("positive", "present", decision=True),
        _row("negative", "not_observed", decision=True),
    ]
    report_dir = tmp_path / "report"
    decision_dir = tmp_path / "decision"
    _write_source(report_dir, report_rows, "report-v1")
    _write_source(decision_dir, decision_rows, "decision-v1")
    canonical_path = tmp_path / "canonical.jsonl"
    canonical_path.write_text(
        "".join(
            json.dumps(
                {
                    "id": row["id"],
                    "metadata": {
                        "label": json.loads(row["messages"][2]["content"])["assessment"]
                    },
                    "code": {"text": "int value = 0;"},
                }
            )
            + "\n"
            for row in report_rows
        ),
        encoding="utf-8",
    )
    output = tmp_path / "multitask"

    manifest = build_source_multitask_artifact(
        report_dir,
        decision_dir,
        canonical_path,
        output,
        development_per_class=1,
        expected_train_count=2,
        expected_validation_count=2,
    )

    assert manifest["counts"]["development"] == 2
    assert manifest["mixing"]["train_probabilities"] == [0.75, 0.25]
    report_challenge = load_jsonl(output / "development" / "report-challenge.jsonl")
    decision_challenge = load_jsonl(output / "development" / "decision-challenge.jsonl")
    assert all(len(row["messages"]) == 2 for row in report_challenge)
    assert all(len(row["messages"]) == 2 for row in decision_challenge)
    assert {row["id"] for row in report_challenge} == {
        row["id"] for row in decision_challenge
    }
    assert (output / "development" / "private-records.jsonl").is_file()
