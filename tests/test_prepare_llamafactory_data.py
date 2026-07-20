from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_prepare_llamafactory_data_registers_train_and_validation(tmp_path: Path):
    llamafactory_data = tmp_path / "llamafactory"
    llamafactory_data.mkdir(parents=True)
    dataset_info = llamafactory_data / "dataset_info.json"
    dataset_info.write_text('{"identity": {"file_name": "identity.json"}}\n')

    script = Path("scripts/prepare_llamafactory_data.py")
    subprocess.run(
        [
            sys.executable,
            str(script),
            "--dataset-dir",
            str(llamafactory_data),
        ],
        check=True,
    )

    parsed = json.loads(dataset_info.read_text(encoding="utf-8"))

    assert "identity" in parsed
    assert parsed["aegislm_security_sft_train_full"]["file_name"] == (
        "aegislm_security_sft_train_full.json"
    )
    assert parsed["aegislm_security_sft_validation_full"]["columns"]["system"] == (
        "system"
    )


def test_prepare_creates_new_dataset_info(tmp_path: Path):
    dataset_dir = tmp_path / "new-data"
    subprocess.run(
        [
            sys.executable,
            "scripts/prepare_llamafactory_data.py",
            "--dataset-dir",
            str(dataset_dir),
        ],
        check=True,
    )

    parsed = json.loads((dataset_dir / "dataset_info.json").read_text())
    assert sorted(parsed) == [
        "aegislm_security_sft_train_full",
        "aegislm_security_sft_validation_full",
    ]
