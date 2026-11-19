from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegislm.datasets.rebuild_pipeline import (
    DatasetRebuildConfig,
    DatasetRebuildError,
    _validate_config,
)
from aegislm.datasets.sard_juliet import SARD_JULIET_PROFILE


def _config(tmp_path: Path, *, profile: str) -> DatasetRebuildConfig:
    approved = tmp_path / "approved"
    tokenizer = tmp_path / "tokenizer"
    profile_config = tmp_path / "source-profile.json"
    approved.mkdir()
    tokenizer.mkdir()
    (approved / "dataset_manifest.json").write_text(
        json.dumps({"profile": profile}),
        encoding="utf-8",
    )
    (approved / "SHA256SUMS").write_text("", encoding="utf-8")
    profile_config.write_text("{}", encoding="utf-8")
    return DatasetRebuildConfig(
        approved_f2_root=approved,
        tokenizer=tokenizer,
        output_root=tmp_path / "output",
        profile_config=profile_config,
    )


def test_rebuild_config_accepts_only_remediated_f2_profile(tmp_path: Path) -> None:
    _validate_config(_config(tmp_path, profile=SARD_JULIET_PROFILE))


def test_rebuild_config_rejects_legacy_grounded_v2(tmp_path: Path) -> None:
    with pytest.raises(DatasetRebuildError, match="remediated"):
        _validate_config(_config(tmp_path, profile="phase-f-sard-grounded-v2"))
