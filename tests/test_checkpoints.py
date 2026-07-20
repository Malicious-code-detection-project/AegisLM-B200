import json
from pathlib import Path

import pytest

from aegislm.runtime.checkpoints import (
    CheckpointError,
    list_valid_checkpoints,
    mirror_checkpoint,
    resolve_resume_checkpoint,
)


def _checkpoint(root: Path, step: int, payload: bytes = b"weights") -> Path:
    path = root / f"checkpoint-{step}"
    path.mkdir(parents=True)
    (path / "trainer_state.json").write_text(
        json.dumps({"global_step": step}), encoding="utf-8"
    )
    (path / "adapter_model.safetensors").write_bytes(payload)
    return path


def test_mirror_is_atomic_and_retains_one_checkpoint(tmp_path: Path):
    local = tmp_path / "local"
    mirror = tmp_path / "mirror"
    first = _checkpoint(local, 500)
    mirror_checkpoint(first, mirror)
    second = _checkpoint(local, 1000, b"new")
    mirror_checkpoint(second, mirror)

    assert [item.step for item in list_valid_checkpoints(mirror)] == [1000]
    metadata = json.loads((mirror / "latest_checkpoint.json").read_text())
    assert metadata["step"] == 1000
    assert not list(mirror.glob(".*.tmp-*"))


def test_auto_resume_restores_persistent_checkpoint(tmp_path: Path):
    local = tmp_path / "local"
    mirror = tmp_path / "mirror"
    persistent = _checkpoint(mirror, 500)

    resolved = resolve_resume_checkpoint(local, mirror, mode="auto")

    assert resolved == local / "checkpoint-500"
    assert resolved.is_dir()
    assert persistent.is_dir()


def test_auto_resume_refuses_step_mismatch(tmp_path: Path):
    local = tmp_path / "local"
    mirror = tmp_path / "mirror"
    _checkpoint(local, 500)
    _checkpoint(mirror, 1000)

    with pytest.raises(CheckpointError, match="disagree"):
        resolve_resume_checkpoint(local, mirror, mode="auto")


def test_fresh_resume_refuses_existing_checkpoint(tmp_path: Path):
    local = tmp_path / "local"
    _checkpoint(local, 500)

    with pytest.raises(CheckpointError, match="Fresh run refused"):
        resolve_resume_checkpoint(local, tmp_path / "mirror", mode="fresh")
