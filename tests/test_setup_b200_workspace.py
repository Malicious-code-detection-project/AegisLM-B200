import os

import pytest

from scripts.setup_b200_workspace import configure_workspace


def test_configure_workspace_creates_persistent_layout_and_symlinks(tmp_path):
    project = tmp_path / "project"
    persistent = tmp_path / "persistent"
    project.mkdir()

    try:
        configure_workspace(project, persistent)
    except OSError as exc:
        if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
            pytest.skip("Windows developer mode is required for symlink creation")
        raise

    assert (project / "model").is_symlink()
    assert (project / "model").resolve() == (persistent / "Model").resolve()
    assert (project / "data").resolve() == (persistent / "Data").resolve()
    assert (persistent / "TrainingArtifacts" / "checkpoints").is_dir()
    assert (persistent / "Cache" / "huggingface").is_dir()
    mistral = project / "training_artifacts" / "mistral-small-4-119b"
    assert mistral.is_symlink()
    assert (
        mistral.resolve()
        == (persistent / "TrainingArtifacts" / "mistral-small-4-119b").resolve()
    )


def test_configure_workspace_is_idempotent_and_preserves_qwen_local_data(tmp_path):
    project = tmp_path / "project"
    persistent = tmp_path / "persistent"
    project.mkdir()
    artifacts = project / "training_artifacts"
    artifacts.mkdir()
    qwen = artifacts / "qwen-existing"
    qwen.mkdir()
    marker = qwen / "checkpoint.marker"
    marker.write_text("preserve", encoding="utf-8")

    try:
        configure_workspace(project, persistent)
        configure_workspace(project, persistent)
    except OSError as exc:
        if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
            pytest.skip("Windows developer mode is required for symlink creation")
        raise

    assert marker.read_text(encoding="utf-8") == "preserve"
    assert not artifacts.is_symlink()


def test_configure_workspace_rejects_wrong_mistral_target(tmp_path):
    project = tmp_path / "project"
    persistent = tmp_path / "persistent"
    project.mkdir()
    artifacts = project / "training_artifacts"
    artifacts.mkdir()
    wrong_target = tmp_path / "wrong"
    wrong_target.mkdir()
    link = artifacts / "mistral-small-4-119b"
    try:
        link.symlink_to(wrong_target, target_is_directory=True)
    except OSError as exc:
        if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
            pytest.skip("Windows developer mode is required for symlink creation")
        raise

    with pytest.raises(RuntimeError, match="Symlink target mismatch"):
        configure_workspace(project, persistent)
