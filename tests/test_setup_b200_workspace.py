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
