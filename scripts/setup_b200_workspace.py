"""Create the two-GPU B200 persistent directory and symlink layout."""

from __future__ import annotations

import argparse
import os
from pathlib import Path


DEFAULT_PERSISTENT_ROOT = Path("/NHNHOME/WORKSPACE/26moel002_ex07/LLM")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--persistent-root", type=Path, default=DEFAULT_PERSISTENT_ROOT)
    return parser.parse_args()


def ensure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if not os.access(path, os.W_OK):
        raise PermissionError(f"Directory is not writable: {path}")


def ensure_directory_symlink(link: Path, target: Path) -> None:
    target = target.resolve()
    if link.is_symlink():
        if link.resolve() != target:
            raise RuntimeError(f"Symlink target mismatch: {link} -> {link.resolve()}")
        return
    if link.exists():
        raise RuntimeError(f"Refusing to replace existing non-symlink path: {link}")
    link.symlink_to(target, target_is_directory=True)


def configure_workspace(project_root: Path, persistent_root: Path) -> None:
    project_root = project_root.resolve()
    persistent_root = persistent_root.resolve()
    directories = [
        persistent_root / "Model" / "base",
        persistent_root / "Data" / "processed" / "hf-full-v1",
        persistent_root / "Data" / "llamafactory",
        persistent_root / "TrainingArtifacts" / "checkpoints",
        persistent_root / "TrainingArtifacts" / "runs",
        persistent_root / "TrainingArtifacts" / "wandb",
        persistent_root / "Cache" / "huggingface",
        project_root / "training_artifacts",
    ]
    for directory in directories:
        ensure_directory(directory)
    ensure_directory_symlink(project_root / "model", persistent_root / "Model")
    ensure_directory_symlink(project_root / "data", persistent_root / "Data")


def main() -> None:
    args = parse_args()
    configure_workspace(args.project_root, args.persistent_root)
    print(f"Configured B200 workspace at {args.project_root.resolve()}")


if __name__ == "__main__":
    main()
