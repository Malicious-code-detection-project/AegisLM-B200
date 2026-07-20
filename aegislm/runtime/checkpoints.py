"""Checkpoint discovery, mirroring, and resume selection."""

from __future__ import annotations

import json
import os
import re
import shutil
import time
import uuid
from dataclasses import dataclass
from pathlib import Path


CHECKPOINT_PATTERN = re.compile(r"^checkpoint-(\d+)$")
PAYLOAD_NAMES = {
    "adapter_model.safetensors",
    "model.safetensors",
    "optimizer.pt",
    "pytorch_model.bin",
}


class CheckpointError(RuntimeError):
    """Raised when a checkpoint cannot be trusted or selected safely."""


@dataclass(frozen=True)
class CheckpointInfo:
    path: Path
    step: int
    file_count: int
    total_bytes: int
    latest_mtime_ns: int


def inspect_checkpoint(path: Path) -> CheckpointInfo:
    """Validate a Trainer/DeepSpeed checkpoint and return its fingerprint."""
    match = CHECKPOINT_PATTERN.match(path.name)
    if not path.is_dir() or match is None:
        raise CheckpointError(f"Invalid checkpoint directory: {path}")
    if not (path / "trainer_state.json").is_file():
        raise CheckpointError(f"Missing trainer_state.json: {path}")

    files = [item for item in path.rglob("*") if item.is_file()]
    has_payload = any(item.name in PAYLOAD_NAMES for item in files) or any(
        part.startswith("global_step") for item in files for part in item.parts
    )
    if not has_payload:
        raise CheckpointError(f"No model or optimizer payload found: {path}")

    stats = [item.stat() for item in files]
    return CheckpointInfo(
        path=path,
        step=int(match.group(1)),
        file_count=len(files),
        total_bytes=sum(stat.st_size for stat in stats),
        latest_mtime_ns=max(stat.st_mtime_ns for stat in stats),
    )


def list_valid_checkpoints(root: Path) -> list[CheckpointInfo]:
    """Return valid checkpoints sorted by training step."""
    if not root.is_dir():
        return []
    checkpoints: list[CheckpointInfo] = []
    for path in root.iterdir():
        if CHECKPOINT_PATTERN.match(path.name) is None:
            continue
        try:
            checkpoints.append(inspect_checkpoint(path))
        except CheckpointError:
            continue
    return sorted(checkpoints, key=lambda item: item.step)


def mirror_checkpoint(source: Path, mirror_root: Path) -> Path:
    """Copy one complete checkpoint and retain one physical mirror."""
    source_info = inspect_checkpoint(source)
    mirror_root.mkdir(parents=True, exist_ok=True)
    destination = mirror_root / source.name

    if destination.exists():
        try:
            destination_info = inspect_checkpoint(destination)
        except CheckpointError:
            destination_info = None
        if destination_info and _same_content(source_info, destination_info):
            _write_latest_metadata(mirror_root, destination_info)
            _remove_older_checkpoints(mirror_root, keep=destination)
            return destination

    staging = mirror_root / f".{source.name}.tmp-{uuid.uuid4().hex}"
    backup = mirror_root / f".{source.name}.old-{uuid.uuid4().hex}"
    try:
        shutil.copytree(source, staging, copy_function=shutil.copy2)
        staged_files = [item for item in staging.rglob("*") if item.is_file()]
        staged_bytes = sum(item.stat().st_size for item in staged_files)
        if (
            len(staged_files) != source_info.file_count
            or staged_bytes != source_info.total_bytes
        ):
            raise CheckpointError(f"Checkpoint mirror verification failed: {source}")

        if destination.exists():
            os.replace(destination, backup)
        os.replace(staging, destination)
        mirrored_info = inspect_checkpoint(destination)
        if not _same_content(source_info, mirrored_info):
            raise CheckpointError(f"Checkpoint mirror fingerprint mismatch: {source}")
        _write_latest_metadata(mirror_root, mirrored_info)
        _remove_older_checkpoints(mirror_root, keep=destination)
        if backup.exists():
            shutil.rmtree(backup)
        return destination
    except Exception:
        if staging.exists():
            shutil.rmtree(staging)
        if backup.exists() and not destination.exists():
            os.replace(backup, destination)
        raise


def restore_checkpoint(source: Path, local_root: Path) -> Path:
    """Restore a persistent checkpoint as the one local physical copy."""
    restored = mirror_checkpoint(source, local_root)
    return restored


def resolve_resume_checkpoint(
    local_root: Path,
    mirror_root: Path,
    *,
    mode: str,
) -> Path | None:
    """Resolve fresh/auto/explicit resume policy without guessing on mismatch."""
    local = list_valid_checkpoints(local_root)
    mirrored = list_valid_checkpoints(mirror_root)

    if mode == "fresh":
        if local or mirrored:
            raise CheckpointError(
                "Fresh run refused because an existing checkpoint was found."
            )
        return None

    if mode != "auto":
        explicit = Path(mode).expanduser().resolve()
        inspect_checkpoint(explicit)
        return explicit

    local_latest = local[-1] if local else None
    mirror_latest = mirrored[-1] if mirrored else None
    if local_latest and mirror_latest and local_latest.step != mirror_latest.step:
        raise CheckpointError(
            "Local and persistent checkpoints disagree: "
            f"{local_latest.path.name} vs {mirror_latest.path.name}."
        )
    if local_latest:
        return local_latest.path
    if mirror_latest:
        return restore_checkpoint(mirror_latest.path, local_root)
    return None


def wait_for_stable_checkpoint(
    checkpoint: Path,
    *,
    interval_seconds: float,
) -> CheckpointInfo:
    """Require an unchanged fingerprint across two observations."""
    first = inspect_checkpoint(checkpoint)
    time.sleep(interval_seconds)
    second = inspect_checkpoint(checkpoint)
    if (
        not _same_content(first, second)
        or first.latest_mtime_ns != second.latest_mtime_ns
    ):
        raise CheckpointError(f"Checkpoint is still changing: {checkpoint}")
    return second


def _same_content(left: CheckpointInfo, right: CheckpointInfo) -> bool:
    return left.file_count == right.file_count and left.total_bytes == right.total_bytes


def _write_latest_metadata(root: Path, checkpoint: CheckpointInfo) -> None:
    metadata = {
        "checkpoint": checkpoint.path.name,
        "step": checkpoint.step,
        "file_count": checkpoint.file_count,
        "total_bytes": checkpoint.total_bytes,
    }
    temp = root / f".latest_checkpoint.tmp-{uuid.uuid4().hex}"
    temp.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    os.replace(temp, root / "latest_checkpoint.json")


def _remove_older_checkpoints(root: Path, *, keep: Path) -> None:
    for checkpoint in list_valid_checkpoints(root):
        if checkpoint.path != keep:
            shutil.rmtree(checkpoint.path)
