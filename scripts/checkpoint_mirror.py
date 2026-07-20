"""Observe, mirror, and resolve Trainer checkpoints without signaling training."""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from aegislm.runtime.checkpoints import (  # noqa: E402
    CheckpointError,
    list_valid_checkpoints,
    mirror_checkpoint,
    resolve_resume_checkpoint,
    wait_for_stable_checkpoint,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-root", type=Path, required=True)
    parser.add_argument("--mirror-root", type=Path, required=True)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--once", action="store_true")
    action.add_argument("--watch", action="store_true")
    action.add_argument("--resolve", metavar="MODE")
    parser.add_argument("--interval-seconds", type=float, default=30.0)
    parser.add_argument("--duration-seconds", type=float)
    parser.add_argument("--log-path", type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.resolve is not None:
        resolved = resolve_resume_checkpoint(
            args.local_root,
            args.mirror_root,
            mode=args.resolve,
        )
        print(str(resolved) if resolved else "")
        return

    log_path = args.log_path or args.mirror_root / "checkpoint_mirror.jsonl"
    if args.once:
        _mirror_latest(args.local_root, args.mirror_root, log_path, wait=False)
        return

    started = time.monotonic()
    while True:
        try:
            _mirror_latest(args.local_root, args.mirror_root, log_path, wait=True)
        except Exception as exc:  # keep the observer alive and never signal training
            _append_log(log_path, status="error", message=str(exc))
            print(f"[checkpoint-mirror] {exc}", file=sys.stderr, flush=True)
        if args.duration_seconds is not None:
            if time.monotonic() - started >= args.duration_seconds:
                return
        time.sleep(args.interval_seconds)


def _mirror_latest(
    local_root: Path,
    mirror_root: Path,
    log_path: Path,
    *,
    wait: bool,
) -> None:
    checkpoints = list_valid_checkpoints(local_root)
    if not checkpoints:
        return
    source = checkpoints[-1]
    mirrored = list_valid_checkpoints(mirror_root)
    if mirrored and mirrored[-1].step == source.step:
        return
    if wait:
        wait_for_stable_checkpoint(source.path, interval_seconds=2.0)
    destination = mirror_checkpoint(source.path, mirror_root)
    _append_log(
        log_path,
        status="mirrored",
        message=f"{source.path} -> {destination}",
        step=source.step,
    )
    print(f"[checkpoint-mirror] mirrored {destination}", flush=True)


def _append_log(
    path: Path,
    *,
    status: str,
    message: str,
    step: int | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": datetime.now(UTC).isoformat(),
        "status": status,
        "step": step,
        "message": message,
    }
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    try:
        main()
    except CheckpointError as exc:
        raise SystemExit(str(exc)) from exc
