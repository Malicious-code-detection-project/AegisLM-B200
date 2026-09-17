"""Finalize the fixed 100-record Phase F binary target-quality review."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.datasets.binary_v1 import summarize_binary_manual_review  # noqa: E402
from aegislm.datasets.phase_f import load_jsonl  # noqa: E402


def finalize_review(dataset_dir: Path) -> dict[str, Any]:
    """Apply the manual gate without changing any model-visible data."""
    review_path = dataset_dir / "private" / "manual_review_100.jsonl"
    manifest_path = dataset_dir / "dataset_manifest.json"
    rows = load_jsonl(review_path)
    manifest: dict[str, Any] = json.loads(manifest_path.read_text(encoding="utf-8"))
    result = summarize_binary_manual_review(
        rows,
        required_count=int(manifest["manual_review"]["required_count"]),
    )
    automated_pass = bool(
        manifest.get("quality_gates") and all(manifest["quality_gates"].values())
    )
    manifest["manual_review"] = result
    manifest["approved_for_training"] = bool(automated_pass and result["pass"])
    manifest["status"] = (
        "approved_for_binary_canary"
        if manifest["approved_for_training"]
        else "manual_target_quality_gate_failed"
    )
    manifest["frozen_files"] = _file_hashes(dataset_dir)
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _write_hashes(dataset_dir)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        manifest = finalize_review(args.dataset_dir)
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    review = manifest["manual_review"]
    print(
        "Phase F binary manual review finalized: "
        f"status={manifest['status']}, "
        f"errors={review['error_count']}/{review['required_count']}, "
        f"error_rate={review['error_rate']:.4f}"
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _file_hashes(output_dir: Path) -> dict[str, str]:
    return {
        path.relative_to(output_dir).as_posix(): _sha256_file(path)
        for path in sorted(output_dir.rglob("*"))
        if path.is_file() and path.name not in {"SHA256SUMS", "dataset_manifest.json"}
    }


def _write_hashes(output_dir: Path) -> None:
    files = sorted(
        path
        for path in output_dir.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    )
    lines = [
        f"{_sha256_file(path)}  {path.relative_to(output_dir).as_posix()}"
        for path in files
    ]
    (output_dir / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
