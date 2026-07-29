"""Finalize the fixed 100-case SARD review without approving GPU training."""

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


def main() -> None:
    from aegislm.datasets.phase_f import load_jsonl
    from aegislm.datasets.sard_juliet import summarize_juliet_manual_review

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-dir", type=Path, required=True)
    args = parser.parse_args()

    review_path = args.dataset_dir / "manual_review_100.jsonl"
    manifest_path = args.dataset_dir / "dataset_manifest.json"
    rows = load_jsonl(review_path)
    try:
        result = summarize_juliet_manual_review(rows)
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    manifest: dict[str, Any] = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["manual_review"] = result
    manifest["approved_for_source_v3_integration"] = bool(
        manifest.get("automated_pass") and result["pass"]
    )
    manifest["approved_for_training"] = False
    manifest["status"] = (
        "ready_for_source_v3_integration"
        if manifest["approved_for_source_v3_integration"]
        else "manual_quality_gate_failed"
    )
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _write_hashes(args.dataset_dir)
    print(
        "SARD Juliet manual review finalized: "
        f"status={manifest['status']}, "
        f"errors={result['error_count']}/{result['reviewed_count']}, "
        f"error_rate={result['error_rate']:.4f}"
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


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
