"""Project a frozen source blind into decision and evidence evaluation contracts."""

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
    from aegislm.datasets.source import SourceContractError
    from aegislm.datasets.source_blind_subset import build_fresh_blind_contracts
    from aegislm.evaluation.harness import load_jsonl

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    source_dir = args.source_dir.resolve()
    output_dir = args.output_dir.resolve()
    if output_dir.exists():
        raise SourceContractError(f"output directory already exists: {output_dir}")
    source_manifest_path = source_dir / "dataset_manifest.json"
    source_manifest = json.loads(source_manifest_path.read_text(encoding="utf-8"))
    if (
        source_manifest.get("status") != "frozen_blind"
        or source_manifest.get("evaluation_only") is not True
        or source_manifest.get("approved_for_training") is not False
    ):
        raise SourceContractError(
            "source artifact is not a frozen evaluation-only blind"
        )
    _verify_hashes(source_dir)

    contracts = build_fresh_blind_contracts(
        load_jsonl(source_dir / "challenge.jsonl"),
        load_jsonl(source_dir / "gold.jsonl"),
        load_jsonl(source_dir / "private" / "records.jsonl"),
    )
    output_dir.mkdir(parents=True)
    outputs = {
        "decision/challenge.jsonl": contracts.decision_challenge,
        "decision/gold.jsonl": contracts.decision_gold,
        "evidence/gold.jsonl": contracts.evidence_gold,
    }
    for relative, rows in outputs.items():
        _write_jsonl(output_dir / relative, rows)
    manifest = {
        **contracts.manifest,
        "source": {
            "profile": source_manifest.get("profile"),
            "dataset_manifest_sha256": _sha256(source_manifest_path),
            "sha256s_sha256": _sha256(source_dir / "SHA256SUMS"),
            "private_records_sha256": _sha256(source_dir / "private" / "records.jsonl"),
        },
        "outputs": {relative: _sha256(output_dir / relative) for relative in outputs},
    }
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _write_hash_inventory(output_dir)
    print(
        "Fresh source blind contracts complete: "
        f"count={manifest['count']}, labels={manifest['labels']}, "
        f"manifest={manifest_path}"
    )


def _verify_hashes(root: Path) -> None:
    inventory = root / "SHA256SUMS"
    if not inventory.is_file():
        raise ValueError(f"missing source hash inventory: {inventory}")
    for line in inventory.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        expected, relative = line.split("  ", 1)
        path = root / relative
        if not path.is_file() or _sha256(path) != expected:
            raise ValueError(f"source artifact hash mismatch: {relative}")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows
        ),
        encoding="utf-8",
    )


def _write_hash_inventory(root: Path) -> None:
    paths = sorted(
        path for path in root.rglob("*") if path.is_file() and path.name != "SHA256SUMS"
    )
    (root / "SHA256SUMS").write_text(
        "".join(
            f"{_sha256(path)}  {path.relative_to(root).as_posix()}\n" for path in paths
        ),
        encoding="utf-8",
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


if __name__ == "__main__":
    main()
