"""Validate, plan, or run the approved Mistral F5-X compatibility matrix."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

REPO_ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.experiments.runtime_compatibility import (  # noqa: E402
    build_probe_plan,
    load_compatibility_matrix,
    probe_compatibility_matrix,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument(
        "--action", choices=("validate", "plan", "probe"), required=True
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    matrix_path = _resolve_matrix_argument(args.matrix)
    matrix, digest = load_compatibility_matrix(matrix_path, repo_root=REPO_ROOT)
    if args.action == "validate":
        print(f"Mistral compatibility matrix PASS: sha256={digest}")
        return
    if args.action == "plan":
        print(json.dumps(build_probe_plan(matrix), indent=2, sort_keys=True))
        return
    evidence = probe_compatibility_matrix(
        matrix,
        matrix_sha256=digest,
        repo_root=REPO_ROOT,
    )
    print(json.dumps(evidence, indent=2, sort_keys=True))


def _resolve_matrix_argument(argument: Path) -> Path:
    matrix_path = argument if argument.is_absolute() else REPO_ROOT / argument
    resolved = matrix_path.resolve()
    expected = (
        REPO_ROOT / "configs/runtime/mistral_f5x_compatibility_matrix.json"
    ).resolve()
    if resolved != expected:
        raise ValueError(
            "--matrix must identify the repository-owned compatibility matrix"
        )
    return resolved


if __name__ == "__main__":
    main()
