"""Check the active Mistral F5-X environment without starting training."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.experiments.config import load_experiment_config  # noqa: E402
from aegislm.experiments.runtime import verify_runtime_environment  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-gpus", action="store_true")
    args = parser.parse_args()
    config = load_experiment_config(
        REPO_ROOT / "configs/experiment.yaml", repo_root=REPO_ROOT
    )
    evidence = verify_runtime_environment(config, require_gpus=args.require_gpus)
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
