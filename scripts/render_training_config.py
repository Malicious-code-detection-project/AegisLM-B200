"""Render a runtime LlamaFactory YAML with an explicit resume decision."""

from __future__ import annotations

import argparse
from pathlib import Path

import yaml


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--resume-from-checkpoint")
    parser.add_argument("--run-name-suffix")
    return parser.parse_args()


def render_config(
    source: Path,
    destination: Path,
    *,
    resume_from_checkpoint: str | None,
    run_name_suffix: str | None,
) -> dict[str, object]:
    data = yaml.safe_load(source.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Training config must be a YAML mapping: {source}")
    data["resume_from_checkpoint"] = resume_from_checkpoint
    if run_name_suffix:
        data["run_name"] = f"{data.get('run_name', 'aegislm')}-{run_name_suffix}"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        yaml.safe_dump(data, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    return data


def main() -> None:
    args = parse_args()
    render_config(
        args.input,
        args.output,
        resume_from_checkpoint=args.resume_from_checkpoint or None,
        run_name_suffix=args.run_name_suffix,
    )
    print(args.output)


if __name__ == "__main__":
    main()
