"""Inventory Phase F binary candidates and decide whether B0 may start."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def inspect_local_source(
    source: Mapping[str, Any],
    *,
    repo_root: Path,
) -> dict[str, Any]:
    """Return presence and size without reading executable payloads."""
    relative_path = Path(str(source["path"]))
    path = (repo_root / relative_path).resolve()
    expected_kind = str(source["kind"])
    exists = path.is_file() if expected_kind == "file" else path.is_dir()
    size_bytes = _path_size(path) if exists else 0
    return {
        **dict(source),
        "absolute_path": str(path),
        "exists": exists,
        "size_bytes": size_bytes,
    }


def assess_readiness(
    *,
    local_sources: Sequence[Mapping[str, Any]],
    selected_source_ids: Sequence[str],
    tools: Mapping[str, Mapping[str, Any]],
    required_compilers: Sequence[str],
    required_static_tools: Sequence[str],
    decompiler_any_of: Sequence[str],
) -> dict[str, Any]:
    """Apply F6-A and F6-B preflight gates."""
    sources_by_id = {str(source["id"]): source for source in local_sources}
    source_failures: list[str] = []
    for source_id in selected_source_ids:
        source = sources_by_id.get(source_id)
        if source is None:
            source_failures.append(f"selected source is not configured: {source_id}")
            continue
        if not bool(source["exists"]):
            source_failures.append(f"selected source is missing: {source_id}")
        if source["license_status"] != "approved":
            source_failures.append(
                f"selected source license is not approved: {source_id}"
            )
        if bool(source["contains_raw_executable"]):
            source_failures.append(
                f"selected source contains raw executables: {source_id}"
            )

    missing_compilers = [
        name for name in required_compilers if not bool(tools[name]["available"])
    ]
    missing_static_tools = [
        name for name in required_static_tools if not bool(tools[name]["available"])
    ]
    available_decompilers = [
        name for name in decompiler_any_of if bool(tools[name]["available"])
    ]
    f6a_pass = not source_failures
    f6b_ready = (
        f6a_pass
        and not missing_compilers
        and not missing_static_tools
        and bool(available_decompilers)
    )
    blockers = [
        *source_failures,
        *(f"missing required compiler: {name}" for name in missing_compilers),
        *(f"missing required static tool: {name}" for name in missing_static_tools),
    ]
    if not available_decompilers:
        blockers.append("no approved decompiler found: " + ", ".join(decompiler_any_of))
    return {
        "f6a_candidate_inventory_pass": f6a_pass,
        "f6b_b0_ready": f6b_ready,
        "missing_compilers": missing_compilers,
        "missing_static_tools": missing_static_tools,
        "available_decompilers": available_decompilers,
        "blockers": blockers,
    }


def build_inventory(
    config: Mapping[str, Any],
    *,
    repo_root: Path,
    generated_at: str,
) -> dict[str, Any]:
    """Build the complete candidate and toolchain inventory."""
    local_sources = [
        inspect_local_source(source, repo_root=repo_root)
        for source in _mapping_list(config["local_sources"])
    ]
    toolchain = _mapping(config["toolchain"])
    command_names = list(
        dict.fromkeys(
            [
                *_string_list(toolchain["required_compilers"]),
                *_string_list(toolchain["required_static_tools"]),
                *_string_list(toolchain["decompiler_any_of"]),
                *_string_list(toolchain["optional_build_tools"]),
            ]
        )
    )
    tools = {name: _inspect_tool(name) for name in command_names}
    readiness = assess_readiness(
        local_sources=local_sources,
        selected_source_ids=_string_list(config["selected_b0_sources"]),
        tools=tools,
        required_compilers=_string_list(toolchain["required_compilers"]),
        required_static_tools=_string_list(toolchain["required_static_tools"]),
        decompiler_any_of=_string_list(toolchain["decompiler_any_of"]),
    )
    return {
        "schema_version": "aegislm.binary-candidate-inventory.v1",
        "profile": config["profile"],
        "generated_at": generated_at,
        "repo_root": str(repo_root.resolve()),
        "selected_b0_sources": config["selected_b0_sources"],
        "local_sources": local_sources,
        "external_candidates": config["external_candidates"],
        "toolchain": tools,
        "safety_policy": config["safety_policy"],
        "readiness": readiness,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("configs/phase_f/binary_candidates.json"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/raw_data/_manifests/binary_candidate_inventory.json"),
    )
    parser.add_argument(
        "--generated-at",
        help="ISO-8601 timestamp override for deterministic tests/rebuilds.",
    )
    args = parser.parse_args()
    config = json.loads(args.config.read_text(encoding="utf-8"))
    generated_at = args.generated_at or datetime.now(UTC).isoformat()
    inventory = build_inventory(
        config,
        repo_root=REPO_ROOT,
        generated_at=generated_at,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(inventory, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    readiness = inventory["readiness"]
    print(
        "Phase F binary B0 preflight: "
        f"F6-A={'PASS' if readiness['f6a_candidate_inventory_pass'] else 'FAIL'}, "
        f"F6-B={'READY' if readiness['f6b_b0_ready'] else 'BLOCKED'}, "
        f"output={args.output}"
    )


def _inspect_tool(name: str) -> dict[str, Any]:
    executable = shutil.which(name)
    version = None
    if executable:
        try:
            result = subprocess.run(
                [executable, "--version"],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            output = result.stdout.strip() or result.stderr.strip()
            version = output.splitlines()[0] if output else None
        except (OSError, subprocess.TimeoutExpired):
            version = None
    return {
        "available": executable is not None,
        "path": executable,
        "version": version,
    }


def _path_size(path: Path) -> int:
    if path.is_file():
        return path.stat().st_size
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())


def _mapping(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("expected a JSON object")
    return value


def _mapping_list(value: Any) -> list[Mapping[str, Any]]:
    if not isinstance(value, list) or not all(
        isinstance(item, Mapping) for item in value
    ):
        raise ValueError("expected a list of JSON objects")
    return list(value)


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError("expected a list of strings")
    return list(value)


if __name__ == "__main__":
    main()
