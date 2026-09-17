from __future__ import annotations

from pathlib import Path

from scripts.preflight_phase_f_binary_b0 import (
    assess_readiness,
    inspect_local_source,
)


def _tool(available: bool) -> dict[str, object]:
    return {"available": available, "path": None, "version": None}


def test_binary_b0_preflight_requires_approved_source_and_full_toolchain(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "sard.zip"
    archive.write_bytes(b"fixture")
    source = inspect_local_source(
        {
            "id": "sard",
            "path": "sard.zip",
            "kind": "file",
            "license_status": "approved",
            "contains_raw_executable": False,
        },
        repo_root=tmp_path,
    )
    tools = {
        "gcc": _tool(True),
        "clang": _tool(False),
        "objdump": _tool(True),
        "ghidra": _tool(False),
    }

    result = assess_readiness(
        local_sources=[source],
        selected_source_ids=["sard"],
        tools=tools,
        required_compilers=["gcc", "clang"],
        required_static_tools=["objdump"],
        decompiler_any_of=["ghidra"],
    )

    assert result["f6a_candidate_inventory_pass"]
    assert not result["f6b_b0_ready"]
    assert result["missing_compilers"] == ["clang"]
    assert result["available_decompilers"] == []


def test_binary_b0_preflight_passes_when_all_gates_are_available(
    tmp_path: Path,
) -> None:
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "sample.c").write_text("int main(void) { return 0; }")
    source = inspect_local_source(
        {
            "id": "source",
            "path": "source",
            "kind": "directory",
            "license_status": "approved",
            "contains_raw_executable": False,
        },
        repo_root=tmp_path,
    )
    tools = {
        "gcc": _tool(True),
        "clang": _tool(True),
        "objdump": _tool(True),
        "ghidra": _tool(True),
    }

    result = assess_readiness(
        local_sources=[source],
        selected_source_ids=["source"],
        tools=tools,
        required_compilers=["gcc", "clang"],
        required_static_tools=["objdump"],
        decompiler_any_of=["ghidra"],
    )

    assert result["f6a_candidate_inventory_pass"]
    assert result["f6b_b0_ready"]
    assert result["blockers"] == []


def test_ghidra_exporter_includes_juliet_helper_functions() -> None:
    source = Path("scripts/ghidra/ExportJulietFunctions.java").read_text(
        encoding="utf-8"
    )

    assert 'name.startsWith("bad")' in source
    assert 'name.startsWith("good")' in source
