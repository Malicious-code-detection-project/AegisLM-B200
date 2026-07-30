import json
import zipfile
from pathlib import Path

import pytest

from scripts.run_phase_f_binary_b0_compile_canary import (
    _extract_members,
    _select_candidates,
)


def test_extract_members_limits_content_and_blocks_traversal(tmp_path: Path) -> None:
    archive = tmp_path / "suite.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("C/testcases/example.c", "void bad(void) {}")
        bundle.writestr("C/testcasesupport/header.h", "#pragma once")
        bundle.writestr("private/unused.txt", "unused")
    output = tmp_path / "output"

    _extract_members(
        archive,
        output,
        ["C/testcases/example.c", "C/testcasesupport/"],
    )

    assert (output / "C/testcases/example.c").is_file()
    assert (output / "C/testcasesupport/header.h").is_file()
    assert not (output / "private/unused.txt").exists()


def test_extract_members_rejects_zip_slip(tmp_path: Path) -> None:
    archive = tmp_path / "suite.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("../escape.c", "void bad(void) {}")

    with pytest.raises(ValueError, match="unsafe archive member"):
        _extract_members(archive, tmp_path / "output", ["../escape.c"])


def test_candidate_fixture_is_json_serializable() -> None:
    fixture = {
        "schema_version": "aegislm.phase-f-binary-b0-compile-canary.v1",
        "object_execution_count": 0,
    }

    assert json.loads(json.dumps(fixture))["object_execution_count"] == 0


def test_select_candidates_accepts_b0_primary_and_f7_pilot() -> None:
    manifest = {
        "candidates": [
            {"pair_id": "accepted", "queue": "accepted"},
            {"pair_id": "b0", "queue": "primary"},
            {"pair_id": "f7", "queue": "pilot"},
        ]
    }

    selected = _select_candidates(manifest, limit=2)

    assert [row["pair_id"] for row in selected] == ["b0", "f7"]
