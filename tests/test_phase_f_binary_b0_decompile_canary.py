from pathlib import Path

import pytest

from scripts.run_phase_f_binary_b0_decompile_canary import (
    parse_function_manifest,
)


def test_parse_function_manifest(tmp_path: Path) -> None:
    manifest = tmp_path / "functions.tsv"
    manifest.write_text(
        "label\tfull_name\toutput_file\tcompleted\n"
        "present\tScope::bad\t00-present.c\ttrue\n"
        "not_observed\tScope::good\t01-not-observed.c\ttrue\n",
        encoding="utf-8",
    )

    assert parse_function_manifest(manifest) == [
        {
            "label": "present",
            "full_name": "Scope::bad",
            "output_file": "00-present.c",
            "completed": "true",
        },
        {
            "label": "not_observed",
            "full_name": "Scope::good",
            "output_file": "01-not-observed.c",
            "completed": "true",
        },
    ]


def test_parse_function_manifest_rejects_invalid_header(tmp_path: Path) -> None:
    manifest = tmp_path / "functions.tsv"
    manifest.write_text("wrong\n", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid Ghidra function manifest"):
        parse_function_manifest(manifest)
