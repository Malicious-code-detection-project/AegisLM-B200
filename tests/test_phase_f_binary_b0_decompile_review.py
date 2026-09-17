import json
from pathlib import Path

from scripts.render_phase_f_binary_b0_decompile_review import (
    annotated_source_excerpt,
    build_review,
)


def test_annotated_source_excerpt_is_bounded() -> None:
    source = "\n".join(
        [
            "line0",
            "line1",
            "/* FLAW: allocation */",
            "danger();",
            "line4",
            "line5",
            "line6",
            "/* FIX: bound */",
            "safe();",
            "line9",
        ]
    )

    excerpt = annotated_source_excerpt(source, radius=1)

    assert "0002: line1" in excerpt
    assert "0003: /* FLAW: allocation */" in excerpt
    assert "0004: danger();" in excerpt
    assert "0007: line6" in excerpt
    assert "0008: /* FIX: bound */" in excerpt
    assert "0009: safe();" in excerpt
    assert "line0" not in excerpt


def test_build_review_skips_failed_compile_variants(tmp_path: Path) -> None:
    compile_root = tmp_path / "compile"
    compile_root.mkdir()
    (compile_root / "compile-summary.json").write_text(
        json.dumps(
            {
                "results": [
                    {
                        "pair_id": "failed-pair",
                        "compiler": "gcc",
                        "optimization": "O0",
                        "archive_path": "missing.c",
                        "compile_success": False,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    assert (
        build_review(
            compile_root=compile_root,
            decompile_root=tmp_path / "decompile",
        )
        == []
    )
