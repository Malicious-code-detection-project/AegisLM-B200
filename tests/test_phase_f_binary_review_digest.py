from scripts.render_phase_f_binary_review_digest import (
    build_digest,
    relevant_lines,
)


def test_relevant_lines_removes_bulk_initialization() -> None:
    text = """
dataBuffer[0] = '\\0';
if (size < 10) {
  memcpy(dest, source, size);
}
"""

    assert relevant_lines(text, maximum_lines=5) == [
        "if (size < 10) {",
        "memcpy(dest, source, size);",
    ]


def test_digest_groups_variants_without_approving() -> None:
    entries = [
        {
            "pair_id": "pair-a",
            "target_cwe": "CWE-121",
            "private_source_path": "private.c",
            "compiler": compiler,
            "optimization": "O2",
            "source_annotation_excerpt": "/* FLAW */ memcpy(a, b, n);",
            "present_pseudo_c": "memcpy(a, b, n);",
            "not_observed_pseudo_c": "if (n < 10) memcpy(a, b, n);",
        }
        for compiler in ("gcc", "clang")
    ]

    digest = build_digest(
        entries,
        {"pair_flags": {"pair-a": ["source_operation_not_recovered"]}},
    )

    assert len(digest) == 1
    assert len(digest[0]["variants"]) == 2
    assert digest[0]["triage_flags"] == ["source_operation_not_recovered"]
    assert digest[0]["operator_decision"] == "pending"
