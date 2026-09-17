from scripts.triage_phase_f_binary_b0_review import triage_review


def _entry(
    *,
    optimization: str,
    present: str,
    negative: str,
) -> dict[str, object]:
    return {
        "pair_id": "pair",
        "target_cwe": "CWE-476",
        "compiler": "gcc",
        "optimization": optimization,
        "source_annotation_excerpt": "data = NULL; free(data);",
        "present_pseudo_c": present,
        "not_observed_pseudo_c": negative,
    }


def test_triage_flags_o2_evidence_collapse_without_auto_approval() -> None:
    result = triage_review(
        [
            _entry(
                optimization="O0",
                present="void f() {" + "data = malloc(4);" * 30 + "}",
                negative="void g() {" + "data = malloc(4); free(data);" * 30 + "}",
            ),
            _entry(
                optimization="O2",
                present="void f() {}",
                negative="void g() {" + "free(data);" * 20 + "}",
            ),
        ]
    )

    assert result["policy"]["automatic_pair_approval"] is False
    assert "present_o2_evidence_collapse" in result["cases"][1]["flags"]
    assert result["flagged_pair_ids"] == ["pair"]
