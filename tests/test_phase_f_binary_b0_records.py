from scripts.build_phase_f_binary_b0_records import (
    extract_imports,
    extract_labeled_assembly,
    prompt_leakage,
)


def test_extract_labeled_assembly_hides_symbols_and_respects_labels() -> None:
    assembly = """
0000 <CWE121_case_bad>:
   0:  e8 00 00 00 00        call   5 <CWE121_case_helper>
   5:  c3                    ret
0010 <CWE121_case_good>:
  10:  90                    nop
  11:  c3                    ret
"""

    present = extract_labeled_assembly(assembly, label="present")
    fixed = extract_labeled_assembly(assembly, label="not_observed")

    assert present == ["call   5 <symbol>", "ret"]
    assert fixed == ["nop", "ret"]
    assert "CWE121" not in " ".join(present + fixed)


def test_extract_imports_keeps_only_non_source_undefined_symbols() -> None:
    nm = """
                 U malloc@@GLIBC_2.2.5
                 U CWE121_case_good
"""

    assert extract_imports(nm) == ["malloc"]


def test_prompt_leakage_detects_private_boundaries() -> None:
    prompt = '{"target_cwe":"CWE-121","pseudo_c":"CWE121_case_bad()"}'

    assert prompt_leakage(prompt) == [
        "source symbol",
        "Juliet label symbol",
    ]
