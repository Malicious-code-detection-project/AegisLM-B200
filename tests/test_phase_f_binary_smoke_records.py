from scripts.build_phase_f_binary_smoke_records import (
    extract_assembly_blocks,
    sanitize_pseudo_c,
)


def test_binary_smoke_sanitizes_source_namespace_and_juliet_labels() -> None:
    pseudo_c = """
void CWE122_Heap_Based_Buffer_Overflow__case::bad(void) {
  goodG2B();
  __assert_fail("x", "C/testcases/CWE617_case.c", 1, "CWE617_case_bad");
}
"""

    sanitized = sanitize_pseudo_c(pseudo_c)

    assert "CWE122_Heap" not in sanitized
    assert "::bad" not in sanitized
    assert "goodG2B" not in sanitized
    assert "C/testcases" not in sanitized
    assert "CWE617_case_bad" not in sanitized
    assert "target_function" in sanitized
    assert "target_helper" in sanitized


def test_binary_smoke_extracts_only_bounded_target_assembly() -> None:
    assembly = """
0000000000401000 <unrelated()>:
  401000:  c3                    ret
0000000000401010 <Namespace::bad()>:
  401010:  e8 00 00 00 00        call   401015 <Namespace::helper()>
  401015:  c3                    ret
0000000000401020 <another()>:
  401020:  90                    nop
"""

    selected = extract_assembly_blocks(
        assembly,
        function_suffixes=("::bad()",),
    )

    assert selected == ["call   401015 <symbol>", "ret"]
