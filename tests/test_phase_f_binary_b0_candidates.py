import pytest

from scripts.select_phase_f_binary_b0_candidates import select_candidates


def _pair(
    group: str,
    cwe: str,
    *,
    split: str = "train",
) -> list[dict[str, object]]:
    common: dict[str, object] = {
        "group_id": group,
        "split": split,
        "cwe": cwe,
        "archive_path": f"C/testcases/{group}.cpp",
        "source_sha256": f"source-{group}",
        "contains_executable_payload": False,
        "disposition": "eligible",
    }
    return [
        {
            **common,
            "record_id": f"{group}-present",
            "label": "present",
            "code_sha256": f"{group}-present-code",
        },
        {
            **common,
            "record_id": f"{group}-not-observed",
            "label": "not_observed",
            "code_sha256": f"{group}-not-observed-code",
        },
    ]


def test_candidate_queue_is_deterministic_and_stratified() -> None:
    rows: list[dict[str, object]] = []
    for index in range(6):
        rows.extend(_pair(f"a-{index}", "CWE-122"))
    for index in range(3):
        rows.extend(_pair(f"b-{index}", "CWE-476"))
    for index in range(3):
        rows.extend(_pair(f"c-{index}", "CWE-787"))

    first = select_candidates(rows, primary_pairs=6, reserve_pairs=3)
    second = select_candidates(list(reversed(rows)), primary_pairs=6, reserve_pairs=3)

    assert first == second
    assert first["metrics"]["supply_pass"] is True
    assert first["metrics"]["primary_cwe_count"] == 3
    assert first["metrics"]["maximum_primary_cwe_fraction"] <= 1 / 3
    assert {
        item["target_preservation_audit"]["status"] for item in first["candidates"]
    } == {"pending"}


def test_candidate_queue_rejects_incomplete_and_payload_groups() -> None:
    rows = _pair("valid", "CWE-122")
    rows.extend(_pair("payload", "CWE-476"))
    rows[-1]["contains_executable_payload"] = True
    rows.append(
        {
            **_pair("incomplete", "CWE-787")[0],
        }
    )

    result = select_candidates(rows, primary_pairs=1, reserve_pairs=0)

    assert result["metrics"]["primary_pair_count"] == 1
    assert result["metrics"]["rejected_pair_count"] == 2
    assert {row["reason"] for row in result["structural_rejections"]} == {
        "pair_must_contain_exactly_two_records",
        "source_manifest_contains_executable_payload",
    }


def test_candidate_queue_does_not_use_blind_test_rows() -> None:
    rows = _pair("train", "CWE-122")
    rows.extend(_pair("blind", "CWE-476", split="test"))

    result = select_candidates(rows, primary_pairs=1, reserve_pairs=0)

    assert [row["target_cwe"] for row in result["candidates"]] == ["CWE-122"]


def test_candidate_queue_excludes_windows_specific_sources() -> None:
    rows = _pair("portable", "CWE-122")
    windows = _pair("windows", "CWE-15")
    for row in windows:
        row["archive_path"] = "C/testcases/example__w32_03.c"
    rows.extend(windows)

    result = select_candidates(rows, primary_pairs=1, reserve_pairs=0)

    assert result["metrics"]["primary_pair_count"] == 1
    assert result["structural_rejections"] == [
        {
            "group_id": "windows",
            "disposition": "reject",
            "reason": "windows_specific_source_excluded_from_linux_b0",
        }
    ]


@pytest.mark.parametrize(
    "archive_path",
    [
        "C/testcases/example__wchar_t_environment_ifstream_08.cpp",
        ("C/testcases/CWE36/s03/example__wchar_t_connect_socket_open_08.cpp"),
        ("C/testcases/CWE36/s04/example__wchar_t_listen_socket_fopen_02.cpp"),
    ],
)
def test_candidate_queue_excludes_nonportable_wide_file_api(
    archive_path: str,
) -> None:
    rows = _pair("portable", "CWE-122")
    wide = _pair("wide", "CWE-23")
    for row in wide:
        row["archive_path"] = archive_path
    rows.extend(wide)

    result = select_candidates(rows, primary_pairs=1, reserve_pairs=0)

    assert result["metrics"]["primary_pair_count"] == 1
    assert result["structural_rejections"][0]["reason"] == (
        "nonportable_wide_file_api_excluded_from_linux_b0"
    )
