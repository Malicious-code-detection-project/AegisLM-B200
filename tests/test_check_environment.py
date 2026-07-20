from scripts.check_environment import _profile_venv_check


def test_missing_fast_venv_is_blocked_when_optional(tmp_path):
    result = _profile_venv_check(
        tmp_path / ".venv-fast",
        profile="fast",
        require_fast=False,
    )

    assert result.status == "BLOCKED"


def test_missing_fast_venv_fails_when_required(tmp_path):
    result = _profile_venv_check(
        tmp_path / ".venv-fast",
        profile="fast",
        require_fast=True,
    )

    assert result.status == "FAIL"
