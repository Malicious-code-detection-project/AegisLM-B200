from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from aegislm.experiments import runtime_compatibility as compatibility
from scripts import probe_mistral_f5x_compatibility as probe_cli


REPO_ROOT = Path(__file__).resolve().parents[1]


def _matrix_workspace(tmp_path: Path) -> Path:
    path = tmp_path / compatibility.MATRIX_PATH
    path.parent.mkdir(parents=True)
    shutil.copyfile(REPO_ROOT / compatibility.MATRIX_PATH, path)
    return path


def _read_matrix(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _write_matrix(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


def _tree_fingerprint(root: Path) -> str:
    records = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            records.append(f"F\t{relative}\t{digest}\n")
        else:
            records.append(f"D\t{relative}\t-\n")
    return hashlib.sha256("".join(records).encode()).hexdigest()


def _loaded_matrix(tmp_path: Path) -> tuple[dict[str, Any], str]:
    path = _matrix_workspace(tmp_path)
    return compatibility.load_compatibility_matrix(path, repo_root=tmp_path)


def _prepare_probe(tmp_path: Path) -> tuple[dict[str, Any], str]:
    matrix, digest = _loaded_matrix(tmp_path)
    qwen = tmp_path / matrix["qwen_environment"]
    qwen.mkdir()
    (qwen / "qwen-package.txt").write_text("frozen", encoding="utf-8")
    return matrix, digest


def _runtime_payload(
    matrix: dict[str, Any], digest: str, repo_root: Path, candidate_id: str
) -> dict[str, Any]:
    candidate = next(
        item for item in matrix["candidates"] if item["candidate_id"] == candidate_id
    )
    candidate_environment = (
        repo_root / matrix["probe_root"] / candidate["probe_directory"] / "environment"
    ).resolve()
    packages = {}
    for key, expected in compatibility._expected_runtime_packages(
        matrix, candidate
    ).items():
        package = {
            "distribution": expected["distribution"],
            "version": expected.get("version", "0.0.dev0"),
            "import": expected["import"],
        }
        if "revision" in expected:
            package.update(
                {
                    "repository": expected["repository"],
                    "revision": expected["revision"],
                }
            )
        packages[key] = package
    return {
        "schema_version": "aegislm.mistral-f5x-candidate-runtime.v1",
        "matrix_sha256": digest,
        "candidate_id": candidate_id,
        "python": "3.12.11",
        "python_prefix": str(candidate_environment),
        "cuda": "13.0",
        "gpu_names": ["NVIDIA B200", "NVIDIA B200"],
        "axolotl_cli": str(candidate_environment / "bin/axolotl"),
        "packages": packages,
        "mistral4_symbols": matrix["mistral4_symbols"],
    }


def test_matrix_loads_exact_candidates_and_raw_hash(tmp_path: Path) -> None:
    path = _matrix_workspace(tmp_path)

    matrix, digest = compatibility.load_compatibility_matrix(path, repo_root=tmp_path)

    assert [item["candidate_id"] for item in matrix["candidates"]] == list(
        compatibility.CANDIDATE_IDS
    )
    assert digest == hashlib.sha256(path.read_bytes()).hexdigest()
    assert matrix["candidates"][2]["eligible_for_final"] is False


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update({"extra": True}), "top-level schema drift"),
        (
            lambda value: value["candidates"][0].update(
                {"probe_directory": "../escape"}
            ),
            "unsafe compatibility path",
        ),
        (
            lambda value: value["candidates"][0]["axolotl"].update(
                {"revision": "0" * 40}
            ),
            "pin drift",
        ),
        (
            lambda value: value.update({"probe_root": "C:/absolute"}),
            "immutable value drift",
        ),
        (
            lambda value: value["telemetry_environment"].update(
                {"PASSWORD": "not-a-secret"}
            ),
            "telemetry policy drift",
        ),
        (
            lambda value: value["mistral4_symbols"].__setitem__(0, "TODO"),
            "placeholder",
        ),
    ],
)
def test_matrix_rejects_schema_pin_and_unsafe_value_drift(
    tmp_path: Path,
    mutation: Any,
    message: str,
) -> None:
    path = _matrix_workspace(tmp_path)
    value = _read_matrix(path)
    mutation(value)
    _write_matrix(path, value)

    with pytest.raises(ValueError, match=message):
        compatibility.load_compatibility_matrix(path, repo_root=tmp_path)


def test_validate_and_plan_are_filesystem_pure(tmp_path: Path) -> None:
    path = _matrix_workspace(tmp_path)
    before = _tree_fingerprint(tmp_path)

    matrix, _ = compatibility.load_compatibility_matrix(path, repo_root=tmp_path)
    plan = compatibility.build_probe_plan(matrix)

    assert before == _tree_fingerprint(tmp_path)
    assert plan["final_environment"] == ".venv-axolotl"
    assert not (tmp_path / matrix["probe_root"]).exists()


def test_public_validate_and_plan_cli_are_filesystem_pure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = _matrix_workspace(tmp_path)
    monkeypatch.setattr(probe_cli, "REPO_ROOT", tmp_path)
    before = _tree_fingerprint(tmp_path)

    for action in ("validate", "plan"):
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "probe_mistral_f5x_compatibility.py",
                "--matrix",
                compatibility.MATRIX_PATH.as_posix(),
                "--action",
                action,
            ],
        )
        probe_cli.main()

    capsys.readouterr()
    assert sys.dont_write_bytecode is True
    assert before == _tree_fingerprint(tmp_path)
    assert path.is_file()


def test_public_cli_rejects_arbitrary_matrix_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    approved = _matrix_workspace(tmp_path)
    copied = tmp_path / "copied-matrix.json"
    shutil.copyfile(approved, copied)
    monkeypatch.setattr(probe_cli, "REPO_ROOT", tmp_path)

    assert probe_cli._resolve_matrix_argument(compatibility.MATRIX_PATH) == approved
    with pytest.raises(ValueError, match="repository-owned"):
        probe_cli._resolve_matrix_argument(copied)


def test_plan_uses_normal_resolver_and_uv_pip_check(tmp_path: Path) -> None:
    matrix, _ = _loaded_matrix(tmp_path)

    plan = compatibility.build_probe_plan(matrix)

    commands = [
        command for candidate in plan["candidates"] for command in candidate["commands"]
    ]
    flattened = [part for command in commands for part in command]
    assert all(option not in flattened for option in compatibility.PROHIBITED_OPTIONS)
    for candidate in plan["candidates"]:
        assert candidate["commands"][1][:3] == ["uv", "pip", "install"]
        assert candidate["commands"][2][:3] == ["uv", "pip", "check"]
    assert "transformers==5.14.1" in plan["candidates"][0]["commands"][1]
    assert "transformers==5.9.0" in plan["candidates"][1]["commands"][1]
    assert any(
        "d24d79da55f7ee6e538a460d3025e41dcc41ab21" in part
        for part in plan["candidates"][2]["commands"][1]
    )


def test_probe_requires_exact_raw_byte_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    matrix, digest = _prepare_probe(tmp_path)
    monkeypatch.setattr(compatibility.platform, "system", lambda: "Linux")
    monkeypatch.setattr(compatibility.shutil, "which", lambda _: "/usr/bin/uv")

    with pytest.raises(RuntimeError, match="is required"):
        compatibility.probe_compatibility_matrix(
            matrix, matrix_sha256=digest, repo_root=tmp_path, environ={}
        )
    with pytest.raises(RuntimeError, match="raw matrix bytes"):
        compatibility.probe_compatibility_matrix(
            matrix,
            matrix_sha256=digest,
            repo_root=tmp_path,
            environ={matrix["approval_environment"]: "0" * 64},
        )
    assert not (tmp_path / matrix["probe_root"]).exists()


def test_probe_refuses_existing_exclusive_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    matrix, digest = _prepare_probe(tmp_path)
    probe_root = tmp_path / matrix["probe_root"]
    probe_root.mkdir(parents=True)
    monkeypatch.setattr(compatibility.platform, "system", lambda: "Linux")
    monkeypatch.setattr(compatibility.shutil, "which", lambda _: "/usr/bin/uv")

    with pytest.raises(FileExistsError, match="exclusive probe root"):
        compatibility.probe_compatibility_matrix(
            matrix,
            matrix_sha256=digest,
            repo_root=tmp_path,
            environ={matrix["approval_environment"]: digest},
        )


def test_probe_records_exact_commands_and_preserves_qwen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    matrix, digest = _prepare_probe(tmp_path)
    monkeypatch.setattr(compatibility.platform, "system", lambda: "Linux")
    monkeypatch.setattr(compatibility.shutil, "which", lambda _: "/usr/bin/uv")
    calls: list[list[str]] = []

    def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        joined = " ".join(command)
        if "approved-negative-control" in joined and command[:3] == [
            "uv",
            "pip",
            "install",
        ]:
            return subprocess.CompletedProcess(command, 1, "", "resolver conflict")
        candidate_id = next(
            item for item in compatibility.CANDIDATE_IDS if item in joined
        )
        stdout = (
            json.dumps(_runtime_payload(matrix, digest, tmp_path, candidate_id))
            if "-c" in command
            else "ok"
        )
        return subprocess.CompletedProcess(command, 0, stdout, "")

    inventory = compatibility.probe_compatibility_matrix(
        matrix,
        matrix_sha256=digest,
        repo_root=tmp_path,
        environ={matrix["approval_environment"]: digest},
        runner=runner,
    )

    assert inventory["compatible_candidates"] == [
        "current-declared",
        "official-v0-17",
    ]
    assert inventory["qwen_environment_unchanged"] is True
    assert inventory["final_environment_created"] is False
    assert inventory["candidates"][2]["result"] == "expected-conflict"
    assert len(calls) == 10
    assert (tmp_path / matrix["probe_root"] / "inventory.json").is_file()
    assert all(
        (tmp_path / matrix["probe_root"] / item / "evidence.json").is_file()
        for item in compatibility.CANDIDATE_IDS
    )


def test_probe_blocks_when_qwen_fingerprint_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    matrix, digest = _prepare_probe(tmp_path)
    monkeypatch.setattr(compatibility.platform, "system", lambda: "Linux")
    monkeypatch.setattr(compatibility.shutil, "which", lambda _: "/usr/bin/uv")
    changed = False

    def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        nonlocal changed
        if not changed:
            (tmp_path / ".venv/qwen-package.txt").write_text(
                "mutated", encoding="utf-8"
            )
            changed = True
        joined = " ".join(command)
        candidate_id = next(
            item for item in compatibility.CANDIDATE_IDS if item in joined
        )
        stdout = (
            json.dumps(_runtime_payload(matrix, digest, tmp_path, candidate_id))
            if "-c" in command
            else "ok"
        )
        return subprocess.CompletedProcess(command, 0, stdout, "")

    with pytest.raises(RuntimeError, match="Qwen environment fingerprint changed"):
        compatibility.probe_compatibility_matrix(
            matrix,
            matrix_sha256=digest,
            repo_root=tmp_path,
            environ={matrix["approval_environment"]: digest},
            runner=runner,
        )

    inventory = json.loads(
        (tmp_path / matrix["probe_root"] / "inventory.json").read_text(encoding="utf-8")
    )
    assert inventory["qwen_environment_unchanged"] is False


def test_fingerprint_includes_file_content(tmp_path: Path) -> None:
    qwen = tmp_path / ".venv"
    qwen.mkdir()
    package = qwen / "package.txt"
    package.write_text("before", encoding="utf-8")
    before = compatibility.fingerprint_environment(qwen, repo_root=tmp_path)

    package.write_text("after", encoding="utf-8")
    after = compatibility.fingerprint_environment(qwen, repo_root=tmp_path)

    assert before["sha256"] != after["sha256"]


def test_negative_control_can_never_be_promoted(tmp_path: Path) -> None:
    matrix, _ = _loaded_matrix(tmp_path)
    negative = matrix["candidates"][2]

    assert negative["kind"] == "negative-control"
    assert negative["eligible_for_final"] is False
    assert negative["expected_resolution"] == "conflict"


def test_incomplete_child_evidence_is_not_compatible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    matrix, digest = _prepare_probe(tmp_path)
    monkeypatch.setattr(compatibility.platform, "system", lambda: "Linux")
    monkeypatch.setattr(compatibility.shutil, "which", lambda _: "/usr/bin/uv")

    def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        stdout = json.dumps({"runtime": "incomplete"}) if "-c" in command else "ok"
        return subprocess.CompletedProcess(command, 0, stdout, "")

    inventory = compatibility.probe_compatibility_matrix(
        matrix,
        matrix_sha256=digest,
        repo_root=tmp_path,
        environ={matrix["approval_environment"]: digest},
        runner=runner,
    )

    assert inventory["compatible_candidates"] == []
    assert inventory["candidates"][0]["result"] == "incompatible"
    assert inventory["candidates"][0]["runtime_validation_errors"] == [
        "candidate runtime evidence schema drift"
    ]


def test_child_evidence_must_match_matrix_and_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    matrix, digest = _prepare_probe(tmp_path)
    candidate = matrix["candidates"][0]
    evidence = _runtime_payload(matrix, "0" * 64, tmp_path, candidate["candidate_id"])

    errors = compatibility._validate_child_runtime_evidence(
        evidence,
        matrix=matrix,
        matrix_sha256=digest,
        candidate=candidate,
        candidate_environment=(
            tmp_path
            / matrix["probe_root"]
            / candidate["probe_directory"]
            / "environment"
        ),
    )

    assert "candidate runtime evidence matrix hash mismatch" in errors


def test_runtime_collection_rejects_wrong_python_before_imports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _matrix_workspace(tmp_path)
    monkeypatch.setattr(
        compatibility.sys,
        "version_info",
        SimpleNamespace(major=3, minor=11),
    )

    with pytest.raises(RuntimeError, match="active Python"):
        compatibility.collect_runtime_evidence(path, "current-declared")
