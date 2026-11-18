"""Safe compatibility probing for isolated Mistral F5-X runtimes."""

from __future__ import annotations

import hashlib
import importlib
import importlib.metadata
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable


MATRIX_PATH = Path("configs/runtime/mistral_f5x_compatibility_matrix.json")
SCHEMA_VERSION = "aegislm.mistral-f5x-compatibility-matrix.v1"
EVIDENCE_VERSION = "aegislm.mistral-f5x-compatibility-evidence.v1"
MATRIX_KEYS = (
    "schema_version",
    "work_order_id",
    "probe_root",
    "approval_environment",
    "python_version",
    "torch_backend",
    "cuda_version",
    "gpu_count",
    "gpu_name_contains",
    "qwen_environment",
    "final_environment",
    "telemetry_environment",
    "shared_packages",
    "candidates",
    "mistral4_symbols",
    "prohibited_options",
)
SHARED_PACKAGE_KEYS = (
    "torch",
    "cut_cross_entropy",
    "flash_attn",
    "bitsandbytes",
    "torchao",
)
CANDIDATE_IDS = (
    "current-declared",
    "official-v0-17",
    "approved-negative-control",
)
APPROVED_VALUES = {
    "work_order_id": "mistral-f5x-runtime-compatibility-matrix-v1",
    "probe_root": ".runtime-probes/mistral-f5x",
    "approval_environment": "AEGISLM_APPROVED_COMPATIBILITY_MATRIX_SHA256",
    "python_version": "3.12",
    "torch_backend": "cu130",
    "cuda_version": "13.0",
    "gpu_count": 2,
    "gpu_name_contains": "B200",
    "qwen_environment": ".venv",
    "final_environment": ".venv-axolotl",
}
EXPECTED_CANDIDATES = {
    "current-declared": {
        "kind": "declared-consistent",
        "probe_directory": "current-declared",
        "eligible_for_final": True,
        "expected_resolution": "pass",
        "axolotl_revision": "3c8334b6f9ae6bf5596f99a1845525c8ffc0a97a",
        "declared_transformers": "5.14.1",
        "transformers_version": "5.14.1",
    },
    "official-v0-17": {
        "kind": "official-consistent",
        "probe_directory": "official-v0-17",
        "eligible_for_final": True,
        "expected_resolution": "pass",
        "axolotl_revision": "09d325b4fd1288b1473c8a330dd19e3c91b1ac32",
        "declared_transformers": "5.9.0",
        "transformers_version": "5.9.0",
    },
    "approved-negative-control": {
        "kind": "negative-control",
        "probe_directory": "approved-negative-control",
        "eligible_for_final": False,
        "expected_resolution": "conflict",
        "axolotl_revision": "3c8334b6f9ae6bf5596f99a1845525c8ffc0a97a",
        "declared_transformers": "5.14.1",
        "transformers_revision": "d24d79da55f7ee6e538a460d3025e41dcc41ab21",
        "observed_version": "5.15.0.dev0",
    },
}
AXOLOTL_REPOSITORY = "https://github.com/axolotl-ai-cloud/axolotl.git"
TRANSFORMERS_REPOSITORY = "https://github.com/huggingface/transformers.git"
CCE_REPOSITORY = "https://github.com/axolotl-ai-cloud/ml-cross-entropy.git"
CCE_REVISION = "5f0c7a7778b5b17d37738fae10065ed3034373af"
MISTRAL4_SYMBOLS = (
    "transformers.models.mistral4.configuration_mistral4:Mistral4Config",
    "transformers.models.mistral4.modeling_mistral4:Mistral4DecoderLayer",
)
PROHIBITED_OPTIONS = (
    "--no-deps",
    "--system",
    "--break-system-packages",
)
_SECRET_KEY_PARTS = {"secret", "password", "token", "api_key", "private_key"}
_PLACEHOLDER_PATTERN = re.compile(
    r"(?:\$\{|<[^>]+>|\b(?:TODO|TBD|CHANGEME|CHANGE_ME|REPLACE_ME)\b)", re.I
)
_WINDOWS_ABSOLUTE = re.compile(r"^[A-Za-z]:[\\/]")


def load_compatibility_matrix(
    path: Path, *, repo_root: Path
) -> tuple[dict[str, Any], str]:
    """Load and validate the exact frozen matrix, returning its raw-byte hash."""
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid compatibility matrix: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise ValueError("compatibility matrix must be an object")
    _validate_matrix(value, repo_root=repo_root)
    return value, hashlib.sha256(raw).hexdigest()


def build_probe_plan(matrix: dict[str, Any]) -> dict[str, Any]:
    """Render a deterministic command plan without touching the filesystem."""
    candidates = []
    for candidate in matrix["candidates"]:
        candidates.append(
            {
                "candidate_id": candidate["candidate_id"],
                "eligible_for_final": candidate["eligible_for_final"],
                "expected_resolution": candidate["expected_resolution"],
                "commands": _candidate_commands(matrix, candidate),
            }
        )
    return {
        "schema_version": "aegislm.mistral-f5x-compatibility-plan.v1",
        "probe_root": matrix["probe_root"],
        "qwen_environment": matrix["qwen_environment"],
        "final_environment": matrix["final_environment"],
        "candidates": candidates,
        "post_probe_check": "Qwen environment fingerprint must be unchanged",
    }


def probe_compatibility_matrix(
    matrix: dict[str, Any],
    *,
    matrix_sha256: str,
    repo_root: Path,
    environ: dict[str, str] | None = None,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    """Run approved probes in new directories and preserve auditable evidence."""
    environment = os.environ if environ is None else environ
    approval_name = matrix["approval_environment"]
    approved = environment.get(approval_name, "")
    if not approved:
        raise RuntimeError(f"{approval_name} is required for probe")
    if approved != matrix_sha256:
        raise RuntimeError(f"{approval_name} does not match raw matrix bytes")
    if platform.system() != "Linux":
        raise RuntimeError("compatibility probe is allowed only on Linux B200")
    if shutil.which("uv") is None:
        raise RuntimeError("uv is required and must already be installed")

    probe_root = _safe_repo_path(repo_root, matrix["probe_root"])
    if probe_root.exists():
        raise FileExistsError(f"exclusive probe root already exists: {probe_root}")

    before = fingerprint_environment(
        _safe_repo_path(repo_root, matrix["qwen_environment"]), repo_root=repo_root
    )
    probe_root.mkdir(parents=True, exist_ok=False)
    process_env = dict(environment)
    process_env["UV_TORCH_BACKEND"] = matrix["torch_backend"]
    process_env.update(matrix["telemetry_environment"])
    candidate_evidence: list[dict[str, Any]] = []
    unexpected_error: BaseException | None = None
    try:
        for candidate in matrix["candidates"]:
            candidate_evidence.append(
                _probe_candidate(
                    matrix,
                    candidate,
                    matrix_sha256=matrix_sha256,
                    repo_root=repo_root,
                    process_env=process_env,
                    runner=runner,
                )
            )
    except BaseException as exc:  # evidence and Qwen verification must survive
        unexpected_error = exc

    after = fingerprint_environment(
        _safe_repo_path(repo_root, matrix["qwen_environment"]), repo_root=repo_root
    )
    qwen_unchanged = before == after
    compatible = [
        item["candidate_id"]
        for item in candidate_evidence
        if item["result"] == "compatible" and item["eligible_for_final"]
    ]
    inventory = {
        "schema_version": EVIDENCE_VERSION,
        "work_order_id": matrix["work_order_id"],
        "matrix_path": MATRIX_PATH.as_posix(),
        "matrix_sha256": matrix_sha256,
        "qwen_fingerprint_before": before,
        "qwen_fingerprint_after": after,
        "qwen_environment_unchanged": qwen_unchanged,
        "compatible_candidates": compatible,
        "final_environment_created": False,
        "candidates": candidate_evidence,
    }
    _write_json_exclusive(probe_root / "inventory.json", inventory)
    if not qwen_unchanged:
        raise RuntimeError("existing Qwen environment fingerprint changed during probe")
    if unexpected_error is not None:
        raise RuntimeError(
            "compatibility probe aborted; inspect inventory evidence"
        ) from unexpected_error
    return inventory


def fingerprint_environment(path: Path, *, repo_root: Path) -> dict[str, Any]:
    """Fingerprint a local environment without following symlinks."""
    safe_path = _safe_repo_path(repo_root, path.relative_to(repo_root).as_posix())
    if not safe_path.exists() or not safe_path.is_dir() or safe_path.is_symlink():
        raise RuntimeError(
            f"Qwen environment must be an existing local directory: {safe_path}"
        )
    records: list[str] = []
    for current, directory_names, file_names in os.walk(safe_path, followlinks=False):
        current_path = Path(current)
        directory_names.sort()
        file_names.sort()
        for name in directory_names:
            entry = current_path / name
            relative = entry.relative_to(safe_path).as_posix()
            if entry.is_symlink():
                records.append(f"L\t{relative}\t{os.readlink(entry)}\n")
            else:
                records.append(f"D\t{relative}\t-\n")
        for name in file_names:
            entry = current_path / name
            relative = entry.relative_to(safe_path).as_posix()
            if entry.is_symlink():
                records.append(f"L\t{relative}\t{os.readlink(entry)}\n")
            else:
                digest = _sha256_file(entry)
                records.append(f"F\t{relative}\t{entry.stat().st_size}:{digest}\n")
    serialized = "".join(records).encode("utf-8")
    return {
        "path": safe_path.relative_to(repo_root).as_posix(),
        "entry_count": len(records),
        "sha256": hashlib.sha256(serialized).hexdigest(),
    }


def collect_runtime_evidence(matrix_path: Path, candidate_id: str) -> dict[str, Any]:
    """Collect evidence from inside a candidate interpreter."""
    repo_root = Path.cwd().resolve()
    matrix, matrix_sha256 = load_compatibility_matrix(matrix_path, repo_root=repo_root)
    active_python = f"{sys.version_info.major}.{sys.version_info.minor}"
    if active_python != matrix["python_version"]:
        raise RuntimeError(
            "active Python does not match the compatibility matrix: "
            f"{active_python}!={matrix['python_version']}"
        )
    candidate = next(
        (item for item in matrix["candidates"] if item["candidate_id"] == candidate_id),
        None,
    )
    if candidate is None:
        raise ValueError(f"unknown compatibility candidate: {candidate_id}")
    packages = _expected_runtime_packages(matrix, candidate)
    observed: dict[str, Any] = {}
    imported: dict[str, Any] = {}
    for key, package in packages.items():
        distribution = importlib.metadata.distribution(package["distribution"])
        version = distribution.version
        expected_version = package.get("version")
        if (
            expected_version is not None
            and version.split("+", 1)[0] != expected_version
        ):
            raise RuntimeError(
                f"{package['distribution']} version drift: "
                f"{version}!={expected_version}"
            )
        expected_revision = package.get("revision")
        if expected_revision is not None:
            _verify_direct_url(distribution, package["repository"], expected_revision)
        imported[key] = importlib.import_module(package["import"])
        observed[key] = {
            "distribution": package["distribution"],
            "version": version,
            **(
                {"repository": package["repository"], "revision": expected_revision}
                if expected_revision is not None
                else {}
            ),
            "import": package["import"],
        }

    torch = imported["torch"]
    if torch.version.cuda != matrix["cuda_version"]:
        raise RuntimeError(
            f"PyTorch CUDA drift: {torch.version.cuda}!={matrix['cuda_version']}"
        )
    count = int(torch.cuda.device_count())
    if count != matrix["gpu_count"]:
        raise RuntimeError(f"runtime requires exactly {matrix['gpu_count']} GPUs")
    gpu_names = [str(torch.cuda.get_device_name(index)) for index in range(count)]
    if any(matrix["gpu_name_contains"] not in name for name in gpu_names):
        raise RuntimeError("runtime GPU identity does not match the B200 contract")

    executable = shutil.which("axolotl")
    if executable is None:
        raise RuntimeError("axolotl CLI is not available on PATH")
    executable_path = Path(executable).resolve()
    try:
        executable_path.relative_to(Path(sys.prefix).resolve())
    except ValueError as exc:
        raise RuntimeError("axolotl CLI is outside the candidate environment") from exc

    symbols: list[str] = []
    for item in matrix["mistral4_symbols"]:
        module_name, symbol_name = item.split(":", 1)
        module = importlib.import_module(module_name)
        if not hasattr(module, symbol_name):
            raise RuntimeError(f"Mistral 4 symbol is missing: {item}")
        symbols.append(item)
    return {
        "schema_version": "aegislm.mistral-f5x-candidate-runtime.v1",
        "matrix_sha256": matrix_sha256,
        "candidate_id": candidate_id,
        "python": sys.version.split()[0],
        "python_prefix": str(Path(sys.prefix).resolve()),
        "cuda": torch.version.cuda,
        "gpu_names": gpu_names,
        "axolotl_cli": str(executable_path),
        "packages": observed,
        "mistral4_symbols": symbols,
    }


def runtime_evidence_cli(matrix_path: str, candidate_id: str) -> None:
    """Print child-interpreter evidence for the fixed parent probe command."""
    print(
        json.dumps(
            collect_runtime_evidence(Path(matrix_path), candidate_id),
            sort_keys=True,
        )
    )


def _validate_matrix(matrix: dict[str, Any], *, repo_root: Path) -> None:
    _require_keys(matrix, MATRIX_KEYS, "top-level")
    if matrix["schema_version"] != SCHEMA_VERSION:
        raise ValueError("compatibility matrix schema version drift")
    for key, expected in APPROVED_VALUES.items():
        if matrix[key] != expected or type(matrix[key]) is not type(expected):
            raise ValueError(f"compatibility matrix immutable value drift: {key}")
    if matrix["telemetry_environment"] != {"AXOLOTL_DO_NOT_TRACK": "1"}:
        raise ValueError("compatibility matrix telemetry policy drift")
    _validate_safe_values(matrix)
    _validate_paths(matrix, repo_root=repo_root)
    _validate_shared_packages(matrix["shared_packages"])
    candidates = matrix["candidates"]
    if not isinstance(candidates, list) or len(candidates) != len(CANDIDATE_IDS):
        raise ValueError("compatibility candidate set drift")
    candidate_ids = tuple(
        item.get("candidate_id") for item in candidates if isinstance(item, dict)
    )
    if candidate_ids != CANDIDATE_IDS:
        raise ValueError("compatibility candidate order drift")
    for candidate in candidates:
        _validate_candidate(candidate)
    if matrix["mistral4_symbols"] != list(MISTRAL4_SYMBOLS):
        raise ValueError("Mistral 4 symbol contract drift")
    if matrix["prohibited_options"] != list(PROHIBITED_OPTIONS):
        raise ValueError("prohibited dependency override policy drift")
    plan = build_probe_plan(matrix)
    flattened = [
        part
        for item in plan["candidates"]
        for command in item["commands"]
        for part in command
    ]
    if any(option in flattened for option in PROHIBITED_OPTIONS):
        raise ValueError("probe plan contains a prohibited dependency override")


def _validate_shared_packages(packages: Any) -> None:
    if not isinstance(packages, dict) or tuple(packages) != SHARED_PACKAGE_KEYS:
        raise ValueError("shared package set or order drift")
    expected = {
        "torch": {"distribution": "torch", "version": "2.12.1", "import": "torch"},
        "cut_cross_entropy": {
            "distribution": "cut-cross-entropy",
            "repository": CCE_REPOSITORY,
            "revision": CCE_REVISION,
            "import": "cut_cross_entropy",
        },
        "flash_attn": {
            "distribution": "flash-attn",
            "version": "2.8.3",
            "import": "flash_attn",
        },
        "bitsandbytes": {
            "distribution": "bitsandbytes",
            "version": "0.49.1",
            "import": "bitsandbytes",
        },
        "torchao": {
            "distribution": "torchao",
            "version": "0.17.0",
            "import": "torchao",
        },
    }
    for key, expected_package in expected.items():
        package = packages[key]
        if not isinstance(package, dict) or package != expected_package:
            raise ValueError(f"shared package contract drift: {key}")


def _validate_candidate(candidate: Any) -> None:
    if not isinstance(candidate, dict):
        raise ValueError("compatibility candidate must be an object")
    _require_keys(
        candidate,
        (
            "candidate_id",
            "kind",
            "probe_directory",
            "eligible_for_final",
            "expected_resolution",
            "axolotl",
            "transformers",
        ),
        "candidate",
    )
    candidate_id = candidate["candidate_id"]
    if candidate_id not in EXPECTED_CANDIDATES:
        raise ValueError("unknown compatibility candidate")
    expected = EXPECTED_CANDIDATES[candidate_id]
    for key in ("kind", "probe_directory", "eligible_for_final", "expected_resolution"):
        if candidate[key] != expected[key] or type(candidate[key]) is not type(
            expected[key]
        ):
            raise ValueError(
                f"compatibility candidate immutable value drift: {candidate_id}.{key}"
            )
    axolotl = candidate["axolotl"]
    _require_keys(
        axolotl,
        ("distribution", "repository", "revision", "import", "declared_transformers"),
        f"candidate {candidate_id} axolotl",
    )
    if axolotl != {
        "distribution": "axolotl",
        "repository": AXOLOTL_REPOSITORY,
        "revision": expected["axolotl_revision"],
        "import": "axolotl",
        "declared_transformers": expected["declared_transformers"],
    }:
        raise ValueError(f"Axolotl candidate pin drift: {candidate_id}")
    transformers = candidate["transformers"]
    if candidate_id == "approved-negative-control":
        expected_transformers = {
            "distribution": "transformers",
            "repository": TRANSFORMERS_REPOSITORY,
            "revision": expected["transformers_revision"],
            "observed_version": expected["observed_version"],
            "import": "transformers",
        }
    else:
        expected_transformers = {
            "distribution": "transformers",
            "version": expected["transformers_version"],
            "import": "transformers",
        }
    if not isinstance(transformers, dict) or transformers != expected_transformers:
        raise ValueError(f"Transformers candidate pin drift: {candidate_id}")


def _validate_paths(matrix: dict[str, Any], *, repo_root: Path) -> None:
    paths = [
        matrix["probe_root"],
        matrix["qwen_environment"],
        matrix["final_environment"],
        *(item["probe_directory"] for item in matrix["candidates"]),
    ]
    for value in paths:
        if not isinstance(value, str) or not value:
            raise ValueError("compatibility path must be a non-empty string")
        if _is_absolute_or_parent_traversal(value):
            raise ValueError(f"unsafe compatibility path: {value}")
    probe_root = _safe_repo_path(repo_root, matrix["probe_root"])
    protected = {
        _safe_repo_path(repo_root, matrix["qwen_environment"]),
        _safe_repo_path(repo_root, matrix["final_environment"]),
    }
    candidate_paths = {
        _safe_repo_path(
            repo_root,
            f"{matrix['probe_root']}/{candidate['probe_directory']}",
        )
        for candidate in matrix["candidates"]
    }
    if len(candidate_paths) != len(matrix["candidates"]):
        raise ValueError("probe candidate directories must be exclusive")
    if probe_root in protected or candidate_paths & protected:
        raise ValueError("probe directory overlaps a protected environment")


def _validate_safe_values(value: Any, *, key: str = "") -> None:
    if isinstance(value, dict):
        for child_key, child_value in value.items():
            lowered = child_key.lower()
            if any(part in lowered for part in _SECRET_KEY_PARTS):
                raise ValueError(f"secret-like field is forbidden: {child_key}")
            _validate_safe_values(child_value, key=child_key)
    elif isinstance(value, list):
        for item in value:
            _validate_safe_values(item, key=key)
    elif isinstance(value, str):
        if _PLACEHOLDER_PATTERN.search(value):
            raise ValueError(f"placeholder is forbidden in compatibility matrix: {key}")


def _candidate_commands(
    matrix: dict[str, Any], candidate: dict[str, Any]
) -> list[list[str]]:
    candidate_root = Path(matrix["probe_root"]) / candidate["probe_directory"]
    environment = candidate_root / "environment"
    python_path = environment / "bin/python"
    requirements = _candidate_requirements(matrix, candidate)
    inspect_code = (
        "from aegislm.experiments.runtime_compatibility import runtime_evidence_cli; "
        "runtime_evidence_cli("
        f"{MATRIX_PATH.as_posix()!r}, {candidate['candidate_id']!r})"
    )
    return [
        ["uv", "venv", "--python", matrix["python_version"], environment.as_posix()],
        ["uv", "pip", "install", "--python", python_path.as_posix(), *requirements],
        ["uv", "pip", "check", "--python", python_path.as_posix()],
        [python_path.as_posix(), "-c", inspect_code],
    ]


def _candidate_requirements(
    matrix: dict[str, Any], candidate: dict[str, Any]
) -> list[str]:
    shared = matrix["shared_packages"]
    axolotl = candidate["axolotl"]
    transformers = candidate["transformers"]
    transformer_requirement = (
        f"transformers=={transformers['version']}"
        if "version" in transformers
        else _vcs_requirement(transformers)
    )
    return [
        f"torch=={shared['torch']['version']}",
        _vcs_requirement(axolotl, extra="flash-attn"),
        transformer_requirement,
        _vcs_requirement(shared["cut_cross_entropy"]),
        f"flash-attn=={shared['flash_attn']['version']}",
        f"bitsandbytes=={shared['bitsandbytes']['version']}",
        f"torchao=={shared['torchao']['version']}",
    ]


def _probe_candidate(
    matrix: dict[str, Any],
    candidate: dict[str, Any],
    *,
    matrix_sha256: str,
    repo_root: Path,
    process_env: dict[str, str],
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> dict[str, Any]:
    candidate_root = _safe_repo_path(
        repo_root,
        f"{matrix['probe_root']}/{candidate['probe_directory']}",
    )
    candidate_root.mkdir(parents=False, exist_ok=False)
    command_evidence: list[dict[str, Any]] = []
    runtime_evidence: dict[str, Any] | None = None
    runtime_validation_errors: list[str] = []
    for index, command in enumerate(_candidate_commands(matrix, candidate)):
        completed = runner(
            command,
            cwd=repo_root,
            env=process_env,
            check=False,
            capture_output=True,
            text=True,
        )
        command_evidence.append(
            {
                "argv": command,
                "exit_code": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
            }
        )
        if completed.returncode != 0:
            break
        if index == 3:
            try:
                parsed = json.loads(completed.stdout)
            except json.JSONDecodeError:
                runtime_validation_errors.append(
                    "candidate runtime evidence is not valid JSON"
                )
            else:
                if not isinstance(parsed, dict):
                    runtime_validation_errors.append(
                        "candidate runtime evidence must be an object"
                    )
                else:
                    runtime_evidence = parsed
                    runtime_validation_errors.extend(
                        _validate_child_runtime_evidence(
                            parsed,
                            matrix=matrix,
                            matrix_sha256=matrix_sha256,
                            candidate=candidate,
                            candidate_environment=candidate_root / "environment",
                        )
                    )
    all_passed = len(command_evidence) == 4 and all(
        item["exit_code"] == 0 for item in command_evidence
    )
    runtime_verified = runtime_evidence is not None and not runtime_validation_errors
    if candidate["kind"] == "negative-control":
        result = (
            "negative-control-unexpected-pass"
            if all_passed and runtime_verified
            else "expected-conflict"
        )
    else:
        result = "compatible" if all_passed and runtime_verified else "incompatible"
    evidence = {
        "schema_version": "aegislm.mistral-f5x-candidate-probe.v1",
        "candidate_id": candidate["candidate_id"],
        "kind": candidate["kind"],
        "eligible_for_final": candidate["eligible_for_final"],
        "expected_resolution": candidate["expected_resolution"],
        "result": result,
        "commands": command_evidence,
        "runtime": runtime_evidence,
        "runtime_validation_errors": runtime_validation_errors,
    }
    _write_json_exclusive(candidate_root / "evidence.json", evidence)
    return evidence


def _validate_child_runtime_evidence(
    evidence: dict[str, Any],
    *,
    matrix: dict[str, Any],
    matrix_sha256: str,
    candidate: dict[str, Any],
    candidate_environment: Path,
) -> list[str]:
    """Return every reason child evidence is not bound to this probe."""
    errors: list[str] = []
    expected_keys = {
        "schema_version",
        "matrix_sha256",
        "candidate_id",
        "python",
        "python_prefix",
        "cuda",
        "gpu_names",
        "axolotl_cli",
        "packages",
        "mistral4_symbols",
    }
    if set(evidence) != expected_keys:
        return ["candidate runtime evidence schema drift"]
    if evidence["schema_version"] != "aegislm.mistral-f5x-candidate-runtime.v1":
        errors.append("candidate runtime evidence schema version drift")
    if evidence["matrix_sha256"] != matrix_sha256:
        errors.append("candidate runtime evidence matrix hash mismatch")
    if evidence["candidate_id"] != candidate["candidate_id"]:
        errors.append("candidate runtime evidence candidate id mismatch")
    python = evidence["python"]
    if not isinstance(python, str) or not python.startswith(
        f"{matrix['python_version']}."
    ):
        errors.append("candidate runtime evidence Python mismatch")
    expected_prefix = candidate_environment.resolve()
    python_prefix = evidence["python_prefix"]
    if (
        not isinstance(python_prefix, str)
        or Path(python_prefix).resolve() != expected_prefix
    ):
        errors.append("candidate runtime evidence Python prefix mismatch")
    if evidence["cuda"] != matrix["cuda_version"]:
        errors.append("candidate runtime evidence CUDA mismatch")
    gpu_names = evidence["gpu_names"]
    if (
        not isinstance(gpu_names, list)
        or len(gpu_names) != matrix["gpu_count"]
        or any(
            not isinstance(name, str) or matrix["gpu_name_contains"] not in name
            for name in gpu_names
        )
    ):
        errors.append("candidate runtime evidence GPU identity mismatch")
    executable = evidence["axolotl_cli"]
    if not isinstance(executable, str):
        errors.append("candidate runtime evidence Axolotl CLI mismatch")
    else:
        try:
            Path(executable).resolve().relative_to(expected_prefix)
        except ValueError:
            errors.append("candidate runtime evidence Axolotl CLI prefix mismatch")
    errors.extend(
        _validate_child_packages(
            evidence["packages"], matrix=matrix, candidate=candidate
        )
    )
    if evidence["mistral4_symbols"] != matrix["mistral4_symbols"]:
        errors.append("candidate runtime evidence Mistral 4 symbols mismatch")
    return errors


def _validate_child_packages(
    observed: Any,
    *,
    matrix: dict[str, Any],
    candidate: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    expected_packages = _expected_runtime_packages(matrix, candidate)
    if not isinstance(observed, dict) or set(observed) != set(expected_packages):
        return ["candidate runtime evidence package schema drift"]
    for key, expected in expected_packages.items():
        package = observed[key]
        if not isinstance(package, dict):
            errors.append(f"candidate runtime evidence package invalid: {key}")
            continue
        expected_keys = {"distribution", "version", "import"}
        if "revision" in expected:
            expected_keys.update({"repository", "revision"})
        if set(package) != expected_keys:
            errors.append(f"candidate runtime evidence package schema drift: {key}")
            continue
        if package["distribution"] != expected["distribution"]:
            errors.append(f"candidate runtime evidence distribution mismatch: {key}")
        if package["import"] != expected["import"]:
            errors.append(f"candidate runtime evidence import mismatch: {key}")
        version = package["version"]
        if not isinstance(version, str) or not version:
            errors.append(f"candidate runtime evidence version missing: {key}")
        expected_version = expected.get("version")
        if (
            expected_version is not None
            and isinstance(version, str)
            and version.split("+", 1)[0] != expected_version
        ):
            errors.append(f"candidate runtime evidence version mismatch: {key}")
        if "revision" in expected and (
            package["revision"] != expected["revision"]
            or not _same_repository(package["repository"], expected["repository"])
        ):
            errors.append(f"candidate runtime evidence source mismatch: {key}")
    return errors


def _expected_runtime_packages(
    matrix: dict[str, Any], candidate: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    transformers = dict(candidate["transformers"])
    transformers.pop("observed_version", None)
    return {
        "torch": matrix["shared_packages"]["torch"],
        "axolotl": candidate["axolotl"],
        "transformers": transformers,
        "cut_cross_entropy": matrix["shared_packages"]["cut_cross_entropy"],
        "flash_attn": matrix["shared_packages"]["flash_attn"],
        "bitsandbytes": matrix["shared_packages"]["bitsandbytes"],
        "torchao": matrix["shared_packages"]["torchao"],
    }


def _verify_direct_url(
    distribution: importlib.metadata.Distribution,
    expected_repository: str,
    expected_revision: str,
) -> None:
    raw = distribution.read_text("direct_url.json")
    if raw is None:
        raise RuntimeError(f"{distribution.metadata['Name']} lacks direct_url evidence")
    try:
        direct_url = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("installed direct_url evidence is invalid") from exc
    vcs = direct_url.get("vcs_info") if isinstance(direct_url, dict) else None
    if (
        not isinstance(vcs, dict)
        or vcs.get("vcs") != "git"
        or vcs.get("commit_id") != expected_revision
        or not _same_repository(direct_url.get("url"), expected_repository)
    ):
        raise RuntimeError(
            f"{distribution.metadata['Name']} source revision evidence mismatch"
        )


def _vcs_requirement(package: dict[str, Any], *, extra: str | None = None) -> str:
    name = package["distribution"]
    rendered_name = f"{name}[{extra}]" if extra else name
    return f"{rendered_name} @ git+{package['repository']}@{package['revision']}"


def _require_keys(
    value: dict[str, Any], expected: tuple[str, ...], context: str
) -> None:
    if tuple(value) != expected:
        raise ValueError(f"compatibility matrix {context} schema drift")


def _is_absolute_or_parent_traversal(value: str) -> bool:
    normalized = value.replace("\\", "/")
    return (
        normalized.startswith("/")
        or bool(_WINDOWS_ABSOLUTE.match(value))
        or ".." in normalized.split("/")
    )


def _safe_repo_path(repo_root: Path, relative: str) -> Path:
    if _is_absolute_or_parent_traversal(relative):
        raise ValueError(f"unsafe repository-relative path: {relative}")
    root = repo_root.resolve()
    resolved = (root / relative).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"path escapes repository root: {relative}") from exc
    return resolved


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json_exclusive(path: Path, value: dict[str, Any]) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def _same_repository(left: Any, right: Any) -> bool:
    def normalize(value: Any) -> str:
        if not isinstance(value, str):
            return ""
        normalized = value.lower().rstrip("/")
        if normalized.endswith(".git"):
            normalized = normalized[:-4]
        for prefix in ("git+https://github.com/", "https://github.com/"):
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix) :]
        return normalized

    return normalize(left) == normalize(right)
