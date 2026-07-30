"""Compile a bounded Phase F B0 candidate canary without executing binaries."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import zipfile
from pathlib import Path
from typing import Any

_TARGET_SYMBOL = re.compile(r"(?:\b|_)(?:bad|good)(?:\(|\b)", re.IGNORECASE)


def compile_canary(
    *,
    archive: Path,
    candidate_manifest: Path,
    output_dir: Path,
    toolchain_root: Path,
    limit: int,
) -> dict[str, Any]:
    """Compile candidate source files to ELF relocatable objects only."""
    if limit <= 0:
        raise ValueError("limit must be positive")
    if output_dir.exists() and any(output_dir.iterdir()):
        raise ValueError(f"output directory is not empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(candidate_manifest.read_text(encoding="utf-8"))
    candidates = [row for row in manifest["candidates"] if row["queue"] == "primary"][
        :limit
    ]
    if len(candidates) < limit:
        raise ValueError("candidate manifest does not contain enough primary pairs")

    extracted = output_dir / "extracted"
    source_root = extracted / "C"
    _extract_members(
        archive,
        extracted,
        [
            *(str(row["archive_path"]) for row in candidates),
            "C/testcasesupport/",
        ],
    )
    tool_bin = toolchain_root / "bin"
    compiler_paths = {
        "gcc": Path("gcc"),
        "g++": Path("g++"),
        "clang": tool_bin / "clang",
        "clang++": tool_bin / "clang++",
    }
    results: list[dict[str, Any]] = []
    for candidate in candidates:
        source = extracted / str(candidate["archive_path"])
        is_cpp = source.suffix == ".cpp"
        for family, optimization in (
            ("gcc", "O0"),
            ("gcc", "O2"),
            ("clang", "O0"),
            ("clang", "O2"),
        ):
            compiler_name = (
                "g++" if is_cpp and family == "gcc" else "clang++" if is_cpp else family
            )
            compiler = compiler_paths[compiler_name]
            variant = f"{family}-{optimization}"
            pair_dir = output_dir / "objects" / str(candidate["pair_id"])
            pair_dir.mkdir(parents=True, exist_ok=True)
            object_path = pair_dir / f"{variant}.o"
            command = [
                str(compiler),
                f"-{optimization}",
                "-g",
                "-fno-omit-frame-pointer",
                "-DS_IREAD=S_IRUSR",
                "-DS_IWRITE=S_IWUSR",
                "-D_DEFAULT_SOURCE",
                "-include",
                "alloca.h",
                "-I",
                str(source_root / "testcasesupport"),
                "-c",
                str(source),
                "-o",
                str(object_path),
            ]
            if is_cpp:
                command.insert(1, "-std=c++17")
            else:
                command.insert(1, "-std=c11")
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=120,
            )
            log_dir = output_dir / "logs" / str(candidate["pair_id"])
            log_dir.mkdir(parents=True, exist_ok=True)
            (log_dir / f"{variant}.log").write_text(
                completed.stdout + completed.stderr,
                encoding="utf-8",
            )
            success = completed.returncode == 0 and object_path.is_file()
            nm_output = ""
            symbol_linked = False
            if success:
                nm = subprocess.run(
                    ["nm", "-C", str(object_path)],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                nm_output = nm.stdout
                symbol_linked = bool(_TARGET_SYMBOL.search(nm_output))
                (log_dir / f"{variant}.nm.txt").write_text(
                    nm_output,
                    encoding="utf-8",
                )
            results.append(
                {
                    "pair_id": candidate["pair_id"],
                    "target_cwe": candidate["target_cwe"],
                    "archive_path": candidate["archive_path"],
                    "compiler": family,
                    "optimization": optimization,
                    "return_code": completed.returncode,
                    "compile_success": success,
                    "target_symbol_linked": symbol_linked,
                    "object_sha256": (_sha256_file(object_path) if success else None),
                    "object_ref": (
                        str(object_path.relative_to(output_dir)) if success else None
                    ),
                    "executed": False,
                }
            )

    compile_passed = sum(bool(row["compile_success"]) for row in results)
    linked = sum(bool(row["target_symbol_linked"]) for row in results)
    total = len(results)
    summary = {
        "schema_version": "aegislm.phase-f-binary-b0-compile-canary.v1",
        "scope": f"{limit}-pair compile-only canary; not the B0 gate",
        "candidate_manifest_sha256": _sha256_file(candidate_manifest),
        "archive_sha256": _sha256_file(archive),
        "pair_count": limit,
        "variant_count": total,
        "compile_success": {
            "passed": compile_passed,
            "total": total,
            "rate": compile_passed / total,
        },
        "target_symbol_link": {
            "passed": linked,
            "total": total,
            "rate": linked / total,
        },
        "object_execution_count": 0,
        "ready_for_decompile_canary": (
            compile_passed / total >= 0.90 and linked / total >= 0.95
        ),
        "results": results,
    }
    (output_dir / "compile-summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


def _extract_members(
    archive: Path,
    destination: Path,
    requested: list[str],
) -> None:
    with zipfile.ZipFile(archive) as bundle:
        names = [
            name
            for name in bundle.namelist()
            if any(
                name == value or (value.endswith("/") and name.startswith(value))
                for value in requested
            )
        ]
        for name in names:
            target = (destination / name).resolve()
            if not target.is_relative_to(destination.resolve()):
                raise ValueError(f"unsafe archive member: {name}")
            if name.endswith("/"):
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(bundle.read(name))


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--candidate-manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--toolchain-root", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=10)
    args = parser.parse_args()
    summary = compile_canary(
        archive=args.archive,
        candidate_manifest=args.candidate_manifest,
        output_dir=args.output_dir,
        toolchain_root=args.toolchain_root,
        limit=args.limit,
    )
    print(
        "Phase F binary B0 compile canary: "
        f"compile={summary['compile_success']['passed']}/"
        f"{summary['compile_success']['total']}, "
        f"symbol_link={summary['target_symbol_link']['passed']}/"
        f"{summary['target_symbol_link']['total']}, "
        f"decompile_ready={summary['ready_for_decompile_canary']}"
    )


if __name__ == "__main__":
    main()
