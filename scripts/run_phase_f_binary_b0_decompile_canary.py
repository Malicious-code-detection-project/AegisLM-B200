"""Decompile a completed B0 compile canary without executing its objects."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any


def parse_function_manifest(path: Path) -> list[dict[str, str]]:
    """Parse the deterministic TSV emitted by the Ghidra post-script."""
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0] != "label\tfull_name\toutput_file\tcompleted":
        raise ValueError(f"invalid Ghidra function manifest: {path}")
    rows: list[dict[str, str]] = []
    for line in lines[1:]:
        values = line.split("\t")
        if len(values) != 4:
            raise ValueError(f"invalid Ghidra function row: {line}")
        rows.append(
            dict(
                zip(
                    ("label", "full_name", "output_file", "completed"),
                    values,
                    strict=True,
                )
            )
        )
    return rows


def decompile_canary(
    *,
    compile_root: Path,
    output_dir: Path,
    toolchain_root: Path,
    script_dir: Path,
    start_index: int = 0,
    end_index: int | None = None,
) -> dict[str, Any]:
    """Run Ghidra headless once per compiler object and audit function linkage."""
    if output_dir.exists() and any(output_dir.iterdir()):
        raise ValueError(f"output directory is not empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    compile_summary_path = compile_root / "compile-summary.json"
    compile_summary = json.loads(compile_summary_path.read_text(encoding="utf-8"))
    if not bool(compile_summary["ready_for_decompile_canary"]):
        raise ValueError("compile canary did not authorize decompilation")

    analyze = toolchain_root / "bin" / "analyzeHeadless"
    java_home = toolchain_root / "jdk-21.0.12+8"
    environment = dict(os.environ)
    environment["JAVA_HOME"] = str(java_home)
    environment["PATH"] = (
        str(toolchain_root / "bin") + os.pathsep + environment.get("PATH", "")
    )
    selected_items = compile_summary["results"][start_index:end_index]
    results: list[dict[str, Any]] = []
    for item in selected_items:
        if not bool(item["compile_success"]):
            continue
        pair_id = str(item["pair_id"])
        variant = f"{item['compiler']}-{item['optimization']}"
        object_path = compile_root / str(item["object_ref"])
        pseudo_dir = output_dir / "pseudo-c" / pair_id / variant
        pseudo_dir.mkdir(parents=True, exist_ok=True)
        project_dir = output_dir / "projects" / pair_id / variant
        project_dir.mkdir(parents=True, exist_ok=True)
        log_dir = output_dir / "logs" / pair_id
        log_dir.mkdir(parents=True, exist_ok=True)
        project_name = f"b0-{pair_id}-{variant}".replace("_", "-")
        command = [
            str(analyze),
            str(project_dir),
            project_name,
            "-import",
            str(object_path),
            "-overwrite",
            "-scriptPath",
            str(script_dir),
            "-postScript",
            "ExportJulietFunctions.java",
            str(pseudo_dir),
            "-deleteProject",
        ]
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=600,
            env=environment,
        )
        (log_dir / f"{variant}.log").write_text(
            completed.stdout + completed.stderr,
            encoding="utf-8",
        )
        manifest_path = pseudo_dir / "functions.tsv"
        functions: list[dict[str, str]] = []
        manifest_error = None
        if manifest_path.is_file():
            try:
                functions = parse_function_manifest(manifest_path)
            except ValueError as exc:
                manifest_error = str(exc)
        completed_functions = [
            row for row in functions if row["completed"].lower() == "true"
        ]
        labels = Counter(row["label"] for row in completed_functions)
        linked = labels["present"] >= 1 and labels["not_observed"] >= 1
        success = completed.returncode == 0 and manifest_error is None and linked
        results.append(
            {
                "pair_id": pair_id,
                "target_cwe": item["target_cwe"],
                "compiler": item["compiler"],
                "optimization": item["optimization"],
                "return_code": completed.returncode,
                "decompile_success": success,
                "present_function_count": labels["present"],
                "not_observed_function_count": labels["not_observed"],
                "source_binary_function_linked": linked,
                "function_manifest_ref": (
                    str(manifest_path.relative_to(output_dir))
                    if manifest_path.is_file()
                    else None
                ),
                "manifest_error": manifest_error,
                "object_executed": False,
                "target_preservation_audit": "pending_operator_review",
            }
        )

    passed = sum(bool(row["decompile_success"]) for row in results)
    linked_count = sum(bool(row["source_binary_function_linked"]) for row in results)
    total = len(results)
    summary = {
        "schema_version": "aegislm.phase-f-binary-b0-decompile-canary.v1",
        "scope": (f"Ghidra variants [{start_index}:{end_index}]; not the B0 gate"),
        "start_index": start_index,
        "end_index": end_index,
        "compile_summary_sha256": _sha256_file(compile_summary_path),
        "variant_count": total,
        "decompile_success": {
            "passed": passed,
            "total": total,
            "rate": passed / total if total else 0.0,
        },
        "source_binary_function_link": {
            "passed": linked_count,
            "total": total,
            "rate": linked_count / total if total else 0.0,
        },
        "object_execution_count": 0,
        "target_preservation_status": "pending_operator_review",
        "ready_for_target_preservation_audit": (
            total > 0 and passed / total >= 0.90 and linked_count / total >= 0.95
        ),
        "results": results,
    }
    (output_dir / "decompile-summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compile-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--toolchain-root", type=Path, required=True)
    parser.add_argument(
        "--script-dir",
        type=Path,
        default=Path("scripts/ghidra"),
    )
    parser.add_argument("--start-index", type=int, default=0)
    parser.add_argument("--end-index", type=int)
    args = parser.parse_args()
    summary = decompile_canary(
        compile_root=args.compile_root,
        output_dir=args.output_dir,
        toolchain_root=args.toolchain_root,
        script_dir=args.script_dir.resolve(),
        start_index=args.start_index,
        end_index=args.end_index,
    )
    print(
        "Phase F binary B0 decompile canary: "
        f"decompile={summary['decompile_success']['passed']}/"
        f"{summary['decompile_success']['total']}, "
        f"link={summary['source_binary_function_link']['passed']}/"
        f"{summary['source_binary_function_link']['total']}, "
        f"audit_ready={summary['ready_for_target_preservation_audit']}"
    )


if __name__ == "__main__":
    main()
