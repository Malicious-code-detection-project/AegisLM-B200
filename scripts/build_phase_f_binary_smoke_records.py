"""Build safe normalized records from a completed F6-B binary smoke artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Iterable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.datasets.binary import (  # noqa: E402
    format_binary_prompt,
    validate_binary_record,
)

_FUNCTION_HEADER = re.compile(r"^[0-9a-f]+ <(.+)>:$")
_INSTRUCTION = re.compile(r"^\s*[0-9a-f]+:\s+(?:(?:[0-9a-f]{2})\s+)+\s*(.+?)\s*$")
_SOURCE_NAMESPACE = re.compile(r"\bCWE[0-9]+_[A-Za-z0-9_]+::")
_SOURCE_SYMBOL = re.compile(
    r"\bCWE[0-9]+_[A-Za-z0-9_]*(?:::[A-Za-z0-9_]+)?",
)
_SOURCE_BEARING_STRING = re.compile(
    r'"[^"\n]*(?:C/testcases|CWE[0-9]+_)[^"\n]*"',
)
_ANGLE_SYMBOL = re.compile(r"<[^>]+>")
_SECTION = re.compile(r"\[\s*\d+\]\s+(\S+)")


def sanitize_pseudo_c(text: str) -> str:
    """Remove source-derived namespace and Juliet label-bearing function names."""
    sanitized = _SOURCE_BEARING_STRING.sub('"<source-reference-redacted>"', text)
    sanitized = _SOURCE_NAMESPACE.sub("", sanitized)
    sanitized = _SOURCE_SYMBOL.sub("target_function", sanitized)
    sanitized = re.sub(r"\bvoid\s+bad\s*\(", "void target_function(", sanitized)
    sanitized = re.sub(r"\bvoid\s+good\s*\(", "void target_function(", sanitized)
    sanitized = re.sub(r"\bvoid\s+goodG2B\s*\(", "void target_helper(", sanitized)
    sanitized = re.sub(
        r"\bgood(?:G2B|B2G)[A-Za-z0-9_]*\s*\(", "target_helper(", sanitized
    )
    return sanitized.strip()


def extract_assembly_blocks(
    text: str,
    *,
    function_suffixes: Iterable[str],
    maximum_instructions: int = 80,
) -> list[str]:
    """Extract bounded instructions while replacing address-bearing symbols."""
    suffixes = tuple(function_suffixes)
    selected = False
    instructions: list[str] = []
    for line in text.splitlines():
        header = _FUNCTION_HEADER.match(line.strip())
        if header:
            name = header.group(1)
            selected = any(name.endswith(suffix) for suffix in suffixes)
            continue
        if not selected:
            continue
        instruction = _INSTRUCTION.match(line)
        if instruction:
            value = _ANGLE_SYMBOL.sub("<symbol>", instruction.group(1))
            value = _SOURCE_NAMESPACE.sub("", value)
            instructions.append(value)
            if len(instructions) >= maximum_instructions:
                break
    return instructions


def build_records(
    *,
    artifact_root: Path,
    pair_id: str,
    target_cwe: str,
) -> list[dict[str, object]]:
    """Materialize one positive/negative record for every compiler variant."""
    variants = ("gcc-O0", "gcc-O2", "clang-O0", "clang-O2")
    records: list[dict[str, object]] = []
    for variant in variants:
        compiler, optimization = variant.split("-", maxsplit=1)
        binary_path = artifact_root / "binaries" / f"{variant}.elf"
        assembly_path = artifact_root / "static" / f"{variant}.assembly-all.txt"
        readelf_path = artifact_root / "static" / f"{variant}.readelf.txt"
        nm_path = artifact_root / "static" / f"{variant}.nm.txt"
        binary_sha256 = _sha256_file(binary_path)
        assembly_text = assembly_path.read_text(encoding="utf-8", errors="replace")
        sections = _sections(readelf_path.read_text(encoding="utf-8", errors="replace"))
        imports = _imports(nm_path.read_text(encoding="utf-8", errors="replace"))
        for label in ("present", "not_observed"):
            suffixes: tuple[str, ...]
            if label == "present":
                pseudo_paths = [artifact_root / "pseudo-c" / variant / "bad.c"]
                suffixes = ("::bad()",)
            else:
                helper = artifact_root / "pseudo-c" / variant / "goodG2B.c"
                pseudo_paths = [
                    artifact_root / "pseudo-c" / variant / "good.c",
                    *([helper] if helper.exists() else []),
                ]
                suffixes = ("::good()", "::goodG2B()")
            pseudo_c = "\n\n".join(
                sanitize_pseudo_c(path.read_text(encoding="utf-8", errors="replace"))
                for path in pseudo_paths
            )
            assembly = extract_assembly_blocks(
                assembly_text,
                function_suffixes=suffixes,
            )
            opaque_id = hashlib.sha256(f"{pair_id}:{label}".encode()).hexdigest()[:16]
            function_hash = hashlib.sha256(
                (pseudo_c + "\n" + "\n".join(assembly)).encode()
            ).hexdigest()
            record: dict[str, object] = {
                "schema_version": "aegislm.binary-analysis-record.v1",
                "id": f"binary-smoke-{opaque_id}-{variant.lower()}",
                "artifact": {
                    "sha256": binary_sha256,
                    "format": "ELF",
                    "architecture": "x86_64",
                    "compiler": compiler,
                    "optimization": optimization,
                    "stripped": False,
                    "external_artifact_ref": (
                        f"artifact://phase-f-binary-b0-smoke/{binary_sha256}"
                    ),
                },
                "analysis": {
                    "analyzer": "binutils-normalizer",
                    "analyzer_version": "2.42",
                    "decompiler": "Ghidra",
                    "decompiler_version": "12.1.2",
                    "functions": [
                        {
                            "function_id": f"function-{opaque_id}",
                            "function_hash": function_hash,
                            "pseudo_c": pseudo_c,
                            "assembly_evidence": assembly,
                            "static_features": {
                                "imports": imports,
                                "sections": sections,
                                "strings": [],
                                "symbols": [],
                            },
                        }
                    ],
                    "warnings": [
                        "The ELF is not executed.",
                        "Debug symbols are used only for source-binary linkage and are removed from model-visible evidence.",
                    ],
                },
                "task": {"target_cwe": target_cwe},
                "metadata": {
                    "split": "test",
                    "source_dataset": "NIST SARD Juliet C/C++ 1.3",
                    "label": label,
                    "compiler_group_id": f"{pair_id}:{label}",
                    "contains_executable_payload": False,
                },
            }
            validate_binary_record(record)
            prompt = json.dumps(format_binary_prompt(record), ensure_ascii=False)
            _assert_prompt_boundary(prompt)
            records.append(record)
    return records


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--pair-id", required=True)
    parser.add_argument("--target-cwe", required=True)
    args = parser.parse_args()
    records = build_records(
        artifact_root=args.artifact_root,
        pair_id=args.pair_id,
        target_cwe=args.target_cwe,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        "".join(
            json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"
            for record in records
        ),
        encoding="utf-8",
    )
    print(f"Phase F binary smoke records: records={len(records)}, output={args.output}")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sections(text: str) -> list[str]:
    values = [
        match.group(1) for match in map(_SECTION.search, text.splitlines()) if match
    ]
    return sorted(dict.fromkeys(values))


def _imports(text: str) -> list[str]:
    values = []
    for line in text.splitlines():
        if " U " not in line:
            continue
        value = line.split(" U ", maxsplit=1)[1].split("@", maxsplit=1)[0].strip()
        if value:
            values.append(value)
    return sorted(dict.fromkeys(values))


def _assert_prompt_boundary(prompt: str) -> None:
    forbidden = (
        "NIST SARD",
        "Juliet",
        "source_dataset",
        '"label"',
        "artifact://",
        "C/testcases",
        "::bad",
        "::good",
    )
    leaked = [value for value in forbidden if value in prompt]
    if re.search(r"\bCWE[0-9]+_", prompt):
        leaked.append("source CWE symbol")
    if leaked:
        raise ValueError("model-visible binary prompt leakage: " + ", ".join(leaked))


if __name__ == "__main__":
    main()
