"""Assemble verified byte-range downloads without extracting archive members."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.datasets.archive_inventory import (  # noqa: E402
    ArchiveInventoryError,
    ArchiveRangePart,
    assemble_archive_ranges,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output-archive", type=Path, required=True)
    parser.add_argument("--output-report", type=Path, required=True)
    parser.add_argument(
        "--part",
        action="append",
        required=True,
        metavar="START:END:PATH",
        help="Inclusive range and its file; repeat in any order.",
    )
    args = parser.parse_args()
    config = json.loads(args.config.read_text(encoding="utf-8"))
    parts = [_parse_part(value) for value in args.part]
    result = assemble_archive_ranges(
        parts,
        args.output_archive,
        expected_bytes=int(config["expected_bytes"]),
        expected_md5=str(config["expected_md5"]),
    )
    result["profile"] = str(config["profile"])
    result["source_id"] = str(config["source_id"])
    args.output_report.parent.mkdir(parents=True, exist_ok=True)
    args.output_report.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Phase F archive range assembly: "
        f"decision={result['decision']}, "
        f"bytes={result['archive']['observed_bytes']}, "
        f"sha256={result['archive']['observed_sha256']}"
    )


def _parse_part(value: str) -> ArchiveRangePart:
    fields = value.split(":", maxsplit=2)
    if len(fields) != 3:
        raise ArchiveInventoryError(
            f"invalid --part value {value!r}; expected START:END:PATH"
        )
    try:
        start = int(fields[0])
        end = int(fields[1])
    except ValueError as exc:
        raise ArchiveInventoryError(
            f"invalid --part byte range {fields[0]!r}:{fields[1]!r}"
        ) from exc
    return ArchiveRangePart(start=start, end=end, path=Path(fields[2]))


if __name__ == "__main__":
    main()
