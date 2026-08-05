"""Safe developer-patch collection for ARVO buffer feasibility review."""

from __future__ import annotations

import hashlib
import re
from copy import deepcopy
from collections import Counter, defaultdict
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from aegislm.datasets.arvo import (
    ARVO_DEFAULT_FAMILY_QUOTA,
    ARVO_DEFAULT_SEED,
    ARVO_FAMILY_CWE,
    list_arvo_metadata_candidates,
    rank_arvo_project_diverse,
)

ARVO_PATCH_REVIEW_SCHEMA_VERSION = "aegislm.phase-f-arvo-patch-review.v1"
ARVO_PATCH_MAX_BYTES = 5 * 1024 * 1024
ARVO_PATCH_SUPPORTED_HOSTS = ("github.com",)

PatchFetcher = Callable[[str, int], bytes]

_GITHUB_COMMIT_PATH = re.compile(
    r"^/(?P<owner>[^/]+)/(?P<repo>[^/]+)/commit/(?P<commit>[0-9a-fA-F]{7,64})/?$"
)
_SOURCE_SUFFIXES = (
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
)
_BUFFER_TERMS = re.compile(
    r"\b(?:memcpy|memmove|memset|strcpy|strncpy|strcat|strncat|"
    r"sprintf|snprintf|vsprintf|vsnprintf|read|write|recv|send|"
    r"malloc|calloc|realloc|free|new|delete|sizeof|strlen|strnlen)\b"
    r"|\[[^\]\n]+\]",
    re.IGNORECASE,
)
_BOUND_TERMS = re.compile(
    r"(?:<=|>=|<|>|\b(?:size|length|len|limit|bound|capacity|offset|"
    r"index|count|remaining|overflow)\b)",
    re.IGNORECASE,
)


class ArvoPatchError(ValueError):
    """Raised when a patch URL or downloaded patch violates the safe contract."""


def collect_arvo_patch_review(
    database: Path,
    patch_dir: Path,
    *,
    fetcher: PatchFetcher | None = None,
    seed: int = ARVO_DEFAULT_SEED,
    family_quota: int = ARVO_DEFAULT_FAMILY_QUOTA,
    max_bytes: int = ARVO_PATCH_MAX_BYTES,
) -> dict[str, Any]:
    """Collect bounded public source patches without reading or executing payloads."""
    if family_quota <= 0:
        raise ValueError("family_quota must be positive")
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    active_fetcher = fetcher or fetch_github_patch
    candidates = list_arvo_metadata_candidates(database)
    by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
    unsupported_hosts: Counter[str] = Counter()
    for candidate in candidates:
        host = _hostname(str(candidate["patch_url"]))
        if host not in ARVO_PATCH_SUPPORTED_HOSTS:
            unsupported_hosts[host] += 1
            continue
        by_family[str(candidate["crash_family"])].append(candidate)

    patch_dir.mkdir(parents=True, exist_ok=True)
    selected: list[dict[str, Any]] = []
    attempts: list[dict[str, Any]] = []
    used_patch_identities: set[str] = set()
    selected_counts: dict[str, int] = {}
    for family in sorted(ARVO_FAMILY_CWE):
        ranked = rank_arvo_project_diverse(
            by_family.get(family, []),
            seed=seed,
            family=family,
        )
        family_selected = 0
        for candidate in ranked:
            identity = _patch_identity(candidate)
            if identity in used_patch_identities:
                attempts.append(
                    _attempt_record(candidate, "duplicate_patch_identity", identity)
                )
                continue
            used_patch_identities.add(identity)
            try:
                download_url = github_patch_download_url(candidate)
                patch_path = patch_dir / (
                    f"{int(candidate['local_id'])}-"
                    f"{str(candidate['fix_commit'])[:12]}.patch"
                )
                patch_source = "cache" if patch_path.exists() else "network"
                patch_bytes = (
                    patch_path.read_bytes()
                    if patch_path.exists()
                    else active_fetcher(download_url, max_bytes)
                )
                _validate_patch_bytes(patch_bytes, max_bytes=max_bytes)
                patch_sha256 = hashlib.sha256(patch_bytes).hexdigest()
                patch_summary = summarize_patch(patch_bytes)
                _validate_reviewable_source_patch(patch_bytes, patch_summary)
                _write_immutable_patch(patch_path, patch_bytes)
            except (ArvoPatchError, OSError) as error:
                attempts.append(
                    _attempt_record(candidate, "fetch_or_validation_failed", str(error))
                )
                continue

            review = dict(candidate)
            review.update(
                {
                    "download_url": download_url,
                    "patch_path": str(patch_path),
                    "patch_sha256": patch_sha256,
                    "patch_size_bytes": len(patch_bytes),
                    "patch_source": patch_source,
                    "patch_summary": patch_summary,
                    "operator_family_match": None,
                    "operator_patch_evidence_error": None,
                    "operator_notes": "",
                }
            )
            selected.append(review)
            attempts.append(_attempt_record(candidate, "selected", patch_sha256))
            family_selected += 1
            if family_selected == family_quota:
                break
        selected_counts[family] = family_selected

    expected_count = family_quota * len(ARVO_FAMILY_CWE)
    return {
        "schema_version": ARVO_PATCH_REVIEW_SCHEMA_VERSION,
        "source": {
            "database_path": str(database),
            "database_sha256": _sha256(database),
        },
        "selection": {
            "seed": seed,
            "family_quota": family_quota,
            "expected_count": expected_count,
            "selected_count": len(selected),
            "selected_family_counts": selected_counts,
            "unique_patch_identity_count": len(
                {_patch_identity(row) for row in selected}
            ),
        },
        "inventory": {
            "metadata_candidate_count": len(candidates),
            "supported_host_candidate_count": sum(map(len, by_family.values())),
            "unsupported_host_counts": dict(sorted(unsupported_hosts.items())),
        },
        "safety": {
            "downloaded_content": "public_developer_patch_with_reviewable_c_cpp_hunk",
            "supported_hosts": list(ARVO_PATCH_SUPPORTED_HOSTS),
            "max_patch_bytes": max_bytes,
            "git_binary_patch_count": 0,
            "raw_payload_read_count": 0,
            "poc_read_count": 0,
            "reproducer_execution_count": 0,
            "object_execution_count": 0,
            "docker_image_pull_count": 0,
        },
        "gate": {
            "supply_pass": len(selected) == expected_count
            and all(count == family_quota for count in selected_counts.values()),
            "manual_review_required": True,
            "maximum_error_rate": 0.05,
            "approved_for_training": False,
        },
        "attempts": attempts,
        "review_records": selected,
    }


def github_patch_download_url(candidate: Mapping[str, Any]) -> str:
    """Convert a GitHub commit page into its plain-text patch endpoint."""
    patch_url = str(candidate.get("patch_url") or "")
    parsed = urlparse(patch_url)
    if parsed.scheme != "https" or (parsed.hostname or "").lower() != "github.com":
        raise ArvoPatchError("only HTTPS github.com commit URLs are supported")
    match = _GITHUB_COMMIT_PATH.fullmatch(parsed.path)
    if match is None or parsed.query or parsed.fragment:
        raise ArvoPatchError("patch_url is not a canonical GitHub commit URL")
    metadata_commit = str(candidate.get("fix_commit") or "").lower()
    url_commit = match.group("commit").lower()
    if not metadata_commit.startswith(url_commit) and not url_commit.startswith(
        metadata_commit
    ):
        raise ArvoPatchError("patch_url commit does not match fix_commit")
    return patch_url.rstrip("/") + ".patch"


def fetch_github_patch(url: str, max_bytes: int) -> bytes:
    """Fetch one bounded GitHub source patch without invoking repository code."""
    parsed = urlparse(url)
    if (
        parsed.scheme != "https"
        or (parsed.hostname or "").lower() != "github.com"
        or not parsed.path.endswith(".patch")
    ):
        raise ArvoPatchError("download URL is outside the GitHub patch allowlist")
    request = Request(
        url,
        headers={
            "Accept": "text/plain",
            "User-Agent": "AegisLM-Phase-F-ARVO-Patch-Review/1.0",
        },
    )
    with urlopen(request, timeout=30) as response:  # noqa: S310
        final = urlparse(response.geturl())
        if final.scheme != "https" or (final.hostname or "").lower() != "github.com":
            raise ArvoPatchError("patch request redirected outside github.com")
        content_length = response.headers.get("Content-Length")
        if content_length and int(content_length) > max_bytes:
            raise ArvoPatchError("patch exceeds configured maximum size")
        patch_bytes = response.read(max_bytes + 1)
    return patch_bytes


def summarize_patch(patch_bytes: bytes) -> dict[str, Any]:
    """Create bounded, review-oriented source diff metadata."""
    text = patch_bytes.decode("utf-8", errors="replace")
    lines = text.splitlines()
    changed_files = [
        line.removeprefix("+++ b/")
        for line in lines
        if line.startswith("+++ b/") and line != "+++ /dev/null"
    ]
    added = [
        line[1:]
        for line in lines
        if line.startswith("+") and not line.startswith("+++")
    ]
    deleted = [
        line[1:]
        for line in lines
        if line.startswith("-") and not line.startswith("---")
    ]
    changed = added + deleted
    relevant = [
        line.strip()
        for line in changed
        if _BUFFER_TERMS.search(line) or _BOUND_TERMS.search(line)
    ]
    excerpt = _review_excerpt(text)
    return {
        "changed_file_count": len(set(changed_files)),
        "source_file_count": len(
            {path for path in changed_files if path.lower().endswith(_SOURCE_SUFFIXES)}
        ),
        "hunk_count": sum(line.startswith("@@") for line in lines),
        "added_line_count": len(added),
        "deleted_line_count": len(deleted),
        "buffer_term_line_count": sum(
            bool(_BUFFER_TERMS.search(line)) for line in changed
        ),
        "bound_term_line_count": sum(
            bool(_BOUND_TERMS.search(line)) for line in changed
        ),
        "review_excerpt": excerpt[:8000],
        "automated_disposition": (
            "manual_relation_review_ready"
            if relevant
            and any(path.lower().endswith(_SOURCE_SUFFIXES) for path in changed_files)
            else "weak_patch_signal"
        ),
    }


def render_arvo_patch_manual_review(
    records: Sequence[Mapping[str, Any]],
) -> str:
    """Render the complete review queue with explicit operator questions."""
    ordered = sorted(
        records,
        key=lambda row: (
            str(row["patch_summary"]["automated_disposition"]) != "weak_patch_signal",
            str(row["crash_family"]),
            int(row["local_id"]),
        ),
    )
    lines = [
        "# Phase F ARVO Patch↔Buffer-Family Manual Review",
        "",
        "판정 범위는 공개 개발자 패치와 ARVO의 crash family 연결뿐입니다.",
        "PoC, crash output, reproducer, Docker image, 실행파일은 검토하지 않습니다.",
        "",
        "각 항목은 다음 두 boolean을 모두 기록합니다.",
        "",
        "- `operator_family_match`: 패치가 해당 heap/stack + read/write family와 "
        "인과적으로 일치하면 `true`; 불충분·상충하면 `false`.",
        "- `operator_patch_evidence_error`: excerpt가 실제 수정 근거를 잘못 "
        "대표하거나 근거가 없으면 `true`.",
        "",
        "둘 중 하나라도 실패하면 해당 레코드는 오류입니다. 전체 오류율이 "
        "5%를 초과하면 gate는 FAIL입니다.",
        "",
    ]
    for index, row in enumerate(ordered, start=1):
        summary = row["patch_summary"]
        lines.extend(
            [
                f"## {index}. ARVO {row['local_id']} — {row['crash_family']}",
                "",
                f"- Project: `{row['project']}`",
                f"- Candidate CWE: `{row['candidate_cwe']}`",
                f"- Crash type: `{row['crash_type']}`",
                f"- Patch: {row['patch_url']}",
                f"- Patch SHA-256: `{row['patch_sha256']}`",
                f"- Automated disposition: `{summary['automated_disposition']}`",
                f"- Source files / hunks: `{summary['source_file_count']}` / "
                f"`{summary['hunk_count']}`",
                "- `operator_family_match`: `TODO`",
                "- `operator_patch_evidence_error`: `TODO`",
                "- Notes:",
                "",
                "```diff",
                str(summary["review_excerpt"]) or "(no bounded source hunk found)",
                "```",
                "",
            ]
        )
    return "\n".join(lines)


def refresh_arvo_patch_review(
    manifest: Mapping[str, Any],
) -> dict[str, Any]:
    """Refresh bounded summaries from hash-bound cached developer patches."""
    refreshed = deepcopy(dict(manifest))
    for row in refreshed["review_records"]:
        patch_path = Path(str(row["patch_path"]))
        patch_bytes = patch_path.read_bytes()
        _validate_patch_bytes(
            patch_bytes,
            max_bytes=int(refreshed["safety"]["max_patch_bytes"]),
        )
        actual_sha256 = hashlib.sha256(patch_bytes).hexdigest()
        if actual_sha256 != row["patch_sha256"]:
            raise ArvoPatchError(f"cached patch hash mismatch: {patch_path}")
        row["patch_source"] = "cache"
        row["patch_size_bytes"] = len(patch_bytes)
        row["patch_summary"] = summarize_patch(patch_bytes)
        _validate_reviewable_source_patch(patch_bytes, row["patch_summary"])
    return refreshed


def summarize_arvo_patch_manual_review(
    records: Sequence[Mapping[str, Any]],
    *,
    required_count: int,
    maximum_error_rate: float = 0.05,
) -> dict[str, Any]:
    """Apply the fixed human gate to completed ARVO patch review decisions."""
    if len(records) != required_count:
        raise ArvoPatchError(
            f"manual review requires {required_count} records, got {len(records)}"
        )
    partial = [
        str(row["local_id"])
        for row in records
        if isinstance(row.get("operator_family_match"), bool)
        != isinstance(row.get("operator_patch_evidence_error"), bool)
    ]
    if partial:
        raise ArvoPatchError(
            "manual review has partially completed decisions: " + ", ".join(partial)
        )
    completed = [
        row
        for row in records
        if isinstance(row.get("operator_family_match"), bool)
        and isinstance(row.get("operator_patch_evidence_error"), bool)
    ]
    unfinished = [
        str(row["local_id"])
        for row in records
        if not isinstance(row.get("operator_family_match"), bool)
    ]
    family_mismatch_count = sum(
        not bool(row["operator_family_match"]) for row in completed
    )
    evidence_error_count = sum(
        bool(row["operator_patch_evidence_error"]) for row in completed
    )
    error_count = sum(
        not bool(row["operator_family_match"])
        or bool(row["operator_patch_evidence_error"])
        for row in completed
    )
    error_budget = int(required_count * maximum_error_rate)
    if unfinished and error_count <= error_budget:
        raise ArvoPatchError(
            "manual review has unfinished boolean decisions: " + ", ".join(unfinished)
        )
    minimum_error_rate = error_count / required_count
    fail_early = bool(unfinished) and error_count > error_budget
    return {
        "required_count": required_count,
        "reviewed_count": len(completed),
        "unfinished_count": len(unfinished),
        "family_mismatch_count": family_mismatch_count,
        "patch_evidence_error_count": evidence_error_count,
        "error_count": error_count,
        "error_budget": error_budget,
        "minimum_error_rate": minimum_error_rate,
        "maximum_error_rate": maximum_error_rate,
        "status": "fail_early" if fail_early else "complete",
        "pass": not fail_early and minimum_error_rate <= maximum_error_rate,
    }


def apply_arvo_patch_manual_decisions(
    records: Sequence[Mapping[str, Any]],
    decisions: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Apply explicit operator decisions without changing unreviewed records."""
    updated = [dict(row) for row in records]
    by_id = {int(row["local_id"]): row for row in updated}
    seen: set[int] = set()
    for decision in decisions:
        local_id = int(decision["local_id"])
        if local_id in seen:
            raise ArvoPatchError(f"duplicate manual decision: {local_id}")
        seen.add(local_id)
        if local_id not in by_id:
            raise ArvoPatchError(f"manual decision is outside review queue: {local_id}")
        family_match = decision.get("operator_family_match")
        evidence_error = decision.get("operator_patch_evidence_error")
        if not isinstance(family_match, bool) or not isinstance(evidence_error, bool):
            raise ArvoPatchError(f"manual decision requires booleans: {local_id}")
        row = by_id[local_id]
        row["operator_family_match"] = family_match
        row["operator_patch_evidence_error"] = evidence_error
        row["operator_notes"] = str(decision.get("operator_notes") or "")
    return updated


def _validate_patch_bytes(patch_bytes: bytes, *, max_bytes: int) -> None:
    if not patch_bytes:
        raise ArvoPatchError("empty patch response")
    if len(patch_bytes) > max_bytes:
        raise ArvoPatchError("patch exceeds configured maximum size")
    if b"\x00" in patch_bytes[:8192]:
        raise ArvoPatchError("patch response contains binary bytes")
    if b"diff --git " not in patch_bytes:
        raise ArvoPatchError("response is not a unified Git patch")


def _validate_reviewable_source_patch(
    patch_bytes: bytes,
    patch_summary: Mapping[str, Any],
) -> None:
    if b"GIT binary patch" in patch_bytes or b"Binary files " in patch_bytes:
        raise ArvoPatchError("patch contains a Git binary diff")
    if (
        int(patch_summary["source_file_count"]) == 0
        or not str(patch_summary["review_excerpt"]).strip()
    ):
        raise ArvoPatchError("patch has no reviewable C/C++ source hunk")


def _review_excerpt(text: str) -> str:
    source_hunks: list[tuple[bool, str]] = []
    for file_block in re.split(r"(?=^diff --git )", text, flags=re.MULTILINE):
        changed_file_match = re.search(r"^\+\+\+ b/(.+)$", file_block, re.MULTILINE)
        if changed_file_match is None:
            continue
        changed_file = changed_file_match.group(1)
        if not changed_file.lower().endswith(_SOURCE_SUFFIXES):
            continue
        for hunk in re.split(r"(?=^@@ )", file_block, flags=re.MULTILINE):
            if not hunk.startswith("@@ "):
                continue
            changed_lines = [
                line[1:]
                for line in hunk.splitlines()
                if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))
            ]
            relevant = any(
                _BUFFER_TERMS.search(line) or _BOUND_TERMS.search(line)
                for line in changed_lines
            )
            source_hunks.append((relevant, f"--- {changed_file}\n{hunk.strip()}"))
    if not source_hunks:
        return ""
    prioritized = [hunk for relevant, hunk in source_hunks if relevant]
    prioritized.extend(hunk for relevant, hunk in source_hunks if not relevant)
    excerpt = ""
    for hunk in prioritized:
        addition = ("\n\n" if excerpt else "") + hunk
        if len(excerpt) + len(addition) > 8000:
            remaining = 8000 - len(excerpt)
            if remaining > 200:
                excerpt += addition[:remaining]
            break
        excerpt += addition
    return excerpt


def _write_immutable_patch(path: Path, patch_bytes: bytes) -> None:
    if path.exists():
        existing = path.read_bytes()
        if hashlib.sha256(existing).digest() != hashlib.sha256(patch_bytes).digest():
            raise ArvoPatchError(f"existing patch hash mismatch: {path}")
        return
    path.write_bytes(patch_bytes)


def _patch_identity(candidate: Mapping[str, Any]) -> str:
    repo = (
        str(candidate.get("repo_addr") or "").rstrip("/").removesuffix(".git").lower()
    )
    commit = str(candidate.get("fix_commit") or "").lower()
    return f"{repo}@{commit}"


def _attempt_record(
    candidate: Mapping[str, Any],
    status: str,
    detail: str,
) -> dict[str, Any]:
    return {
        "local_id": int(candidate["local_id"]),
        "crash_family": str(candidate["crash_family"]),
        "patch_url": str(candidate["patch_url"]),
        "status": status,
        "detail": detail,
    }


def _hostname(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
