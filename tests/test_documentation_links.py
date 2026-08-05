from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
IGNORED_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "artifacts",
    "cache",
    "raw",
    "vendor",
}
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")
HTML_LINK = re.compile(r"\b(?:href|src)\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
URI_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*:", re.IGNORECASE)

MIGRATED_DOCUMENTS = {
    "AGENT_WORKFLOW.md": "docs/governance/AGENT_WORKFLOW.md",
    "CONTRIBUTING.md": "docs/governance/CONTRIBUTING.md",
    "QUALITY_GATES.md": "docs/governance/QUALITY_GATES.md",
    "LOCAL_LLM_MCP_BOUNDARY_IDEA.md": "docs/design/architecture/LOCAL_LLM_MCP_BOUNDARY_IDEA.md",
    "DATA_STRATEGY.md": "docs/design/datasets/DATA_STRATEGY.md",
    "DATASET_CANDIDATES.md": "docs/design/datasets/DATASET_CANDIDATES.md",
    "ABSOLUTE_EVALUATION.md": "docs/evaluation/ABSOLUTE_EVALUATION.md",
    "EVALUATION_PLAN.md": "docs/evaluation/EVALUATION_PLAN.md",
    "PHASE_D_EXIT_CRITERIA.md": "docs/evaluation/PHASE_D_EXIT_CRITERIA.md",
    "SOURCE_MANUAL_REVIEW_RUBRIC.md": "docs/evaluation/SOURCE_MANUAL_REVIEW_RUBRIC.md",
    "TEST_CRITERIA.md": "docs/evaluation/TEST_CRITERIA.md",
    "FINETUNING_EXPERIMENT_PLAN.md": "docs/experiments/plans/FINETUNING_EXPERIMENT_PLAN.md",
    "PHASE_F_DATASET_AND_BINARY_EXPERIMENT_PLAN.md": "docs/experiments/plans/PHASE_F_DATASET_AND_BINARY_EXPERIMENT_PLAN.md",
    "PHASE_F_ARVO_PATCH_GATE_DECISION_20260731.md": "docs/experiments/decisions/phase-f/PHASE_F_ARVO_PATCH_GATE_DECISION_20260731.md",
    "PHASE_F_ASSEMBLAGE_METADATA_DECISION_20260731.md": "docs/experiments/decisions/phase-f/PHASE_F_ASSEMBLAGE_METADATA_DECISION_20260731.md",
    "PHASE_F_BINARY_ROLE_TARGET_DECISION_20260731.md": "docs/experiments/decisions/phase-f/PHASE_F_BINARY_ROLE_TARGET_DECISION_20260731.md",
    "PHASE_F_BINKIT_METADATA_DECISION_20260731.md": "docs/experiments/decisions/phase-f/PHASE_F_BINKIT_METADATA_DECISION_20260731.md",
    "PHASE_F_DECOMPILE_BENCH_ALIGNMENT_DECISION_20260731.md": "docs/experiments/decisions/phase-f/PHASE_F_DECOMPILE_BENCH_ALIGNMENT_DECISION_20260731.md",
    "PHASE_F_EMBER2024_BENCHMARK_DECISION_20260731.md": "docs/experiments/decisions/phase-f/PHASE_F_EMBER2024_BENCHMARK_DECISION_20260731.md",
    "PHASE_F_EMBER2024_CLASSIFIER_BASELINE_DECISION_20260731.md": "docs/experiments/decisions/phase-f/PHASE_F_EMBER2024_CLASSIFIER_BASELINE_DECISION_20260731.md",
    "PHASE_F_PATCH_LABEL_SUPPLY_DECISION_20260731.md": "docs/experiments/decisions/phase-f/PHASE_F_PATCH_LABEL_SUPPLY_DECISION_20260731.md",
    "B200_2GPU_SETUP.md": "docs/operations/b200/B200_2GPU_SETUP.md",
    "B200_SERVER_READINESS_REPORT.md": "docs/operations/b200/B200_SERVER_READINESS_REPORT.md",
    "B200_TRAINING_HANDOFF.md": "docs/operations/b200/B200_TRAINING_HANDOFF.md",
    "ENVIRONMENT_PROFILES.md": "docs/operations/b200/ENVIRONMENT_PROFILES.md",
    "FINETUNING_TEST_WORKBOOK.md": "docs/operations/b200/FINETUNING_TEST_WORKBOOK.md",
    "FULL_SIZE_TRAINING_QUEUE.md": "docs/operations/b200/FULL_SIZE_TRAINING_QUEUE.md",
    "LLAMA_FACTORY_B200_WANDB.md": "docs/operations/b200/LLAMA_FACTORY_B200_WANDB.md",
    "ARTIFACT_STORAGE_POLICY.md": "docs/operations/policies/ARTIFACT_STORAGE_POLICY.md",
    "CHECKPOINT_POLICY.md": "docs/operations/policies/CHECKPOINT_POLICY.md",
    "DEEPSPEED_ZERO3_DTYPE_MISMATCH.md": "docs/operations/troubleshooting/DEEPSPEED_ZERO3_DTYPE_MISMATCH.md",
    "EXPERIMENT_LOG_TEMPLATE.md": "docs/templates/EXPERIMENT_LOG_TEMPLATE.md",
    "PR_DESCRIPTION_TEMPLATE.md": "docs/templates/PR_DESCRIPTION_TEMPLATE.md",
    "PHASE_E_TEAM_ONBOARDING.html": "docs/onboarding/PHASE_E_TEAM_ONBOARDING.html",
    "COMMIT_REVIEW_GUIDE_KO.md": "review/guides/COMMIT_REVIEW_GUIDE_KO.md",
}


def _is_in_scope(path: Path) -> bool:
    return not any(part in IGNORED_PARTS for part in path.parts)


def _project_documents() -> list[Path]:
    documents = [
        PROJECT_ROOT / name for name in ("README.md", "AGENTS.md", "CONTRIBUTING.md")
    ]
    for directory in (PROJECT_ROOT / "docs", PROJECT_ROOT / "review"):
        documents.extend(
            path
            for path in directory.rglob("*")
            if path.suffix.lower() in {".md", ".html"} and _is_in_scope(path)
        )
    return documents


def _targets(document: Path) -> list[str]:
    text = document.read_text(encoding="utf-8")
    return [*MARKDOWN_LINK.findall(text), *HTML_LINK.findall(text)]


def _resolves(document: Path, target: str) -> bool:
    target = target.strip().strip("<>")
    target = target.split(maxsplit=1)[0]
    location = target.split("#", 1)[0]
    if not location:
        return True
    if URI_SCHEME.match(location):
        return True
    return (document.parent / location).resolve().exists()


def _old_project_path_tokens() -> list[str]:
    return [f"docs/{source_name}" for source_name in MIGRATED_DOCUMENTS]


def test_migrated_documents_are_only_at_their_new_paths() -> None:
    failures = []
    for source_name, destination in MIGRATED_DOCUMENTS.items():
        old_path = PROJECT_ROOT / "docs" / source_name
        new_path = PROJECT_ROOT / destination
        if old_path.exists() or not new_path.is_file():
            failures.append(f"{old_path.relative_to(PROJECT_ROOT)} -> {destination}")
    assert not failures, "\n".join(failures)


def test_migration_destinations_are_not_ignored() -> None:
    git_executable = shutil.which("git")
    if git_executable is None:
        return

    repository_check = subprocess.run(
        [
            git_executable,
            "-c",
            f"safe.directory={PROJECT_ROOT}",
            "rev-parse",
            "--is-inside-work-tree",
        ],
        capture_output=True,
        check=False,
        cwd=PROJECT_ROOT,
        text=True,
    )
    if not (PROJECT_ROOT / ".git").exists():
        return
    assert repository_check.returncode == 0, repository_check.stderr.strip()
    assert repository_check.stdout.strip() == "true", repository_check.stdout.strip()

    failures = []
    for destination in MIGRATED_DOCUMENTS.values():
        result = subprocess.run(
            [
                git_executable,
                "-c",
                f"safe.directory={PROJECT_ROOT}",
                "check-ignore",
                "--no-index",
                "-q",
                destination,
            ],
            capture_output=True,
            check=False,
            cwd=PROJECT_ROOT,
            text=True,
        )
        assert result.returncode in {0, 1}, (
            f"git check-ignore failed for {destination}: {result.stderr.strip()}"
        )
        if result.returncode == 0:
            failures.append(destination)
    assert not failures, "Ignored migration destinations:\n" + "\n".join(failures)


def test_documentation_relative_links_resolve() -> None:
    failures = []
    for document in _project_documents():
        for target in _targets(document):
            if not _resolves(document, target):
                failures.append(f"{document}: {target}")
    assert not failures, "Broken documentation links:\n" + "\n".join(failures)


def test_migrated_document_path_literals_are_rebased() -> None:
    failures = []
    for document in _project_documents():
        text = document.read_text(encoding="utf-8")
        for old_path in _old_project_path_tokens():
            if old_path in text:
                failures.append(f"{document}: {old_path}")

    assert not failures, "Unrebased migrated document paths:\n" + "\n".join(failures)
