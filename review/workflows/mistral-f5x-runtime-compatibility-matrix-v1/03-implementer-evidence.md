---
type: Decision Note
title: Mistral F5-X Runtime Compatibility Matrix v1 Implementer Evidence
description: Luna implementer의 allowlist 구현과 로컬 검증 증거
tags: [aegislm, mistral, compatibility, implementation, evidence]
timestamp: 2026-08-08
status: active
---

# Verdict

```yaml
actor_role: implementer
work_order_id: mistral-f5x-runtime-compatibility-matrix-v1
parent_work_order_id: mistral-f5x-runtime-compatibility-matrix-v1
head_sha: cb520cdd132f86f23fc45a8800cb6c20c3ab9dc3
worktree_diff_sha256: 6bab1f58c470121b672ef102179caf963ecfa37dcdf9f48aadb74aa3f5c33841
worktree_hash_scope: pre-evidence-file implementation state
result: FIXED
delegation_used: false
delegated_to: []
effective_sandbox_mode: workspace-write
effective_approval_policy: no install, download, SSH, GPU, symlink, or Git mutation
changed_files:
  - configs/runtime/mistral_f5x_compatibility_matrix.json
  - aegislm/experiments/runtime_compatibility.py
  - scripts/probe_mistral_f5x_compatibility.py
  - tests/test_mistral_runtime_compatibility.py
  - .gitignore
  - docs/operations/b200/B200_2GPU_SETUP.md
  - docs/operations/b200/FINETUNING_TEST_WORKBOOK.md
  - review/workflows/mistral-f5x-runtime-compatibility-matrix-v1/03-implementer-evidence.md
out_of_allowlist_changes: []
preexisting_changes_preserved: true
evidence_complete: true
revalidation_basis: sol_review_fixes
revalidation_reason: >-
  Sol review에서 matrix 경로 결박, CLI filesystem purity, Python pin,
  child runtime evidence 검증과 prohibited option 범위를 보강하도록 요청했다.
failed_skipped_not_executed:
  failed:
    - command: Sol Ruff format-check
      reason: runtime compatibility module and tests required formatting; Ruff formatter applied to both files, independent rerun pending
    - command: Sol approved-interpreter targeted pytest
      reason: one assertion expected immutable value drift instead of the actual unsafe compatibility path message; expectation corrected, rerun pending
    - command: .venv/Scripts/python.exe -m pytest tests/test_mistral_runtime_compatibility.py -q
      reason: uv trampoline permission denied (os error 5); tests did not start
    - command: .venv/Scripts/python.exe -m ruff check <target files>
      reason: uv trampoline permission denied (os error 5); check did not start
    - command: .venv/Scripts/python.exe -m mypy <target modules>
      reason: uv trampoline permission denied (os error 5); check did not start
  skipped: []
  not_executed:
    - dependency installation or lock creation
    - actual compatibility probe
    - model, tokenizer, or dataset download
    - SSH or GPU execution
    - symlink creation
    - final .venv-axolotl creation
    - full pytest, Ruff format-check, and full mypy
known_limitations:
  - Local Python-based verification is unavailable because the existing uv trampoline cannot spawn its child process in this sandbox.
  - Compatible candidates can be selected only by a separately approved B200 probe and Sol review.
approval_required_next:
  - approved interpreter for CPU verification
  - dependency download, SSH, and B200 probe execution
```

# Commands

| Command | Exit | Evidence |
| --- | ---: | --- |
| Read frozen Work Order and Terra plan | 0 | allowlist and candidate pins confirmed |
| `.venv/Scripts/python.exe -m pytest tests/test_mistral_runtime_compatibility.py -q` | 1 | uv trampoline permission denied before test execution |
| `.venv/Scripts/python.exe -m ruff check ...` | 1 | same trampoline failure before Ruff execution |
| `.venv/Scripts/python.exe -m mypy ...` | 1 | same trampoline failure before mypy execution |
| `git diff --check` | 0 | whitespace check passed |
| long-line audit of the three Python files | 1 | `rg` found no lines over 88 characters |

# Implemented Contract

- Matrix candidates are fixed to `current-declared`, `official-v0-17`, and
  `approved-negative-control`; the negative control is never final-eligible.
- `validate` and `plan` do not create files, and the public CLI enables
  `sys.dont_write_bytecode` before importing repository modules.
- `--matrix` resolves only to the repository-owned canonical matrix.
- `probe` requires the raw-byte matrix SHA-256 and refuses an existing probe root.
- Resolver commands use normal dependency resolution followed by `uv pip check`.
  No dependency escape hatch is exposed.
- Child evidence must exactly match the candidate, matrix hash, Python 3.12,
  CUDA 13.0, two B200 identities, package/version/source contracts, Mistral 4
  symbols, and candidate environment CLI prefix. Incomplete evidence is recorded
  as incompatible and cannot enter the eligible candidate list.
- The existing Qwen `.venv` tree fingerprint is compared before and after the
  matrix run. The probe never creates `.venv-axolotl`.
