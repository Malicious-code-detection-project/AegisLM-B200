---
type: Decision Note
title: Mistral F5-X Runtime Compatibility Matrix v1 Sol Final
description: 호환성 probe CPU 구현의 allowlist, 회귀 테스트, 기존 환경 보존 및 다음 승인 경계에 대한 Sol 최종 판정
tags: [aegislm, mistral, compatibility, review, decision]
timestamp: 2026-08-09
status: active
---

# Final Verdict

```yaml
work_order_id: mistral-f5x-runtime-compatibility-matrix-v1
actor_role: sol_main
parent_work_order_id: not_applicable
head_sha: cb520cdd132f86f23fc45a8800cb6c20c3ab9dc3
worktree_diff_sha256: c23b8b7f17a2148d3c2c34abcd6558b1b2ec854b1afb1dae6071617062506b33
worktree_hash_scope: before this final evidence file
result: PASS
delegation_used: true
delegated_to:
  - terra-runtime-planner: read-only plan review
  - luna-runtime-implementer: allowlisted CPU implementation and fixes
effective_sandbox_mode: workspace-write
effective_approval_policy: managed; approved existing-interpreter test execution only
evidence_complete: true
revalidation_basis: evidence_conflict
revalidation_reason: >-
  Luna의 최초 evidence와 실제 targeted pytest 및 Ruff format 결과가 달라 Sol이
  수정과 재검증을 요구했다. 최종 파일과 모든 gate는 독립 재실행 결과와 일치한다.
changed_files:
  - .gitignore
  - docs/operations/b200/B200_2GPU_SETUP.md
  - docs/operations/b200/FINETUNING_TEST_WORKBOOK.md
  - configs/runtime/mistral_f5x_compatibility_matrix.json
  - aegislm/experiments/runtime_compatibility.py
  - scripts/probe_mistral_f5x_compatibility.py
  - tests/test_mistral_runtime_compatibility.py
  - review/workflows/mistral-f5x-runtime-compatibility-matrix-v1/00-work-order-v1.md
  - review/workflows/mistral-f5x-runtime-compatibility-matrix-v1/01-sol-main-dispatch.md
  - review/workflows/mistral-f5x-runtime-compatibility-matrix-v1/02-planner-plan.md
  - review/workflows/mistral-f5x-runtime-compatibility-matrix-v1/03-implementer-evidence.md
  - review/workflows/mistral-f5x-runtime-compatibility-matrix-v1/05-sol-main-final.md
out_of_allowlist_changes: []
preexisting_changes_preserved: true
failed_skipped_not_executed:
  failed: []
  skipped:
    - full pytest skipped three pre-existing environment-dependent tests
  not_executed:
    - dependency installation or lock creation
    - actual B200 compatibility probe
    - model, tokenizer, or dataset download
    - SSH or GPU execution
    - symlink creation
    - final .venv-axolotl creation
    - Git stage, commit, push, or PR
known_limitations:
  - CPU PASS proves the probe contract, not a compatible runtime candidate.
  - Actual candidate selection requires a separately approved B200 probe.
approval_required_next:
  - dependency download and installation into exclusive probe environments
  - SSH and B200 runtime probe execution
```

# Independent Verification

| Gate | Result |
| --- | --- |
| Frozen matrix CLI validate | PASS, SHA-256 `47e2a8714d38e5b9cad3001a6bdad95fc6e0cd2599a51851618adbddc2007378` |
| Frozen matrix CLI plan | PASS, three isolated candidates and no final environment creation |
| Targeted compatibility tests | `20 passed` |
| Mistral compatibility and regression tests | `48 passed` |
| Full pytest | `467 passed, 3 skipped` |
| Ruff check | PASS |
| Ruff format check | `259 files already formatted` |
| mypy official scope | `151 source files`, PASS |
| `git diff --check` | PASS; only line-ending warnings on pre-existing Windows worktree files |
| Original 22-file baseline | only allowlisted `.gitignore` and two B200 docs changed; other 19 hashes unchanged |
| Install/download/SSH/GPU/symlink/Git mutation | NOT EXECUTED |

# Decision

CPU 구현 단계는 `PASS`다. `current-declared`, `official-v0-17`,
`approved-negative-control`을 각각 `.runtime-probes/mistral-f5x` 아래의 배타적
환경에서 검사할 준비가 되었다. 이 판정은 어느 후보도 호환으로 승인하지 않는다.
다음 단계는 별도 승인된 B200 probe이며, 결과 inventory를 Sol이 검토하기 전에는
최종 `.venv-axolotl`을 만들거나 runtime manifest와 experiment pin을 변경할 수 없다.

# Related Concepts

- [Work Order](00-work-order-v1.md)
- [Terra plan](02-planner-plan.md)
- [Luna evidence](03-implementer-evidence.md)
