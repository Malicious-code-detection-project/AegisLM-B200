---
type: Decision Note
title: Mistral F5-X Runtime Compatibility Matrix v1 Terra Plan
description: Terra planner의 read-only 구현 계획 검토와 CPU 단계 판정
tags: [aegislm, mistral, agents, planning]
timestamp: 2026-08-08
status: active
---

# Verdict

```yaml
work_order_id: mistral-f5x-runtime-compatibility-matrix-v1
actor_role: planner
parent_work_order_id: mistral-f5x-runtime-compatibility-matrix-v1
head_sha: cb520cdd132f86f23fc45a8800cb6c20c3ab9dc3
worktree_diff_sha256: eaa652b9eea6cec94f6d491f8e12817935174eb6ff9912d9a34532d50963b6f0
result: PASS
delegation_used: false
delegated_to: []
effective_sandbox_mode: read-only
effective_approval_policy: no external mutation
evidence_complete: true
revalidation_basis: initial
revalidation_reason: null
commands:
  - command: read frozen Work Order and allowlisted runtime implementation
    exit_code: 0
    key_output: CPU implementation plan is bounded and testable
changed_files: []
out_of_allowlist_changes: []
preexisting_changes_preserved: true
failed_skipped_not_executed:
  failed: []
  skipped: []
  not_executed:
    - dependency installation
    - B200 probe
    - SSH and GPU verification
known_limitations:
  - PASS는 probe 도구의 CPU 구현 계획에만 적용된다.
  - 실제 compatible 후보 확정은 별도 승인된 B200 evidence가 필요하다.
approval_required_next:
  - dependency installation
  - SSH and B200 probe execution
```

# Frozen Implementation Plan

- matrix는 `current-declared`, `official-v0-17`, `approved-negative-control`의
  세 후보를 고정 순서로 정의한다.
- loader는 raw-byte SHA-256, exact key/type/value, 안전한 probe namespace를
  검증한다.
- 공개 CLI는 `--matrix`와 `--action validate|plan|probe`만 허용하며 후보나
  패키지 override를 제공하지 않는다.
- `validate`와 `plan`은 파일시스템을 변경하지 않는다. `probe`는 승인 hash와
  배타적인 새 probe directory를 요구한다.
- resolver와 `uv pip check`를 정상적으로 실행하고 `--no-deps`, metadata patch,
  floating dependency, 실패 무시를 허용하지 않는다.
- 기존 Qwen `.venv`의 pre/post tree fingerprint를 비교한다.
- candidate evidence에는 command, exit code, package/direct-url identity, imports,
  CUDA/GPU, Axolotl CLI 경로, Mistral 4 import와 Qwen fingerprint를 포함한다.
- negative control은 성공 여부와 관계없이 선택 후보로 승격할 수 없다.
- 테스트는 schema drift, unsafe path, filesystem purity, approval mismatch,
  directory collision, exact subprocess command, fingerprint mutation과 불완전
  evidence 거부를 포함한다.

# Stop Conditions

HEAD 또는 기존 22개 baseline hash 변경, allowlist 밖 수정, root dependency나
approved runtime/config pin 변경 필요, 설치·다운로드·SSH·GPU·symlink·Git 실행,
기존 `.venv`/`.venv-axolotl` 변경, dependency override 필요, evidence 누락 시
즉시 `BLOCK`한다.

# Related Concepts

- [Work Order](00-work-order-v1.md)
- [Sol dispatch](01-sol-main-dispatch.md)
