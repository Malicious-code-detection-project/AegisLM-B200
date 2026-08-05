---
type: Setup Guide
title: AegisLM 역할 기반 custom-agent 운영 가이드
description: sol_main이 동결된 Work Order 안에서 역할 기반 custom agent를 최대 depth 1로 배정하고 증거와 gate를 관리하는 운영 기준
tags: [aegislm, agents, workflow, review]
timestamp: 2026-08-04
status: active
---

# AegisLM 역할 기반 custom-agent 운영 가이드

## 1. 목적

이 문서는 모델 이름보다 역할, 권한, Work Order, 검증 증거와 gate를 우선하여 AegisLM 작업을 운영하기 위한 기준이다. 실행 가능한 역할 설정은 [`.codex/agents/`](../../.codex/agents/)에 두고, 사용자는 목적·불변 조건·권한과 외부 실행 승인을 정하며, `sol_main`은 동결된 Work Order를 관리한다.

프로젝트는 worker가 다른 worker를 부르는 구조를 사용하지 않는다. 다만 동결된 Work Order 안에서 `sol_main`만 depth 1, 최대 2명의 worker를 배정할 수 있다. 모든 worker는 배정받은 작업을 직접 수행하며 재위임하지 않는다.

## 2. 권한과 orchestration

```text
사용자: 목적·불변 조건·allowlist·설치·다운로드·GPU·Git 권한을 승인한다.
sol_main: Work Order를 frozen으로 만들고, 필요한 worker를 dispatch하며, 상태·증거·최종 판정을 관리한다.
planner: 읽기 전용으로 저장소 조사, 파일 단위 계획, 테스트·위험·중단 조건을 직접 제출한다.
implementer: 승인 allowlist 안에서 일반 구현·디버깅·테스트와 결함 수정을 직접 수행한다.
mechanical-worker: 결정론적·반복적·기계 검증 가능한 수정·검사만 직접 수행한다.
security-reviewer: 필요할 때 독립적인 읽기 전용 고위험 diff·evidence·보안 검토를 직접 수행한다.
```

작업 크기에 따라 다음 경로를 사용한다.

- `small`: Sol 단독
- `normal`: Sol → worker 1명 → Sol
- `complex`: 필요한 경우에만 planner 계획 → implementer 구현 → Sol 종합
- `high-risk`: 위 경로에 security-reviewer를 추가

`sol_main`은 동결된 Work Order에 기록된 worker만 dispatch한다. 일반 worker가 다른 worker를 호출하거나 자동 handoff·재위임하는 것은 금지한다.

### 2.1 worker 재위임 금지와 sol_main dispatch

worker 재위임은 예외 없이 금지한다. `sol_main`의 depth 1 dispatch는 worker
재위임이 아니라 orchestration이다.

- 허용 주체: `sol_main` 하나
- 허용 조건: `status: frozen`인 Work Order 안에서만
- 최대 깊이: `max_delegation_depth: 1`
- 최대 동시 worker: `max_parallel_workers: 2`
- worker의 `spawn_agent`, 자동 handoff, 하위 작업자 생성, 다른 모델 재위임: 금지

`delegation_policy`는 `orchestrator_only`, 개별 worker의 `worker_delegation`은 `forbidden`으로 고정한다. 개별 Work Order는 이 원칙을 해제할 수 없다.

TOML의 sandbox는 기본값이다. parent turn의 live permission·approval override 또는 `--yolo`가 이를 바꿀 수 있으므로, `sol_main`은 dispatch 전에 effective permission과 sandbox를 확인한다. planner 또는 security-reviewer가 write-capable 환경이면 read-only로 바꾼 뒤 dispatch하거나 `BLOCK`한다. 이 규칙은 [OpenAI Codex Subagents의 approvals and sandbox controls](https://developers.openai.com/codex/agent-configuration/subagents)를 따른다.

같은 파일을 여러 worker가 동시에 수정하지 않는다. 병렬 dispatch는 서로 겹치지 않는 읽기 전용 조사 또는 파일 allowlist가 분리된 작업에만 허용한다. workspace-write allowlist는 filesystem enforcement가 아닌 운영 계약이며, `sol_main`은 최종 changed path를 allowlist와 대조한다.

동일한 `head_sha`와 `worktree_diff_sha256`에 대해 `evidence_complete: true`인 gate는 반복하지 않는다. 재검증은 다음 사유 중 하나를 Work Order와 evidence에 명시한 경우에만 가능하다.

- `head_changed`
- `worktree_changed`
- `evidence_missing`
- `evidence_conflict`

implementer와 mechanical-worker는 allowlist 내부 결함을 직접 수정하고 재시험한 뒤 `FIXED`로 보고한다. `REQUEST_CHANGES`는 planner와 security-reviewer만 사용한다. `BLOCK`은 사용자 승인, 외부 상태, 또는 allowlist 밖 범위 확장이 필요한 경우에만 사용한다.

설치·다운로드·GPU 실행·Git stage/commit/push는 사용자의 별도 승인이 없으면 수행하지 않는다.

## 3. 역할별 계약

### 3.1 사용자 / Owner

사용자는 다음을 결정한다.

- 목적, 불변 조건, 허용 gate와 `PASS/BLOCK` 기준
- 모델·데이터·artifact의 immutable identity
- 정확한 수정 allowlist와 금지 범위
- dependency 설치, 모델·데이터 다운로드, GPU 실행
- Git stage, commit, push, PR
- gate 또는 Work Order 범위 변경
- 다음 작업과 최종 승인

### 3.2 `sol_main`

`sol_main`은 다음을 직접 관리한다.

- 사용자 요구를 Work Order로 구조화하고 `frozen` 상태로 동결
- Work Order의 `base_commit`, `head_sha`, `worktree_diff_sha256`, orchestration 필드와 worker allowlist 기록
- 필요할 때만 depth 1, 최대 2 worker dispatch
- worker 상태와 evidence 수집, 중복 gate 방지, 최종 결과 종합
- 최종 `PASS` 또는 `BLOCK`, 또는 사용자가 결정할 다음 gate 보고

다음은 금지한다.

- 동결 전 dispatch 또는 동결 Work Order 밖의 작업 배정
- depth 1 초과, worker 2명 초과, 같은 파일 동시 수정
- worker에게 재위임을 허용하거나 worker 대신 설치·다운로드·GPU·Git 승인 수행
- 사용자 승인 없는 gate·allowlist·schema 변경

### 3.3 planner

planner는 읽기 전용으로 배정 범위의 저장소 조사와 파일 단위 계획을 직접 수행한다. 계획에는 수정 파일, 금지 파일, 테스트 명령, 위험과 중단 조건을 포함한다. 결과는 `PASS`, `REQUEST_CHANGES`, `BLOCK` 중 하나로 보고하며, worker를 호출하거나 재위임하지 않는다.

### 3.4 implementer

implementer는 동결된 Work Order의 allowlist 안에서 일반 구현·디버깅·테스트를 직접 수행한다. allowlist 내부 결함은 직접 수정·재시험하고 `FIXED`로 보고한다. 다음은 `BLOCK`으로 보고한다.

- allowlist 밖 파일 변경이 필요한 경우
- gate·schema·불변 조건 변경이 필요한 경우
- dependency 설치, 다운로드, GPU·외부 서비스 실행이 필요한 경우
- stage·commit·push가 필요한 경우
- 기존 사용자 변경과 충돌하는 경우

implementer는 `REQUEST_CHANGES`를 사용하지 않으며, worker를 호출하거나 재위임하지 않는다.

### 3.5 mechanical-worker

mechanical-worker는 결정론적·반복적·기계 검증 가능한 작업만 받는다. 승인 allowlist 밖의 설계 판단, 새로운 정책·schema·gate, 불명확한 결함은 `BLOCK`으로 보고한다. `FIXED` 또는 `BLOCK`만 사용하며 worker를 호출하거나 재위임하지 않는다.

### 3.6 security-reviewer

security-reviewer는 read-only로 고위험 diff와 테스트·evidence, 보안·개인정보 경계를 독립적으로 확인하고 `PASS`, `REQUEST_CHANGES`, `BLOCK`을 보고한다. 수정이 필요하면 직접 고치지 않고 구체적인 변경 이유와 gate를 남긴다. worker를 호출하거나 재위임하지 않는다.

## 4. 표준 실행 순서

```text
1. 사용자가 목적·불변 조건·권한·allowlist를 정한다.
2. sol_main이 Work Order를 작성하고 frozen으로 동결한다.
3. small이면 sol_main이 직접 처리한다.
4. normal이면 sol_main이 한 worker를 dispatch하고 결과를 종합한다.
5. complex이면 sol_main이 planner 계획 후 implementer 구현을 순차 dispatch한다.
6. high-risk이면 sol_main이 security-reviewer를 추가 dispatch한다.
7. sol_main이 head_sha, worktree_diff_sha256, changed_files, 명령·exit code, gate와 verdict를 종합한다.
8. 사용자가 최종 승인, Git 작업, 다음 gate 또는 중단을 결정한다.
```

서로 겹치지 않는 조사만 병렬화할 수 있다. 구현과 검토, 같은 파일을 쓰는 작업은 순차 수행한다. `head_sha`와 `worktree_diff_sha256`가 evidence와 모두 일치하면 동일 gate를 되풀이하지 않는다.

## 5. Work Order 계약

모든 Work Order는 다음 필드를 포함한다.

```yaml
work_order_id: <task>-v1
status: draft | frozen | dispatched | evidence_ready | review_ready | complete | blocked
owner: <user>
base_commit: <immutable base commit>
head_sha: <current head sha>
worktree_diff_sha256: <current worktree diff sha256>
baseline:
  dirty_files: []
  dirty_diff_sha256: <sha256 or not_applicable>
delegation: forbidden  # worker 재위임. sol_main의 depth 1 dispatch는 orchestration 예외다.

orchestration:
  delegation_policy: orchestrator_only
  allowed_delegator: sol_main
  worker_delegation: forbidden
  max_delegation_depth: 1
  max_parallel_workers: 2

workers:
  - worker_id: <id>
    role: planner | implementer | mechanical-worker | security-reviewer
    mode: plan | implementation | mechanical | review
    required_sandbox_mode: read-only | workspace-write
    required_approval_policy: <required policy>
    allowed_files: []
    state: pending | dispatched | evidence_ready | complete | blocked

objective: <검증 가능한 목적>
out_of_scope: []
immutable_inputs:
  model_id: not_applicable
  model_revision: not_applicable
  dataset_manifest: not_applicable
  dataset_sha256: not_applicable
  evaluation_artifact_sha256: not_applicable
  schema_version: not_applicable

allowed_files: []
forbidden_files: []

do_not_repeat:
  - head_sha: <sha>
    worktree_diff_sha256: <sha256>
    gate: <gate id>
    evidence_complete: true
    revalidation_basis: none
    revalidation_reason: null

gates:
  pass: []
  block: []

approvals_required:
  dependency_install: true
  model_or_data_download: true
  gpu_execution: true
  git_stage_commit_push: true

required_evidence:
  - actor_role
  - work_order_id
  - parent_work_order_id
  - head_sha
  - worktree_diff_sha256
  - result
  - delegation_used
  - delegated_to
  - effective_sandbox_mode
  - effective_approval_policy
  - commands
  - changed_files
  - out_of_allowlist_changes
  - preexisting_changes_preserved
  - failed_skipped_not_executed
  - evidence_complete
  - revalidation_basis
  - revalidation_reason
  - known_limitations
  - approval_required_next
```

`status`는 실제 상태 전이에 맞춰 갱신한다. `orchestration`의 다섯 값은 Work Order마다 명시하며, worker가 이를 변경할 수 없다. dispatch 전 `sol_main`은 parent의 live permission과 effective sandbox를 확인하고, read-only 역할이 write-capable이면 `BLOCK`한다. `do_not_repeat`에 같은 `head_sha`와 같은 `worktree_diff_sha256`의 완전한 evidence가 있으면 gate를 반복하지 않는다. 반복이 필요하면 `head_changed`, `worktree_changed`, `evidence_missing`, `evidence_conflict` 중 하나와 이유를 기록한다.

`worktree_diff_sha256`는 Git이 추적하는 변경만이 아니라 untracked 파일도 포함한다. 변경 상태와 repository-relative 경로를 정렬한 뒤, 현재 파일 내용의 SHA-256 또는 삭제 marker를 기록한 canonical manifest를 만들고 그 manifest의 SHA-256을 사용한다. 같은 Work Order 안에서는 동일한 생성 절차를 유지한다.

적용하지 않는 immutable 입력은 `null`이 아니라 `not_applicable`로 표시한다. `TODO`, `REQUIRED`, `CHANGEME`가 남아 있으면 Work Order를 `frozen`으로 만들지 않는다.

gate·schema·allowlist 또는 불변 조건을 바꿔야 하면 현재 Work Order를 `blocked`로 보고하고 사용자 승인 후 새 버전을 만든다.

## 6. Evidence 계약

각 worker와 reviewer는 다음 구조로 증거를 제출한다.

```yaml
work_order_id: <task>-v1
actor_role: sol_main | planner | implementer | mechanical-worker | security-reviewer
parent_work_order_id: <parent id or not_applicable>
head_sha: <sha at execution>
worktree_diff_sha256: <worktree diff sha256 at execution>
result: FIXED | PASS | REQUEST_CHANGES | BLOCK

delegation_used: false | true
delegated_to: []
# worker/reviewer는 항상 false와 []를 사용한다.
# sol_main은 dispatch했다면 true와 실제 역할·작업 식별자 목록을 사용한다.
# sol_main이 단독 작업이면 false와 []를 사용한다.
effective_sandbox_mode: read-only | workspace-write | <actual mode>
effective_approval_policy: <actual policy>
evidence_complete: true | false
revalidation_basis: initial | head_changed | worktree_changed | evidence_missing | evidence_conflict
revalidation_reason: <사유 or null>

commands:
  - command: <실행 명령>
    exit_code: <정수>
    key_output: <핵심 출력>

changed_files: []
out_of_allowlist_changes: []
preexisting_changes_preserved: true | false
failed_skipped_not_executed:
  failed: []
  skipped: []
  not_executed: []
known_limitations: []
approval_required_next: []
```

worker/reviewer evidence에는 `delegation_used: false`, `delegated_to: []`를
항상 고정한다. `sol_main` evidence는 실제 dispatch 여부를 기록한다. 한 명
이상의 worker를 dispatch했으면 `delegation_used: true`와 실제 역할·작업
식별자 목록을 기록하고, Sol 단독 작업이면 `false`와 `[]`를 기록한다.
`sol_main`의 dispatch 자체는 worker 재위임이 아니라 orchestration이다.

effective permission을 확인할 수 없으면 `evidence_complete: false`와 `BLOCK`으로 보고한다. read-only 역할의 `changed_files`는 항상 `[]`다. `PASS`는 변경 파일, 명령, exit code, 실패·skip·미실행 항목, gate가 모두 확인된 경우에만 가능하다. implementer와 mechanical-worker의 결과는 `FIXED` 또는 `BLOCK`이고, `REQUEST_CHANGES`는 planner와 security-reviewer만 사용할 수 있다. `sol_main` 최종 gate는 `git diff --name-only`와 allowlist를 대조하고, 현재 `worktree_diff_sha256`가 evidence hash와 일치하며 baseline dirty diff가 보존됐는지 확인한다.

## 7. 판정 규칙

- implementer / mechanical-worker: `FIXED` 또는 `BLOCK`
- planner / security-reviewer: `PASS`, `REQUEST_CHANGES` 또는 `BLOCK`
- `sol_main`: 최종 `PASS`, `BLOCK` 또는 다음 gate 보고

`BLOCK`은 사용자 승인, 외부 상태, allowlist 밖 범위 확장이 필요한 경우에만 사용한다. 단순한 allowlist 내부 결함은 implementer 또는 mechanical-worker가 수정·재시험하여 `FIXED`로 보고한다. planner 또는 security-reviewer의 `REQUEST_CHANGES`는 수정할 파일, 근거, 재시험 gate를 구체적으로 지정해야 한다.

## 8. 작업 기록 구조

```text
review/workflows/<task>/
├── 00-work-order-v1.md
├── 01-sol-main-dispatch.md
├── 02-planner-plan.md
├── 03-implementer-evidence.md
├── 04-security-review-evidence.md
└── 05-sol-main-final.md
```

기록에는 raw secret, token, private path, raw 보안 payload를 넣지 않는다. 외부 artifact는 승인된 식별자와 hash만 기록한다.

## 9. 복사 가능한 역할 지시문

### `sol_main` dispatch

```text
역할: sol_main
mode: orchestration
delegation_policy: orchestrator_only

dispatch 결과에 따라 evidence 감사 필드를 작성하라.
- worker를 한 명 이상 dispatch: `delegation_used: true`, `delegated_to`에 실제 역할·작업 식별자 목록
- Sol 단독 작업: `delegation_used: false`, `delegated_to: []`

동결된 Work Order 안에서만 필요한 worker를 dispatch하라.
max_delegation_depth: 1
max_parallel_workers: 2
worker_delegation: forbidden
같은 파일을 동시에 수정하지 말고, worker 결과의 head_sha, worktree_diff_sha256와 evidence를 종합하라.
현재 diff hash와 evidence hash가 같은 경우에만 동일 head_sha의 완전한 evidence를 재사용하라.
```

### planner

```text
역할: planner
mode: plan
delegation: forbidden

동결된 Work Order와 allowlist를 읽고 파일 단위 계획, 위험, 테스트 명령과 중단 조건을 직접 제출하라.
worker를 호출하거나 다른 모델로 재위임하지 말라. 설치·다운로드·GPU·Git 작업은 수행하지 말라.
```

### implementer

```text
역할: implementer
mode: implementation
delegation: forbidden

허용 파일만 직접 수정하고 테스트하라. allowlist 내부 결함은 직접 고치고 재시험한 뒤 FIXED로 보고하라.
allowlist 밖 변경, 승인 필요한 실행, 외부 상태, gate 변경은 BLOCK으로 보고하라.
REQUEST_CHANGES를 사용하거나 worker를 호출하지 말라.
```

### mechanical-worker

```text
역할: mechanical-worker
mode: mechanical
delegation: forbidden

결정론적·반복적·기계 검증 가능한 작업만 수행하라. 허용 파일 안에서만 수정·검사하고 FIXED 또는 BLOCK으로 보고하라.
설계 판단, 불명확한 결함, 범위 밖 변경이 필요하면 BLOCK으로 보고하고 worker를 호출하거나 재위임하지 말라.
```

### security-reviewer

```text
역할: security-reviewer
mode: review
delegation: forbidden

독립적으로 diff와 evidence를 검토하고 PASS / REQUEST_CHANGES / BLOCK 중 하나를 근거와 함께 제출하라.
파일을 수정하거나 worker를 호출하지 말라.
```

## Related Concepts

- [AegisLM 작업 운영 규칙](../../AGENTS.md)
- [B200 수동 검증 워크북](../operations/b200/FINETUNING_TEST_WORKBOOK.md)
- [코드 리뷰 기록](../../review/README.md)

## Citations

- [OpenAI Codex Subagents](https://developers.openai.com/codex/agent-configuration/subagents)
- [OpenAI AGENTS.md guidance](https://developers.openai.com/codex/agent-configuration/agents-md)
- [OpenAI Codex configuration reference](https://developers.openai.com/codex/config-reference)
