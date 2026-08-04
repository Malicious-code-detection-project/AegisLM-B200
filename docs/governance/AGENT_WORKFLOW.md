---
type: Setup Guide
title: AegisLM 다중 모델 수동 작업 운영 가이드
description: 사용자 중심으로 Sol, Terra, implementation agent의 권한과 Work Order, 승인, 구현 증거, 독립 검토 절차를 관리하는 기준
tags: [aegislm, agents, workflow, review]
timestamp: 2026-08-04
status: active
---

# AegisLM 다중 모델 수동 작업 운영 가이드

## 1. 목적

이 문서는 사용자가 각 모델에게 직접 작업을 지시할 때 요구사항, 구현 범위,
검토 기준이 작업 도중 바뀌지 않도록 역할과 인수인계 형식을 고정한다.

모델 이름보다 역할과 권한을 우선한다. 현재 사용할 수 있는 모델이 바뀌어도
`planner`, `implementation_agent`, `reviewer`의 계약은 유지한다.

이 프로젝트는 에이전트가 다른 에이전트를 자동 호출하는 구조를 사용하지
않는다. 사용자가 Sol, Terra 또는 Luna 작업을 직접 열고 각 모델에 역할과
Work Order를 전달한다.

## 2. 권한 원칙

사용자는 Owner이자 최종 orchestrator다. 메인 에이전트는 사용자의 목적을
Work Order로 구조화하고 각 단계의 증거를 종합하지만, 중요한 변경의 최종
승인을 대신하지 않는다.

```text
사용자: 목적과 gate를 승인한다.
메인: Work Order를 작성하고 결과를 종합한다.
Sol: 요구사항과 위험을 독립 검토한다.
Terra: 저장소를 조사해 파일 계획으로 변환한다.
implementation agent: 승인된 파일만 구현한다.
사용자가 직접 연 별도 Terra 작업: diff와 테스트 증거를 독립 검토한다.
사용자가 직접 연 별도 Sol 작업: 고위험 결과의 채택 가능성을 독립 검토한다.
사용자: 다음 실행과 최종 채택을 승인한다.
```

검토자는 gate를 설계하거나 수정하지 않는다. gate가 부적절하거나 충돌하면
현재 작업을 `BLOCK`하고 새 Work Order가 필요한 이유를 보고한다.

### 2.1 서브에이전트와 재위임 금지

사용자가 특정 모델에 작업을 배정한 이유는 그 모델의 역량과 책임을 선택했기
때문이다. 배정받은 모델은 작업을 직접 수행해야 하며 다음 행동을 금지한다.

- 서브에이전트 또는 하위 작업자 생성
- `spawn_agent`와 이에 준하는 자동 위임 도구 사용
- 다른 모델이나 작업으로 자동 handoff
- 사용자에게 알리지 않은 역할 교체
- 구현·조사·검토의 전부 또는 일부를 제3의 에이전트에게 대리 수행시킴

다른 모델의 도움이 필요하면 현재 작업을 `BLOCK`하고 필요한 역할, 이유,
입력과 범위를 사용자에게 보고한다. 사용자가 직접 새 작업을 열어 배정해야
하며, 현재 에이전트가 대신 호출해서는 안 된다.

개별 Work Order는 이 금지를 해제할 수 없다. 향후 서브에이전트를 도입하려면
사용자가 이 운영 규칙 자체의 개정을 별도로 명시하고 승인해야 한다. 일반적인
구현 승인, 파일 수정 승인 또는 “계속 진행”은 재위임 승인으로 해석하지 않는다.

## 3. 역할별 계약

### 3.1 사용자 / Owner

사용자가 직접 승인해야 하는 항목:

- 목적, 비목표, 불변 조건과 `PASS/BLOCK` gate
- 정확한 모델과 revision, 데이터·평가 artifact
- 신규·수정·삭제 허용 파일
- dependency 설치와 환경 변경
- 모델·데이터 다운로드
- GPU 학습과 외부 서비스 실행
- Git stage, commit, push와 PR
- gate 변경과 새 Work Order 버전
- 결과 채택과 다음 단계

### 3.2 메인 에이전트

책임:

- 사용자 요청을 Work Order 초안으로 변환
- 불확실한 입력과 승인 필요 항목 분리
- 동결된 gate와 파일 범위를 각 담당자에게 동일하게 전달
- 구현·테스트·검토 증거를 종합
- 최종 상태와 다음 승인 지점을 사용자에게 보고

금지:

- 사용자 승인 없이 gate 완화
- 검토자의 권고를 자동으로 요구사항에 편입
- 승인 범위 밖의 구현, 설치, GPU 또는 Git 작업
- 서브에이전트 생성, 자동 handoff 또는 다른 모델로의 재위임

### 3.3 Sol reviewer

Sol은 독립 감사자다. 요구사항과 고위험 결과를 읽기 전용으로 검토한다.

검토 항목:

- 목적과 gate의 일치
- 모순, 누락, 모호성
- 보안·개인정보·데이터 무결성 위험
- 승인되지 않은 범위 확대 가능성
- 판정에 필요한 증거의 충분성
- 되돌리기 어렵거나 운영에 영향을 주는 변경

Sol은 검토를 직접 수행한다. 파일을 수정하거나 gate·구현 계획을 다시
작성하거나 다른 에이전트에게 검토를 넘기지 않는다. 결과는 `PASS`,
`REQUEST_CHANGES`, `BLOCK` 중 하나와 근거로 제한한다.

권장 reasoning effort는 일반 독립 검토 `high`, 되돌리기 어려운 고위험 변경
`xhigh`다.

### 3.4 Terra planner

Terra planner는 Work Order와 Sol 검토를 바탕으로 실제 저장소를 읽고 파일
단위 계획을 만든다. 계획 단계는 읽기 전용이다.

필수 산출물:

1. 재사용 가능한 기존 코드
2. 신규 파일과 파일별 목적
3. 수정 파일과 수정 이유
4. 수정 금지 파일
5. 최소 public interface와 데이터 흐름
6. 구현 순서와 단계별 허용 파일 집합
7. CPU 테스트와 정확한 실행 명령
8. GPU·외부 환경에서만 확인 가능한 항목
9. dependency 변경과 별도 승인 항목
10. 위험, 중단 조건과 확인 불가능한 가정

Terra planner는 저장소 조사를 직접 수행한다. 구현, 설치, 다운로드, GPU
실행, Git 변경과 다른 에이전트로의 재위임을 하지 않는다.

권장 reasoning effort는 단일 모듈 `medium`, 다중 파일·학습·인프라 계획
`high`다.

### 3.5 implementation agent

`implementation agent`는 특정 모델이 아니라 사용자가 직접 연 모델 작업에
부여하는 승인된 구현 역할이다. 사용자가 Luna에게 배정하면 Luna가 직접
수행하고 Terra에게 배정하면 Terra가 직접 수행한다. 배정받은 모델은 구현의
일부라도 서브에이전트나 다른 모델에게 넘기지 않는다.

책임:

- 승인된 파일만 생성·수정
- 지정된 테스트 작성과 반복 실행
- 기존 사용자 변경 보존
- 명령·종료 코드·핵심 출력과 미실행 항목 제출
- 작업 전체를 직접 수행했으며 재위임하지 않았다는 증거 제출

다음 상황에서는 수정하지 않고 `BLOCK`한다.

- 승인 파일 밖의 변경이 필요함
- gate 또는 schema 의미 변경이 필요함
- dependency 설치, 다운로드, GPU·외부 서비스 실행이 필요함
- 삭제·덮어쓰기 또는 Git 변경이 필요함
- 기존 사용자 변경과 충돌함
- 다른 모델이나 에이전트의 작업이 필요함

Luna의 권장 reasoning effort는 기계적 변경 `low`, 일반 구현 `medium`,
재현이 어려운 버그 `high`다.

### 3.6 Terra reviewer

Terra reviewer는 사용자가 직접 연 별도 Terra 작업에서 수행한다. 해당
Terra는 검토를 다시 위임하지 않고 구현 설명을 그대로 신뢰하지 않으며 실제
diff와 증거를 직접 읽는다.

검토 항목:

- 승인 파일 밖의 변경
- Work Order 불변 조건과 gate 준수
- 계획과 구현의 일치
- 테스트 명령, 종료 코드와 핵심 출력
- 기존 기능과 사용자 변경의 회귀
- 실패·skip·미실행 항목의 누락
- 추가 Sol 검토가 필요한 고위험 변경

Terra reviewer도 파일을 수정하지 않으며 verdict와 재작업 항목만 제출한다.

## 4. 표준 실행 순서

```text
1. 메인: Work Order 초안 작성
2. 사용자: Work Order와 gate 동결
3. 사용자가 직접 연 Sol 작업: 요구사항·안전성 독립 검토
4. 사용자가 직접 연 Terra 작업: 읽기 전용 파일 계획
5. 사용자: 정확한 파일 범위 승인
6. 사용자가 직접 지정한 implementation agent: 승인 파일만 순차 구현·테스트
7. 사용자가 직접 연 별도 Terra 작업: diff·증거 검토
8. 사용자가 직접 연 별도 Sol 작업: 고위험 변경이면 최종 검토
9. 메인: 증거 종합과 다음 gate 보고
10. 사용자: 채택, 재작업, 다음 실행 또는 중단 결정
```

동일 파일을 여러 에이전트가 병렬 수정하지 않는다. 독립적으로 분리할 수 있는
읽기 전용 조사나 서로 겹치지 않는 파일만 병렬화할 수 있다.
병렬화가 가능하더라도 각 작업은 사용자가 직접 생성·배정하며, 모델이
서브에이전트를 만들어 병렬화하지 않는다.

## 5. Work Order 계약

작업별 Work Order는 다음 항목을 포함한다.

```yaml
work_order_id: <task>-v1
status: draft | frozen | superseded
owner: <user>
delegation: forbidden

objective: <검증 가능한 목적>
out_of_scope: []

immutable_inputs:
  model_id: null
  model_revision: null
  dataset_manifest: null
  dataset_sha256: null
  evaluation_artifact_sha256: null
  schema_version: null

allowed_files: []
forbidden_files: []

gates:
  pass: []
  block: []

approvals_required:
  dependency_install: true
  model_or_data_download: true
  gpu_execution: true
  git_stage_commit_push: true

required_evidence:
  - commands
  - exit_codes
  - key_output
  - changed_files
  - failed_skipped_not_executed
  - known_limitations
  - delegation_used
```

적용되지 않는 불변값은 `null` 대신 명시적인 `not_applicable`로 확정한다.
실험에 필요한 값이 `null`, `TODO`, `REQUIRED`, `CHANGEME` 상태이면 동결하지
않는다.

동결 뒤 기준 변경이 필요하면 현재 작업을 `BLOCK`하고 다음 버전의 Work
Order를 작성해 사용자 재승인을 받는다. 기존 Work Order는 수정하거나
덮어쓰지 않는다.

`delegation`의 기본값은 `forbidden`이다. 이 필드가 누락됐거나 placeholder인
Work Order도 동결하지 않는다.

## 6. 구현 증거 계약

`PASS`는 테스트 통과 한 줄로 인정하지 않는다.

```yaml
work_order_id: <task>-v1
verdict: PASS | REQUEST_CHANGES | BLOCK
delegation_used: false
delegated_to: []

changed_files: []
unapproved_changes: []

commands:
  - command: <실행한 명령>
    exit_code: <종료 코드>
    key_output: <판정에 필요한 핵심 출력>

tests:
  passed: []
  failed: []
  skipped: []

gates: {}
not_executed: []
known_limitations: []
approval_required_next: []
```

다음 중 하나라도 해당하면 구현 단계 `PASS`가 아니다.

- 승인되지 않은 파일 변경
- 명령이나 종료 코드 누락
- 실패·skip·미실행 검증 은폐
- gate 일부만 통과
- 필요한 사용자 승인을 건너뜀
- 서브에이전트, 자동 handoff 또는 재위임 사용

## 7. Verdict 의미

- `PASS`: 승인 범위와 모든 현재 gate를 증거와 함께 충족함
- `REQUEST_CHANGES`: 범위 안에서 명확한 재작업으로 해결 가능함
- `BLOCK`: gate·범위·권한·외부 입력을 변경하거나 새 승인을 받아야 함

검토자는 `REQUEST_CHANGES`에서 수정할 파일과 증거를 지정할 수 있지만 직접
수정하지 않는다. `BLOCK`을 내린 경우 메인과 사용자가 새 Work Order가
필요한지 결정한다.

## 8. 작업 기록 구조

큰 작업은 다음 구조로 단계별 근거를 남긴다.

```text
review/workflows/<task>/
├── 00-work-order-v1.md
├── 01-sol-requirements-review.md
├── 02-terra-file-plan.md
├── 03-user-scope-approval.md
├── 04-implementation-evidence.md
├── 05-terra-diff-review.md
└── 06-sol-risk-review.md
```

각 파일에는 raw secret, token, private path, raw 보안 payload를 넣지 않는다.
필요한 외부 artifact는 승인된 식별자, hash와 비공개 저장 위치의 별도 참조로
기록한다.

## 9. 복사 가능한 역할 지시문

### Sol 요구사항 검토

```text
역할: Independent Auditor
작업 모드: READ ONLY

사용자가 동결한 Work Order를 수정하지 말고 목적, gate, 불변 조건의
모순·누락·보안 위험과 필요한 증거를 독립 검토하세요.

파일 수정, gate 변경, 구현 계획, 설치, 다운로드, GPU, Git 작업은
금지합니다. 서브에이전트 생성, 자동 handoff와 재위임도 금지하며 검토를
직접 수행하세요. 결과는 PASS / REQUEST_CHANGES / BLOCK, gate별 근거,
누락 증거, 잔여 위험으로 제출하세요. gate 변경이 필요하면 BLOCK하고
새 Work Order가 필요한 이유만 설명하세요.
```

### Terra 파일 계획

```text
역할: Technical Planner
작업 모드: READ ONLY

동결된 Work Order와 Sol 검토를 기준으로 저장소를 조사하세요. 코드를
수정하지 말고 재사용 코드, 신규/수정/보존 파일, 최소 interface, 데이터
흐름, 단계별 허용 파일, 테스트 명령, dependency, 위험과 중단 조건을
제출하세요. 구현, 설치, 다운로드, GPU, Git 작업은 금지합니다.
서브에이전트나 다른 모델에게 조사를 넘기지 말고 직접 수행하세요.
```

### Implementation agent

```text
역할: Implementation Agent

동결된 Work Order와 사용자가 승인한 파일만 수정하세요. 범위 밖 변경,
gate·schema 변경, 설치, 다운로드, GPU, 삭제·덮어쓰기 또는 Git 작업이
필요하면 수정하지 말고 BLOCK하세요. 변경 파일, 실행 명령, 종료 코드,
핵심 출력, 통과·실패·skip·미실행 항목과 다음 승인 필요 사항을 제출하세요.
서브에이전트 생성, 자동 handoff와 재위임은 금지합니다. 다른 모델이
필요하면 직접 호출하지 말고 BLOCK 후 사용자에게 배정을 요청하세요.
```

### Terra 구현 검토

```text
역할: Independent Implementation Reviewer
작업 모드: READ ONLY

새 컨텍스트에서 실제 diff와 테스트 증거를 직접 확인하세요. 승인 범위,
Work Order 불변 조건, 계획 일치, 종료 코드, 회귀, 실패·skip·미실행 누락을
검토하세요. 파일을 수정하거나 gate를 바꾸지 말고 PASS /
REQUEST_CHANGES / BLOCK과 정확한 근거만 제출하세요.
서브에이전트나 다른 모델에게 검토를 넘기지 말고 직접 수행하세요.
```

## 10. Mistral F5-X 적용 경계

첫 적용은 구현이 아니라 Mistral F5-X의 읽기 전용 파일 계획과 G0 기반
구현이다.

```text
Work Order와 gate 동결
-> 사용자가 직접 연 Sol 작업의 요구사항 검토
-> 사용자가 직접 연 Terra 작업의 G0 파일 계획
-> 사용자 파일 승인
-> 사용자가 직접 지정한 implementation agent가 manifest validator와 renderer만 구현
-> 사용자가 직접 연 별도 Terra 작업의 diff·CPU 테스트 검토
-> 사용자가 직접 연 별도 Sol 작업의 immutable identity·보안 경계 검토
-> 사용자 G1 1-step GPU 실행 승인
```

G0 검토 전에는 dependency 설치, 모델 다운로드와 GPU 실행을 하지 않는다.
100-step decision gate를 통과하기 전에는 binary dataset, evidence adapter,
merge와 full epoch를 작업 범위에 포함하지 않는다.

## Related Concepts

- [AegisLM 협업 운영 규칙](../../AGENTS.md)
- [Phase F 데이터와 binary 실험 계획](../experiments/plans/PHASE_F_DATASET_AND_BINARY_EXPERIMENT_PLAN.md)
- [B200 수동 검증 워크북](../operations/b200/FINETUNING_TEST_WORKBOOK.md)
- [코드 리뷰 기록](../../review/README.md)

## Citations

- [OpenAI Model Guidance](https://developers.openai.com/api/docs/guides/latest-model)
- [GPT-5.6 model tiers](https://openai.com/index/gpt-5-6/)
