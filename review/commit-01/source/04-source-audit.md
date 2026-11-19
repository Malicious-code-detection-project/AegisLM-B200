# `source_audit.py` 리뷰

## 파일

[`aegislm/datasets/source_audit.py`](../../../aegislm/datasets/source_audit.py)

## 역할

이 파일은 source target을 새로 분석하는 코드가 아니라, 이미 생성된 record,
private manifest, evidence 후보가 학습 준비 기준을 통과하는지 검사하는 자동
품질 gate입니다.

```text
materialized records + private manifest + evidence candidates
→ canonical source record
→ label-blind prompt + supervised target
→ 실제 chat template tokenization
→ schema/leakage/evidence/duplicate/quota gate
→ automated PASS
→ 수동 100건 검토 필요
```

## 입력과 출력

입력:

- train, validation, challenge 등에서 읽은 materialized records
- record ID별 private manifest
- 실제 tokenizer
- 선택적인 record ID별 grounded findings
- split·label별 요구 수량

출력:

- record별 eligible/excluded 사유
- split·label별 적격 수량
- schema, leakage, evidence, duplicate, token 지표
- 자동 gate 결과
- 수동 검토 필요 상태

`overall_pass`는 자동 gate가 모두 통과해도 항상 `false`입니다. 자동 검사가
학습을 직접 승인하지 않고 수동 100건 검토로 넘기는 fail-closed 동작입니다.

## 주요 처리

### 1. record와 manifest 결합

materialized record의 ID로 manifest row를 찾습니다. manifest가 없으면 해당
record를 제외합니다. 이후 private manifest의 label과 split을 canonical record에
넣고, prompt formatter는 CWE와 source code만 모델에 공개합니다.

### 2. target과 prompt 감사

- 근거가 부족한 target 제외
- prompt의 record ID·dataset·통제 key 노출 검사
- target JSON의 exact SHA-256과 중복률 계산
- known generic evidence 문구 검사
- positive evidence linkage 계산

### 3. 실제 token 계산

system+user+assistant 전체를 `apply_chat_template()`로 렌더링해 token을 계산합니다.
명시적인 truncation은 사용하지 않으며 기본 cutoff는 2,048입니다. assistant JSON
본문은 별도로 768-token 제한을 검사합니다.

### 4. 자동 gate와 수동 gate 분리

자동 gate는 schema, leakage, positive linkage, generic evidence, duplicate,
전역 안전 주장, token budget과 quota를 검사합니다. 모두 통과하면 상태를
`manual_review_required`로 설정하지만 학습 승인은 하지 않습니다.

## 잘된 점

- 근거 또는 quota 부족을 임의 데이터로 채우지 않습니다.
- 실제 tokenizer와 전체 chat sequence를 사용합니다.
- cutoff 초과 record를 truncation하지 않고 제외합니다.
- target hash와 record별 제외 사유를 남깁니다.
- 자동 PASS와 최종 학습 승인을 분리합니다.
- schema, leakage, duplicate, evidence, token 문제를 한 보고서에서 확인할 수
  있습니다.

## 발견 사항

| ID | 우선순위 | 상태 | 내용 |
| --- | --- | --- | --- |
| SRC-AUDIT-01 | P1 | Open | manifest ID 중복은 dictionary 생성 중 조용히 덮어쓰고 materialized record ID 중복은 반복 집계되어 label 또는 quota를 왜곡할 수 있습니다. |
| SRC-AUDIT-02 | P1 | Open | entrypoint가 train·validation·challenge를 한 list로 합쳐 파일 출처를 잃고 manifest의 split/materialization 값을 신뢰합니다. 파일과 split이 바뀌어도 이 audit 단독으로 탐지하지 못합니다. |
| SRC-AUDIT-03 | P1 | Open | audit 결과가 dataset, manifest, evidence, tokenizer revision, chat template, system prompt hash와 결합되지 않아 같은 결과의 재현 입력을 증명할 수 없습니다. |
| SRC-AUDIT-04 | P1 | Open | `enable_thinking=False`가 TypeError를 내면 옵션 없이 재시도해 no-think 계약이 조용히 해제될 수 있습니다. |
| SRC-AUDIT-05 | P2 | Open | quota는 exact count가 아니라 `>=`만 검사하고 orphan manifest row나 예상 밖 materialization을 별도 실패시키지 않습니다. 후속 source-v3가 일부 보완하지만 audit v1은 독립적으로 완전하지 않습니다. |
| SRC-AUDIT-06 | P2 | Open | generic evidence 검사는 고정 문구 blocklist라서 같은 의미의 다른 표현을 탐지하지 못합니다. |
| SRC-AUDIT-07 | P2 | Open | prompt variant별 label 수를 보고만 하고 label 상관관계나 최대 편중 비율을 gate로 판정하지 않습니다. |
| SRC-AUDIT-08 | P2 | Open | audit 직접 테스트가 근거 부족과 cutoff 초과 중심이며 duplicate ID, split mismatch, generic evidence, assistant budget, no-think fallback 회귀 테스트가 없습니다. |
| SRC-AUDIT-09 | P2 | Open | `tokenizer_loaded`가 항상 true이고 빈 token 결과도 길이 0으로 처리되어 잘못된 tokenizer 응답을 거부하지 않습니다. |
| SRC-AUDIT-10 | P2 | Open | record label과 tokenizer local path가 포함될 수 있으므로 audit JSON의 private/public 분류와 경로 마스킹이 필요합니다. |

세부 수정 순서와 완료 조건은
[통합 수정 백로그](findings/remediation-backlog.md)에 기록합니다.

## 후속 구현과의 관계

후속 `source_v3.py`는 duplicate ID, record-set 일치, group/content split overlap,
challenge/gold ID와 exact quota를 추가로 검사합니다. 따라서 현재 실행 결과가
전부 무방비한 것은 아닙니다. 하지만 모델 독립 공통 audit로 재사용하려면 다음 중
하나가 필요합니다.

1. 이 audit 자체가 입력 집합·split·hash를 완전히 검사하거나
2. 검증된 upstream manifest의 schema version과 digest를 필수 입력으로 요구

현재처럼 두 파일의 검사를 실행 순서 관습으로만 결합하면 일부 단계만 직접
실행했을 때 gate를 우회할 수 있습니다.

## 모델 교체 시 유지할 계약

- 동일한 record/challenge/gold hash
- 동일한 공개 prompt 내용
- 동일한 output schema와 semantic gate
- 동일한 절대평가 threshold
- tokenizer와 chat template만 model profile에서 교체
- model profile별 렌더링 결과와 system prompt hash 기록

## 판정

`수정 후 유지`입니다. 자동 PASS가 최종 승인이 아니라는 설계는 유지합니다.
다만 다음 모델 학습 전에 `SRC-AUDIT-01`부터 `04`까지를 수정하거나, 동일 검사를
수행하는 upstream/downstream artifact의 digest를 audit 결과에 강제로 결합해야
합니다.

## 문서화 리팩터링 기록

2026-09-04에 동작 변경 없는 1차 문서화 리팩터링을 적용했습니다.

- module docstring에 audit 입력, 처리 순서, 비승인 정책 추가
- `audit_source_targets()`에 입력·출력·불변 조건과 private 경계 추가
- no-truncation, eligible 집계와 `overall_pass=false`의 의도 설명
- token counter의 no-think fallback 한계와 private leakage 검사 범위 설명
- private helper에 반환 의미를 설명하는 짧은 docstring 추가

docstring을 제거한 AST를 변경 전 `HEAD`와 비교해 실행문이 동일함을 확인했고
`py_compile`과 `git diff --check`를 통과했습니다. 이번 작업은 설명 개선만
수행했으므로 `SRC-AUDIT-01`부터 `10`은 계속 `Open`입니다.
