# 데이터·연구 품질 발견 사항

## P1 — 새 학습 전 처리 필요

### SRC-CONTRACT-01: 입력·출력 target CWE 동일성 검사 누락

output schema는 `scope.target_cwe`의 형식만 검사합니다. validator와 source
evaluator가 입력 record의 `task.target_cwe`를 expected value로 전달하지 않으므로,
모델이 다른 CWE를 출력해도 assessment가 맞으면 정답으로 집계될 수 있습니다.

제안:

- output semantic validator에 `expected_target_cwe`를 전달합니다.
- 불일치 출력은 schema 이후 semantic FAIL과 abstention으로 처리합니다.
- 다른 CWE를 출력한 positive/negative fixture를 추가합니다.

### SRC-CONTRACT-02: exact span과 semantic evidence의 혼동

현재 exact substring 검사는 입력에 없는 코드를 근거로 만드는 환각을 막지만,
해당 span이 target CWE를 인과적으로 설명하는지는 검증하지 않습니다.
`evidence_linked`라는 이름도 semantic linkage로 오해될 수 있습니다.

제안:

- `structurally_grounded`와 `semantically_validated`를 분리합니다.
- semantic validation을 통과하지 않은 evidence는 최종 evidence gate의 PASS로
  계산하지 않습니다.

### SRC-CONTRACT-06: generic patch diff의 causal evidence 승격

`derive_patch_findings()`는 before/fixed diff의 변경 줄을 반환하지만 target CWE와
변경 줄의 관계를 검증하지 않습니다. refactoring-only 변경도 보안 evidence로
승격될 수 있습니다.

제안:

- diff 결과는 candidate evidence로만 취급합니다.
- target CWE별 validator 또는 독립 수동 검토를 통과한 span만 gold로 승인합니다.

### SARD-DQ-01: semantic 오류 레코드의 disposition 불일치

semantic basis 오류는 전체 gate를 실패시키지만 해당 레코드는 materialized
output과 `eligible` manifest에 남을 수 있습니다. 공식 승인 절차를 따르면
학습은 차단되지만, JSONL만 직접 사용하면 우회됩니다.

제안:

- 오류 group을 즉시 quarantine합니다.
- manifest에 record별 semantic error 목록을 기록합니다.
- 승인된 manifest 없이는 materialization 또는 training config 생성을 막습니다.

### SARD-DQ-02·03: CWE 지원 범위가 fail-open

근거 수집 규칙과 semantic validator의 지원 범위가 다릅니다. CWE-124,
126, 176은 별도 validator가 없으며 등록되지 않은 CWE도 빈 오류 목록으로
통과할 수 있습니다.

제안:

- `SUPPORTED_JULIET_CWES`를 하나의 정본으로 선언합니다.
- 수집기와 validator가 동일 registry를 사용하게 합니다.
- 미지원 CWE는 `unsupported_cwe`로 quarantine합니다.

### SARD-DQ-04: CWE-321 label 비대칭 미반영

현재 validator는 present/not_observed 모두 runtime key input을 요구합니다.
하드코딩된 key가 핵심인 present 사례를 잘못 제외할 가능성이 있습니다.

제안:

- present: code-visible key literal과 crypto use 관계를 요구합니다.
- not_observed: runtime input과 crypto use 관계를 요구합니다.
- 기존 build에서 CWE-321 pair 공급량과 class 비율을 다시 감사합니다.

### SARD-DQ-05: preprocessor 제거에 의한 의미 변형

모든 `#` directive를 제거하면 조건부 컴파일의 양쪽 branch가 동시에 남을 수
있습니다. 이는 실제로 존재하지 않는 실행 경로 또는 문법 오류를 만들 수 있습니다.

제안:

- 함수 내부 conditional directive가 있으면 우선 quarantine합니다.
- 향후 compiler profile이 고정됐을 때만 통제된 preprocessing을 검토합니다.

### SARD-DQ-06: literal까지 변경하는 identifier 치환

정규식 치환이 코드 전체에 적용되어 string/char literal 내부 token도 바뀔 수
있습니다. lexer-aware 치환이 어렵다면 해당 사례를 quarantine해야 합니다.

### SARD-DQ-07: generated gold와 평가의 공통 의존성

decision label은 Juliet bad/good 구조에서 오지만 evidence span과 설명은 이
builder가 생성합니다. 같은 builder가 train과 blind-test gold를 만들면 evidence
점수에는 생성 규칙을 재현하는 능력이 포함됩니다.

따라서 현재 evidence 결과는 다음 순서로 해석합니다.

1. generated evidence contract 재현 성능
2. 수동 검토 표본에서의 causal evidence 품질
3. 별도 독립 gold를 확보한 뒤 실제 보안 근거 성능

## P2 — 정확도와 공급량 개선

### SRC-CONTRACT-03: code span 최대 개수 불일치

schema와 system prompt는 item당 최대 8개를 허용하지만 `_normalize_code_spans()`는
최대 10개를 반환합니다. 9~10개 span은 정규화 뒤 schema error를 일으킵니다.

### SRC-CONTRACT-04: uncertain supervision 정책 부재

output contract와 평가기는 `uncertain`을 허용하지만 target builder는 uncertain
label을 전부 제외합니다. 기권 능력을 zero-shot으로 기대할지, 검토된 uncertain
표본을 학습할지 명시적인 결정이 필요합니다.

### SRC-CONTRACT-05: 전역 안전 주장 탐지 범위 제한

현재 검사는 일부 영어 표현의 정규식에 의존합니다. 동의어, 우회 표현, 다른 언어
출력에는 완전하지 않습니다. 출력 언어를 고정하거나 별도 semantic safety 평가가
필요합니다.

### SARD-DQ-08: 요소 존재 검사와 causal relation의 차이

현재 validator는 allocation, copy, guard 등이 spans에 존재하는지를 주로
확인합니다. 같은 destination/source에 연결되는지, 올바른 순서와 실행 경로에
있는지는 완전히 검증하지 않습니다.

### SARD-DQ-09: exact substring 위치 모호성

동일한 statement가 함수에 두 번 있으면 line 위치가 없기 때문에 레코드를
폐기합니다. 안전한 보수 정책이지만 공급량을 줄입니다. 향후 line/column 또는
character offset 기반 contract가 필요합니다.

### SARD-DQ-10: 고정 `high` confidence

정규식과 dataset annotation으로 만든 evidence에 항상 `high`를 지정하면
confidence 의미가 사라집니다. confidence를 제거하거나 evidence provenance와
검증 수준에서 결정해야 합니다.

## 완료 조건

- 모든 P1 항목이 Fixed 또는 명시적 Deferred+quarantine으로 결정됨
- 고정 seed dataset 재생성 hash와 quota 보고서 확인
- 변경된 CWE별 positive/negative 최소 fixture 추가
- 독립 수동 검토 queue 재생성 및 허용 오류율 통과
