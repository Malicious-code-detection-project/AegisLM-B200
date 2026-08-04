# `sard_juliet.py` 리뷰

## 파일

[`aegislm/datasets/sard_juliet.py`](../../../aegislm/datasets/sard_juliet.py)

## 역할

Juliet C/C++ ZIP에서 함수 pair를 추출하고 model-safe code, private label,
code-visible evidence, split, tokenizer gate, materialized dataset을 만드는
핵심 builder입니다. 현재 약 1,800줄 안에 추출·정제·근거 생성·검증·split·
materialization·수동 검토 요약이 함께 들어 있습니다.

## 전체 구성

### 1. 후보와 pair 추출

- ZIP을 bulk extract하지 않고 member를 읽습니다.
- 단일 파일 C/C++ variant 01–10을 선택합니다.
- Juliet 함수명 규칙으로 bad/good 함수를 찾습니다.
- 취약 함수와 수정 함수를 하나의 group으로 유지합니다.
- 완전한 pair를 만들 수 없는 후보는 quarantine합니다.

정규식과 brace state machine은 통제된 Juliet 코드용입니다. 일반 C++
parser가 아니며 macro, raw string, template 등은 완전히 지원하지 않습니다.

### 2. 함수와 evidence target 생성

- `POTENTIAL FLAW`와 `FIX` 주석을 private supervision으로 읽습니다.
- 주석 다음 statement와 입력·변환·loop 관련 문장을 수집합니다.
- CWE별 정규식으로 allocation, capacity, sink, guard 등을 보강합니다.
- exact substring으로 근거가 실제 sanitized code에 있는지 확인합니다.
- 반복돼 위치가 모호한 exact span은 레코드에서 제외합니다.

이 과정은 독립적인 취약점 탐지가 아닙니다. 이미 알고 있는 CWE와 label을
설명하는 target을 생성합니다.

### 3. 지원하는 CWE별 휴리스틱

명시적 근거 수집 규칙은 CWE-121, 122, 124, 126, 176, 321, 457, 590,
606, 690, 761을 다룹니다. 그러나 검증기는 이 중 일부만 지원하며 미지원
CWE를 fail-closed하지 않습니다.

### 4. 주변 setup 보충

선택된 sink의 identifier를 기준으로 앞쪽 statement를 역방향 탐색합니다.
allocation, 배열 선언, 산술 대입, 입력 연산에 점수를 부여하고 최대 evidence
수에 맞게 추가합니다. 이는 identifier 문자열 기반 backward-slice
휴리스틱이지 parser 기반 dataflow는 아닙니다.

### 5. 정답 힌트 정리

- 원래 함수명은 `sample_function`으로 바꿉니다.
- good/bad가 들어간 symbol은 `candidate_symbol_N`으로 바꿉니다.
- 주석은 줄 수를 보존하며 제거합니다.
- 주석 설명의 bad/good 표현은 risk/defensive 표현으로 치환해 assistant
  target의 relationship에 사용합니다.

명시적인 label token은 제거되지만, Juliet annotation이 만든 설명 패턴은
assistant target에 남습니다.

### 6. split·token·품질 gate

- 같은 pair가 서로 다른 split에 들어가지 않도록 group-first split합니다.
- actual Qwen chat template로 전체 학습 token을 계산합니다.
- exact code/target duplicate와 model-visible leakage를 검사합니다.
- semantic basis 오류가 있으면 전체 automated quality gate를 실패시킵니다.
- 자동 gate를 통과해도 `approved_for_training`은 수동 검토 전까지 false입니다.

## 잘된 점

- 원본 ZIP과 함수 pair의 provenance를 보존합니다.
- label과 dataset metadata를 prompt에서 분리합니다.
- group leakage를 방지합니다.
- evidence가 원본 코드 substring인지 확인합니다.
- hash seed에 영향받지 않도록 span 정렬 tie-breaker가 있습니다.
- actual tokenizer, duplicate, leakage, 수동 review gate를 결합합니다.
- 근거 없이 수량을 채우는 generic fallback을 사용하지 않습니다.

## 핵심 발견 사항

| ID | 우선순위 | 상태 | 내용 |
| --- | --- | --- | --- |
| SARD-DQ-01 | P1 | Open | semantic 오류 레코드도 manifest에서 `eligible`로 남을 수 있으며 전체 gate만 실패합니다. |
| SARD-DQ-02 | P1 | Open | 미지원 CWE가 빈 오류 목록으로 통과하는 fail-open 구조입니다. |
| SARD-DQ-03 | P1 | Open | CWE-124·126·176은 수집 규칙은 있지만 CWE 전용 semantic validator가 없습니다. |
| SARD-DQ-04 | P1 | Open | CWE-321 validator가 label을 구분하지 않고 runtime key input을 항상 요구합니다. |
| SARD-DQ-05 | P1 | Open | 모든 preprocessor directive를 제거해 조건부 branch 의미가 바뀔 수 있습니다. |
| SARD-DQ-06 | P1 | Open | identifier regex 치환이 string/char literal 내부까지 바꿀 수 있습니다. |
| SARD-DQ-07 | P1 | Open | evidence gold와 평가지표가 같은 휴리스틱 builder에 의존합니다. |
| SARD-DQ-08 | P2 | Open | CWE validator는 동일 변수·순서·경로 관계보다 문자열 요소 존재를 주로 검사합니다. |
| SARD-DQ-09 | P2 | Open | exact substring 근거는 반복 문장을 구분하지 못해 유효 레코드도 폐기합니다. |
| SARD-DQ-10 | P2 | Open | 모든 finding confidence가 `high`로 고정됩니다. |
| SARD-ARCH-01 | P2 | Open | 하나의 파일이 너무 많은 책임을 가지고 있습니다. |
| SARD-ARCH-02 | P2 | Open | Juliet 전용 함수가 범용 이름을 사용해 재사용 가능한 분석기로 오인될 수 있습니다. |
| SARD-ARCH-03 | P3 | Open | 공개 함수와 복잡한 휴리스틱의 역할 중심 주석이 부족합니다. |

세부 설명은 [findings](findings/README.md)에 분류해 기록합니다.

## 연구 결과 해석

- decision 성능은 Juliet bad/good label 판단 성능으로 해석할 수 있습니다.
- evidence 성능은 먼저 generated evidence gold와의 일치도로 해석해야 합니다.
- 고정 100건 수동 검토는 위험을 줄이지만 전체 independent expert gold를
  대신하지는 않습니다.
- 실세계 코드, 임의 언어, decompiled code 일반화 주장은 별도 blind
  benchmark가 필요합니다.

## 판정

`수정 후 유지`입니다. 학습 데이터 구축 기능은 필요하고 여러 안전 gate도
갖췄지만, 새 dataset을 재생성하기 전에 P1 항목을 수정하거나 최소한 해당
범주를 quarantine하고 독립 수동 감사를 다시 수행해야 합니다.
