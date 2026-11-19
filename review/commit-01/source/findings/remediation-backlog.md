# Commit 1-A 통합 수정 백로그

## 목적

파일별 리뷰에서 발견한 문제를 실제 수정 작업으로 전환하기 위한 정본입니다.
모델과 무관한 데이터·prompt·평가 계약을 먼저 안정화하고, 이후에는 모델 adapter와
실행 config만 바꿔 같은 절대 gate를 반복 적용하는 것을 목표로 합니다.

상태는 `Open → Accepted → Fixed` 순서로 변경합니다. 보류할 경우에는
`Deferred`와 재검토 조건을 함께 기록합니다.

## 수정 순서

### Gate 1 — 평가 무결성

| ID | 위치 | 수정 방향 | 완료 조건 |
| --- | --- | --- | --- |
| SRC-CONTRACT-01 | `datasets/source.py`, `evaluation/source.py` | validator에 expected target CWE를 전달하고 출력 scope와 비교 | 다른 CWE를 출력한 fixture가 semantic FAIL이며 TP/TN으로 집계되지 않음 |
| SARD-DQ-07 | Juliet target·blind gold | generated evidence와 independent review 결과를 분리 | 보고서가 generated-gold 점수와 수동 causal-evidence 점수를 별도 표기 |
| SRC-CONTRACT-02 | source target·evaluator | structural span validity와 semantic evidence validity를 별도 metric/gate로 분리 | exact substring만 맞고 관계가 틀린 fixture가 semantic FAIL |
| SRC-AUDIT-01 | source audit input index | manifest와 materialized record ID를 각각 unique index로 검증 | 빈 ID·중복 ID·orphan row가 모두 자동 gate FAIL |
| SRC-AUDIT-02 | audit entrypoint·split contract | 각 record에 실제 입력 파일 role을 결합하고 manifest split과 대조 | train/validation/challenge swap fixture가 FAIL |

### Gate 2 — 학습 데이터 승인 무결성

| ID | 위치 | 수정 방향 | 완료 조건 |
| --- | --- | --- | --- |
| SARD-DQ-01 | Juliet manifest/materializer | semantic 오류 group을 quarantine하고 승인 manifest만 materialize | 오류 row의 training shard 유입 0 |
| SARD-DQ-02·03 | Juliet CWE registry | extractor와 validator가 동일한 fail-closed registry 사용 | 미지원 CWE가 `unsupported_cwe`로 격리됨 |
| SARD-DQ-04 | CWE-321 validator | present/not_observed별 근거 조건 분리 | 양 label fixture와 공급량 재감사 PASS |
| SARD-DQ-05 | source sanitizer | 함수 내부 conditional preprocessor 사례 quarantine | 의미가 합쳐진 branch의 승인 데이터 유입 0 |
| SARD-DQ-06 | identifier sanitizer | lexer-aware 치환 또는 literal 포함 사례 quarantine | string/char literal 변경 fixture 0 |
| SRC-CONTRACT-06 | patch evidence helper | generic diff를 candidate로만 취급하고 CWE별 의미 검증 추가 | refactoring-only patch가 evidence gold로 승인되지 않음 |
| SRC-AUDIT-05 | quota·input set gate | exact quota와 예상 materialization 집합을 검사하거나 검증된 source-v3 digest를 요구 | 초과·누락·예상 밖 row가 조용히 승인되지 않음 |
| SRC-AUDIT-06 | generic evidence gate | 고정 문구 탐지와 별도로 semantic validator 또는 provenance 기반 승인 사용 | blocklist를 바꿔 쓴 generic evidence fixture가 PASS하지 않음 |
| SRC-AUDIT-07 | prompt variant gate | label별 variant 분포와 최대 편중을 gate로 검사 | label-template 상관 fixture가 FAIL |

### Gate 3 — 계약 일관성과 기권 정책

| ID | 위치 | 수정 방향 | 완료 조건 |
| --- | --- | --- | --- |
| SRC-CONTRACT-03 | `_normalize_code_spans()` | schema·prompt와 동일하게 최대 8개로 제한 | 9개 이상 입력 fixture가 예외 없이 8개로 정규화되거나 명시적으로 거부됨 |
| SRC-CONTRACT-04 | target policy | uncertain을 계속 제외할지 고품질 supervision을 추가할지 결정 | config·문서·평가의 abstention 정책이 하나로 일치 |
| SRC-CONTRACT-05 | semantic/safety validator | 제한된 regex임을 명시하고 출력 언어 계약 또는 분류기 보강 | 지원 표현 fixture 전체 PASS, 미지원 언어 정책 명시 |
| SARD-DQ-09 | evidence location | 반복 span을 구분하는 line/offset 계약 검토 | 동일 statement 반복 fixture를 위치로 구분 |
| SARD-DQ-10 | confidence | provenance·검증 수준 기반 confidence 또는 필드 제거 | heuristic evidence에 무조건 high를 부여하지 않음 |
| SRC-AUDIT-04 | token counter | profile이 no-think 지원을 명시할 때만 실행하고 TypeError fallback 제거 | `enable_thinking=False` 미지원·내부 TypeError가 즉시 BLOCK |
| SRC-AUDIT-09 | tokenizer result validation | 실제 tokenizer identity를 검증하고 0/빈/비정상 encoding 거부 | 빈 `input_ids` fixture가 token gate PASS하지 않음 |

### Gate 4 — 운영과 구조

| ID | 위치 | 수정 방향 | 완료 조건 |
| --- | --- | --- | --- |
| SRC-BUILD-01 | tokenizer loader | model/revision allowlist와 실행 manifest pin | 미승인 remote tokenizer code가 fail-closed |
| SRC-BUILD-02 | public manifest | root alias와 상대경로만 공개 | 공개 artifact의 host 절대경로 0 |
| SRC-BUILD-03 | output lifecycle | run ID별 새 디렉터리와 overwrite 거부 | 다른 run artifact 혼입 0 |
| SRC-BUILD-04 | quota/token gate | 동일 계층의 deterministic reserve backfill | 보충 결과가 동일 seed에서 재현되고 부족 시 BLOCK |
| SRC-ARCH-01 | `datasets/source.py` | contract/prompt, target, patch heuristic, legacy bridge 책임 분리 | frozen dataset hash 경로를 보존하며 새 version에서 import 경계 분리 |
| SARD-ARCH-01·02 | Juliet builder | Juliet 전용 추출과 공통 source contract 분리 | 범용 API가 Juliet 명명·annotation 규칙에 의존하지 않음 |
| SRC-AUDIT-03 | audit artifact contract | dataset·manifest·evidence·tokenizer revision·chat template·system prompt digest 기록 | audit 결과만으로 모든 immutable 입력을 식별 가능 |
| SRC-AUDIT-08 | source audit tests | ID, split, generic evidence, assistant budget, no-think 실패 fixture 추가 | 각 audit gate에 최소 하나의 negative regression test 존재 |
| SRC-AUDIT-10 | artifact privacy | audit report를 private artifact로 분류하고 local root를 alias로 마스킹 | 공개 가능한 요약에 label·host 절대경로 0 |

## 모델 교체 전 필수 gate

새 모델의 full fine-tuning 또는 모델 간 비교 전에 최소한 다음 조건을 만족해야
합니다.

1. `SRC-CONTRACT-01·02`, `SRC-AUDIT-01·02·03·04`,
   `SARD-DQ-01·02·03·07`이 Fixed 또는 명시적 quarantine으로 닫힘
2. 동일 label-blind challenge와 private gold hash 동결
3. tokenizer/chat-template revision과 system prompt hash 기록
4. 모델별 출력이 동일 schema와 semantic validator를 통과
5. 동일 precision, recall, FPR, abstention, schema, safety, evidence gate 적용

이후 모델 교체는 다음 인터페이스에만 영향을 주는 것이 목표입니다.

```text
model profile
├─ model ID + immutable revision
├─ tokenizer/chat template
├─ LoRA/QLoRA와 distributed profile
├─ serving adapter
└─ checkpoint save/reload contract
```

dataset builder, challenge, gold, evaluator를 모델마다 복사하거나 별도로 수정하지
않습니다.
