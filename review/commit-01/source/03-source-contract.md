# `source.py` 리뷰

## 파일

[`aegislm/datasets/source.py`](../../../aegislm/datasets/source.py)

## 역할

이 파일은 취약점을 직접 탐지하는 분석기가 아니라 source 학습·평가에서
사용하는 공통 계약 계층입니다. normalized record 검증, model-visible prompt
생성, supervised target 생성, output 검증을 연결합니다.

```text
source code + private metadata
├─ format_source_prompt() → target CWE와 supplied function만 모델에 공개
└─ build_source_target()  → private label과 승인된 evidence로 학습 정답 생성
                              ↓
                       validate_source_output()
```

## 입력 경계

canonical record는 다음 정보를 함께 보관합니다.

- 공개 가능: `target_cwe`, source code
- 비공개 통제 정보: label, split, source dataset, evidence level

`format_source_prompt()`는 원본 record를 그대로 직렬화하지 않고 공개 필드만
새 객체에 복사합니다. record ID, provenance, label, split은 prompt에 포함하지
않습니다. 네 종류의 prompt 문구는 code hash로 결정되므로 label과 독립적입니다.

## target 생성 경계

`build_source_target()`은 다음 조건을 만족할 때만 학습 target을 만듭니다.

- evidence level이 `patch_localized`, `code_span_grounded`,
  `analyzer_grounded` 중 하나
- `present` label이면 실제 source substring인 finding이 최소 하나 존재
- 모든 label에 assessment basis가 존재
- `uncertain` label은 현재 supervised target에서 제외
- 완성된 target이 v2 schema와 semantic validation을 통과

이 정책은 label-only 데이터를 학습에 넣지 않는다는 점에서 적절합니다. 다만
현재 `evidence_linked`는 span과 설명 필드의 존재를 뜻할 뿐, 해당 span들이 CWE의
실제 인과관계를 증명한다는 뜻은 아닙니다.

## output 검증 경계

`validate_source_output()`은 schema, exact source substring, `present` finding,
`not_observed`의 전역 안전 주장 여부를 검사합니다. 이는 모델이 입력에 없는 코드를
근거로 만드는 것을 막지만 semantic correctness를 보증하지는 않습니다.

특히 현재 validator와 `aegislm/evaluation/source.py`는 출력의
`scope.target_cwe`가 입력 record의 `task.target_cwe`와 같은지 확인하지 않습니다.
따라서 다른 CWE를 출력해도 assessment 값만 맞으면 정답으로 집계될 수 있습니다.

## patch evidence helper

`derive_patch_findings()`는 before/fixed 함수의 diff에서 제거·변경된 source span을
최대 세 개 선택합니다. 이 결과는 evidence 후보로는 유용하지만 다음 이유로
독립 gold가 아닙니다.

- patch에 취약점 수정과 무관한 refactoring이 포함될 수 있음
- 변경된 줄과 target CWE의 인과관계를 검사하지 않음
- line diff가 실패하면 character diff로 fallback함

따라서 verified pair라는 사실만으로 high-confidence 보안 근거로 사용하지 않고,
별도 semantic validator 또는 수동 gate를 통과시켜야 합니다.

## 잘된 점

- private metadata와 model-visible prompt가 명시적으로 분리됩니다.
- code SHA-256과 record schema를 함께 검사합니다.
- exact substring이 아닌 model evidence를 거부합니다.
- 근거 없는 positive와 uncertain supervision을 보수적으로 제외합니다.
- `not_observed`를 whole-program safety 주장으로 확장하지 않도록 제한합니다.
- prompt variant가 deterministic하고 label-independent합니다.

## 발견 사항

| ID | 우선순위 | 상태 | 내용 |
| --- | --- | --- | --- |
| SRC-CONTRACT-01 | P1 | Open | 출력 `scope.target_cwe`와 입력 `task.target_cwe`의 동일성 검사가 없어 다른 CWE 판단도 정답 집계될 수 있습니다. |
| SRC-CONTRACT-02 | P1 | Open | exact span 존재를 semantic evidence linkage로 취급할 수 있어 구조적 PASS와 보안 근거 PASS를 구분해야 합니다. |
| SRC-CONTRACT-03 | P2 | Open | schema와 prompt는 span 최대 8개지만 `_normalize_code_spans()`는 최대 10개를 반환합니다. |
| SRC-CONTRACT-04 | P2 | Open | output contract는 `uncertain`을 허용하지만 target builder는 전부 제외해 abstention 학습 정책이 비어 있습니다. |
| SRC-CONTRACT-05 | P2 | Open | 전역 안전 주장 검사가 제한된 영어 정규식에 의존해 동의어·다른 언어 표현을 놓칠 수 있습니다. |
| SRC-CONTRACT-06 | P1 | Open | generic patch diff를 target-CWE의 causal evidence로 직접 사용할 수 있어 별도 의미 검증 gate가 필요합니다. |
| SRC-ARCH-01 | P2 | Open | contract, prompt, target builder, patch heuristic, legacy converter가 한 파일에 혼합돼 있습니다. |

각 항목의 수정 순서와 완료 조건은
[통합 수정 백로그](findings/remediation-backlog.md)에 기록합니다.

## 모델 교체 시 재사용할 부분

다음은 모델 이름이나 학습 프레임워크와 분리된 공통 계층으로 유지합니다.

- canonical source record
- model-visible 정보 경계
- source output schema와 semantic validator
- label-blind challenge와 private gold
- precision, recall, FPR, abstention, schema, evidence 절대 gate

모델별로 바뀌어야 하는 부분은 tokenizer/chat template, serving adapter,
checkpoint lifecycle과 실행 config에 한정합니다. 이 경계를 지키면 동일한 데이터와
평가 계약으로 Qwen, Mistral 및 후속 모델을 반복 검증할 수 있습니다.

## 판정

`수정 후 유지`입니다. source 계약은 모델 교체 실험의 공통 기반으로 필요하지만,
새 모델 평가 전에 `SRC-CONTRACT-01`을 우선 수정하고 나머지 P1 근거 품질 항목을
수정하거나 명시적으로 quarantine해야 합니다.

## 문서화 리팩터링 기록

2026-09-04에 동작 변경 없는 1차 문서화 리팩터링을 적용했습니다.

- module docstring에 pipeline 위치, private/model-visible 경계와 non-goal 추가
- 공개 함수에 입력, 출력, 실패 조건과 structural/semantic 경계 추가
- patch diff가 evidence candidate일 뿐이라는 경고 추가
- 복잡한 정규화·fallback 위치에 의도 중심 inline comment 추가

docstring을 제거한 AST를 변경 전 `HEAD`와 비교해 실행문이 동일함을 확인했고
`py_compile`과 `git diff --check`를 통과했습니다. 이번 작업은 설명 개선만
수행했으므로 `SRC-CONTRACT-01`부터 `06`, `SRC-ARCH-01`은 계속 `Open`입니다.
