# Source Vulnerability Manual Review Rubric

## 목적

수동검토는 `expected_output`을 사람이 직접 고치는 작업이 아니다. 레코드의
private label과 근거가 학습 supervision으로 적합한지 판정하고, 반복되는
생성기 오류를 찾아내는 품질 gate다.

핵심 질문은 다음과 같다.

> Dataset 이름, Juliet 함수명과 주석, private label을 보지 않고도 제공된
> 함수와 target CWE만으로 다른 검토자가 같은 결론에 도달할 수 있는가?

## 검토자 역할

- Codex가 전체 레코드의 기술 검토, 기록, 오류 유형화와 수정안을 담당한다.
- 사용자는 대표 정상 사례와 `uncertain` 사례를 보고 기준·단계 전환을
  승인한다.
- boolean을 일괄적으로 채우거나 수량을 맞추기 위해 애매한 사례를
  통과시키지 않는다.

## Label gate

`operator_label_error=false`가 되려면 다음을 모두 만족해야 한다.

1. `target_cwe`와 실제 코드의 weakness 종류가 일치한다.
2. 위험하거나 방어된 경로가 supplied function 안에서 관찰 가능하다.
3. `present`라면 관련 source/setup, guard, sink/effect가 실행 가능한
   관계를 이룬다.
4. `not_observed`라면 target CWE를 차단하는 용량, 경계, 초기화, 수명 관리
   조건이 실제 위험 연산 전에 적용된다.
5. `not_observed`를 함수 또는 프로그램 전체가 안전하다는 뜻으로 사용하지
   않는다.

판단이 불가능하면 정상으로 간주하지 않고 `review_status=uncertain`으로
분류한다.

## Evidence gate

`operator_evidence_error=false`가 되려면 다음을 모두 만족해야 한다.

1. 모든 `code_spans`가 supplied function의 정확한 부분 문자열이다.
2. `;`, brace, 단독 loop 조건처럼 의미 없는 span이 없다.
3. span들이 취약점의 인과관계를 충분히 포함한다.
   - 할당 크기 ↔ 복사 크기
   - 입력 ↔ 경계 검사 ↔ 배열 접근
   - 초기화 누락 ↔ 값 사용
   - 할당 ↔ 해제 누락
   - 포인터 이동 ↔ 실제 write
   - 정수 경계 ↔ 산술 연산
4. `relationship`은 span 사이의 관계를 구체적으로 설명한다.
5. `conclusion`은 그 관계가 target CWE의 `present/not_observed` 판정으로
   이어지는 이유를 설명한다.
6. 어떤 CWE에도 붙일 수 있는 일반 문장을 근거로 사용하지 않는다.

다음 문장은 evidence로 인정하지 않는다.

```text
code-visible operation on the vulnerable execution path
This exact source operation is the code-visible basis for the scoped assessment.
```

## 판정 매트릭스

| Label | Evidence | 기록 |
| --- | --- | --- |
| 정확 | 충분 | `false / false`, `review_status=pass` |
| 정확 | 부족·오류 | `false / true`, `review_status=evidence_error` |
| 오류 | 오류 | `true / true`, `review_status=label_and_evidence_error` |
| 판단 불가 | 보류 | `true / true`, `review_status=uncertain` |

Label이 틀렸는데 evidence만 정상인 경우는 원칙적으로 허용하지 않는다.

## 조기 중단

고정 100건의 최대 오류율은 5%다. 서로 다른 오류 레코드가 6건 이상
확인되는 순간 나머지 검토 여부와 무관하게 gate는 `fail_early`다.
실패한 표본은 삭제하지 않고 generator 회귀 테스트와 연구 기록으로
보존한다.

## 재검토 산출물

- 전체 판정 JSONL
- CWE별·오류 유형별 집계
- 대표 PASS 사례
- 대표 오류 사례
- `uncertain` 전부
- 이전 실패 사례가 새 builder에서 수정됐는지 확인하는 회귀 표

## 2026-07-29 적용 결과

- v1 실패 기준선: 최초 검토 10건 모두 label은 맞았지만 단일 sink만
  제시해 evidence 오류 `10/10`, `fail_early`
- v2 수정: related exact span 최대 10개, CWE별 최소 인과관계, I/O→변환→
  effect 연결, Juliet `good/bad` target 누출 제거
- 최종 고정 표본: 100건, present/not_observed `50/50`, 26 CWE, 79 인과 유형
- 최종 판정: label 오류 `0`, evidence 오류 `0`, uncertain `0`, `PASS`
- 산출물:
  `data/processed/phase-f-sard-grounded-v2/manual_review_100.jsonl`과
  `manual_review_100.md`

이 PASS는 F3 통합 자격이다. 학습 config·manifest·challenge hash를 F3에서
동결하기 전까지 GPU 학습 승인을 의미하지 않는다.
