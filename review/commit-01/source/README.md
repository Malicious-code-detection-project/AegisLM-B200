# Commit 1-A — SARD/Juliet Source 리뷰

## 목적

NIST SARD Juliet C/C++ ZIP에서 취약 함수와 수정 함수를 pair로 추출하고,
정답 힌트를 모델 입력에서 제거한 뒤 Qwen 학습·validation·blind test 자료를
만드는 경로를 검토합니다.

이 경로는 악성코드를 실행하거나 실제 공격을 재현하지 않습니다. Juliet의
synthetic 취약점 source를 학습 계약으로 변환합니다.

## 처리 흐름

```text
Juliet ZIP
→ 후보 C/C++ 파일 선택
→ bad/good 함수 추출
→ 함수 pair와 private label 구성
→ 주석·함수명의 정답 힌트 정리
→ code-visible evidence 생성
→ group-first split
→ source contract와 tokenizer gate
→ train / validation / blind challenge·gold
→ 수동 검토 후 별도 승인
```

## 파일별 리뷰

| 순서 | 파일 | 역할 | 리뷰 상태 | 판정 |
| ---: | --- | --- | --- | --- |
| 1 | [`scripts/build_sard_juliet_source_dataset.py`](01-build-script.md) | CLI orchestration과 artifact materialization | 완료 | 수정 후 유지 |
| 2 | [`aegislm/datasets/sard_juliet.py`](02-sard-juliet.md) | Juliet 추출·근거 생성·split·gate | 완료 | 수정 후 유지 |
| 3 | [`aegislm/datasets/source.py`](03-source-contract.md) | 공통 source record·contract·prompt | 완료 | 수정 후 유지 |
| 4 | [`aegislm/datasets/source_audit.py`](04-source-audit.md) | source 데이터 품질 감사 | 완료 | 수정 후 유지 |
| 5 | `tests/test_sard_juliet.py` | Juliet builder 회귀 테스트 | 다음 | 미정 |

## 발견 사항 분류

- [데이터·연구 품질](findings/data-quality.md)
- [운영·재현성](findings/operations-and-reproducibility.md)
- [구조·AegisLM/NuriLab 책임 경계](findings/structure-and-boundaries.md)
- [통합 수정 백로그](findings/remediation-backlog.md)

## 현재 해석 경계

- `present/not_observed` decision gold는 Juliet bad/good 구조를 근거로 합니다.
- evidence gold는 주석과 CWE별 정규식 휴리스틱으로 생성합니다.
- 높은 evidence 점수는 실세계 취약점 근거 정확성과 동일하지 않습니다.
- 현재 결과는 검토를 통과한 Juliet CWE와 C/C++ 함수 범위에만 적용합니다.
- 임의 언어, 실제 repository 코드, binary-derived pseudo-C 일반화는 아직
  입증되지 않았습니다.
- 공통 source 계약과 절대평가기는 모델과 분리하고, 모델 교체 시 tokenizer,
  chat template, serving adapter, checkpoint lifecycle만 교체하는 구조를
  목표로 합니다.

## 문서화 리팩터링 진행

`source.py`와 `source_audit.py`에 module/function docstring과 의도 중심 inline
comment를 시범 적용했습니다. 실행문 AST는 변경하지 않았습니다. 기능 결함과
구조 분리는 [통합 수정 백로그](findings/remediation-backlog.md)에 계속 `Open`으로
유지합니다.
