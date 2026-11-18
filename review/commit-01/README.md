# Commit 1 리뷰 — `618db23`

## 커밋 성격

`feat: advance Phase F source and binary validation`은 source 데이터 구축,
two-stage 학습·평가, binary compile·decompile 기반을 한 커밋에 포함합니다.
변경 범위가 매우 크므로 기능 영역을 나눠 검토합니다.

## 영역별 진행 상태

| 영역 | 내용 | 상태 | 상세 기록 |
| --- | --- | --- | --- |
| 1-A | SARD/Juliet source 데이터 | 진행 중 | source audit까지 완료, 회귀 테스트가 다음 |
| 1-B | Q1R10 판단 + Q1R11 근거 | 미시작 | 1-A 완료 후 생성 |
| 1-C | Binary compile + Ghidra | 미시작 | 1-B 완료 후 생성 |

## 현재까지 확인한 결론

- SARD/Juliet ZIP은 실행하지 않고 source만 읽습니다.
- 데이터 빌더는 악성코드 분석기가 아니라 synthetic 취약점 학습자료
  변환기입니다.
- Juliet의 bad/good label은 decision gold로 사용할 수 있지만, evidence
  gold는 이 코드의 휴리스틱으로 생성됩니다.
- 따라서 evidence 평가는 독립 전문가 gold가 아니라 같은 target builder가
  만든 규칙과의 일치 성격을 포함합니다.
- 공통 데이터 계약과 Juliet 전용 추출 규칙, 범용 분석기 역할이 여러 파일에
  걸쳐 혼합돼 있으며, `source.py` 자체도 contract·prompt·target·patch
  heuristic·legacy bridge 책임을 함께 가지고 있습니다.
- source output의 target CWE가 입력 target CWE와 일치하는지 평가하지 않는
  무결성 문제가 확인됐습니다.
- source audit는 최종 승인을 수동 gate로 넘기지만, ID uniqueness, split 파일
  출처, tokenizer/chat-template hash가 audit 결과에 완전히 결합되지 않습니다.
- 모델과 무관한 수정 사항은
  [통합 수정 백로그](source/findings/remediation-backlog.md)에 모읍니다.

## 커밋 단위 임시 판정

아직 Commit 1 전체를 읽지 않았으므로 최종 판정을 내리지 않습니다.
현재 완료된 `sard_juliet.py`와 `source.py`를 `수정 후 유지`로 판정했습니다.

## 다음 리뷰

`aegislm/datasets/source_audit.py`에서 leakage, quota, duplicate, tokenizer와
training 승인 gate가 실제로 fail-closed하는지 확인합니다.
