# Commit 1 리뷰 — `618db23`

## 커밋 성격

`feat: advance Phase F source and binary validation`은 source 데이터 구축,
two-stage 학습·평가, binary compile·decompile 기반을 한 커밋에 포함합니다.
변경 범위가 매우 크므로 기능 영역을 나눠 검토합니다.

## 영역별 진행 상태

| 영역 | 내용 | 상태 | 상세 기록 |
| --- | --- | --- | --- |
| 1-A | SARD/Juliet source 데이터 | 진행 중 | [source 리뷰](source/README.md) |
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
- 공통 데이터 계약과 Juliet 전용 추출 규칙, 범용 분석기 역할이 한 파일에
  과도하게 섞여 있습니다.

## 커밋 단위 임시 판정

아직 Commit 1 전체를 읽지 않았으므로 최종 판정을 내리지 않습니다.
현재 완료된 `sard_juliet.py`만 `수정 후 유지`로 판정했습니다.

## 다음 리뷰

`aegislm/datasets/source.py`에서 canonical source record, output contract,
prompt formatter가 Juliet 전용 코드와 어떻게 분리돼 있는지 확인합니다.
