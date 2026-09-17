# `build_sard_juliet_source_dataset.py` 리뷰

## 파일

[`scripts/build_sard_juliet_source_dataset.py`](../../../scripts/build_sard_juliet_source_dataset.py)

## 역할

이 파일은 취약점을 직접 분석하지 않습니다. 사용자가 전달한 Juliet ZIP과
Qwen tokenizer를 받아 dataset builder를 실행하고, 학습·평가 artifact를
정해진 위치에 기록하는 CLI orchestration entrypoint입니다.

## 입력

- Juliet ZIP 경로
- 출력 디렉터리
- 실제 Qwen tokenizer/model identifier
- profile, seed, token cutoff
- train·validation·test pair 수
- 기존 데이터와 겹치는 group을 제외하기 위한 manifest
- evaluation-only 여부
- 선택적으로 기대하는 archive digest

기본 quota에서 하나의 pair는 `present`와 `not_observed` 두 레코드를
만듭니다. 따라서 train 5,000 pair는 10,000 records, validation 500 pair는
1,000 records, test 250 pair는 500 records입니다.

## 주요 처리

1. 입력 ZIP 존재와 digest를 확인합니다.
2. 실제 tokenizer를 로드합니다.
3. Juliet 함수를 추출하고 기존 데이터 overlap을 제외합니다.
4. group-first split과 token gate를 적용합니다.
5. 모델 입력과 private gold를 분리합니다.
6. manifest, challenge, gold, manual-review queue와 checksums를 기록합니다.

## 출력 성격

- raw catalog와 eligible/quarantine manifest
- canonical source records
- train·validation materialized JSONL
- label-blind challenge와 별도 private gold
- 고정 seed 수동 검토 queue
- 실행 manifest와 checksums

raw executable이나 malware payload를 생성·실행하는 경로는 아닙니다.

## 잘된 점

- archive 무결성 확인 경로가 있습니다.
- 실제 tokenizer로 system+user+assistant token 수를 검사합니다.
- challenge와 gold를 분리합니다.
- pair quota를 record 수와 혼동하지 않도록 builder 계약이 분명합니다.
- 동일 seed 재생성을 위한 manifest와 checksums를 남깁니다.

## 발견 사항

| ID | 우선순위 | 상태 | 내용 |
| --- | --- | --- | --- |
| SRC-BUILD-01 | P2 | Open | tokenizer가 `trust_remote_code=True`를 사용하므로 승인 모델·revision 정책을 명시해야 합니다. |
| SRC-BUILD-02 | P2 | Open | 실행 manifest에 host 절대경로가 기록될 수 있어 공개 artifact에는 root alias와 상대경로가 필요합니다. |
| SRC-BUILD-03 | P2 | Open | 기존 출력 디렉터리와 새 실행을 혼합하지 않도록 run 단위 빈 디렉터리 또는 명시적 overwrite 정책이 필요합니다. |
| SRC-BUILD-04 | P2 | Open | token gate 이후 pair가 탈락해도 reserve를 자동 backfill하지 않아 목표 quota가 부족할 수 있습니다. |
| SRC-BUILD-05 | P3 | Open | CLI 단계별 사전 조건과 생성 artifact의 공개/private 경계를 코드 주석으로 설명할 필요가 있습니다. |

## 판정

`수정 후 유지`입니다. orchestration 책임은 필요하지만, 경로 공개 정책과
tokenizer 신뢰 경계, 출력 디렉터리 lifecycle을 명확히 해야 합니다.
