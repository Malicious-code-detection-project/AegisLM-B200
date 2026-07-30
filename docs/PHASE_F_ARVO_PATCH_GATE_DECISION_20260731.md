# Phase F ARVO Patch Gate Decision — 2026-07-31

## Outcome

ARVO v3 metadata에서 선택한 buffer crash 후보를 공개 개발자 패치와
연결해 검토한 결과는 `FAIL EARLY`입니다. 따라서 ARVO `crash_type`을
CWE-121/122/126 gold label로 변환하거나 binary adapter 학습에 사용하지
않습니다.

- metadata 후보: `2,675`
- 공개 GitHub 개발자 패치 후보: `2,144`
- 최종 review queue: family별 50건, 총 `200`
- 고유 repository+commit: `200/200`
- 수동 오류 예산: `10/200` (`5%`)
- 확정 오류: `11/200`
- 수학적 최소 오류율: `5.5%`
- 판정: `FAIL EARLY`
- training approval: `false`

남은 189건이 모두 정상이더라도 오류율이 5% 이하로 내려갈 수 없으므로
추가 검토를 중단했습니다. 이는 검토 비용을 줄이기 위한 중단 기준이며,
미검토 레코드를 정상으로 판정했다는 뜻이 아닙니다.

## Safe Collection Boundary

수집기는 다음 경계를 강제합니다.

- `https://github.com/<owner>/<repo>/commit/<sha>.patch`만 허용
- 패치당 최대 `5 MiB`
- repository+commit 중복 제거
- C/C++ source hunk가 없는 패치 제외
- `GIT binary patch`가 포함된 패치 제외
- PoC, crash output, reproducer command를 읽지 않음
- Docker image pull, reproducer, object, executable 실행 없음

초기 queue 감사에서 Git binary patch 13건과 reviewable C/C++ hunk가 없는
패치 5건을 발견했습니다. 이 항목들은 review queue에서 제거하고
결정론적 reserve로 보충했습니다.

## Reproducible Evidence

서버 기준 경로와 SHA-256은 다음과 같습니다. 패치 본문과 생성 artifact는
Git에 커밋하지 않습니다.

| Artifact | Server path | SHA-256 |
|---|---|---|
| ARVO DB | `data/raw_data/arvo/v3.0.0/arvo.db` | `331184ca807c2f136f98dac9f1df94c893f4ee2fdf9329dca517ff88e72f97ce` |
| 200-record review manifest | `data/processed/phase-f-arvo-patch-review-v1/patch-review.json` | `3926e39e1d3ac430a590a393f2ab7828f071f4fa709010972d0a8af385f932d1` |
| readable review queue | `data/processed/phase-f-arvo-patch-review-v1/manual-review-200.md` | `68ab5f303d3db7b3da9188018c6abe935e267a541e4ffed8ceff4a96627c8bbb` |
| operator decisions | `data/processed/phase-f-arvo-patch-review-v1/manual-decisions-20260731.json` | `8e70104439f29e7b1538d9aab70318b8aeeba5ff81a4b14fcdfb17342b6d3308` |
| final decision | `data/processed/phase-f-arvo-patch-review-v1/manual-review-result.json` | `9dcbf615a03a0e073c1bf03512ade2de939a1b5f01e3d64239ed76a4e53d72c3` |

## Confirmed Error Classes

| 유형 | 예시 local ID | 판정 이유 |
|---|---|---|
| 보안 수정과 무관한 변경 | `42492850`, `42487630` | spelling/version 또는 숫자 출력 수정만 존재 |
| sanitizer 억제 | `42491388` | out-of-bounds 수정이 아니라 ASAN instrumentation 비활성화 |
| 다른 memory-safety family | `42508187`, `42475836` | stale object·decode failure 처리이며 주장된 buffer family 근거가 없음 |
| patch와 crash family 불일치 | `42507578`, `42539520` | image clipping·TIFF field 검증이 stack read/write를 입증하지 않음 |
| 근거 없는 semantic/WIP 변경 | `42476531`, `42521581`, `42528093`, `42526513` | exact buffer operation·bound 또는 국소화된 fix 관계가 없음 |

## Decision

1. ARVO metadata-only family mapping은 학습 supply로 사용하지 않습니다.
2. 현재 200건을 수량 확보 목적으로 재라벨링하지 않습니다.
3. source patch를 확보하더라도 sanitizer crash family와 CWE를 자동
   등치하지 않습니다.
4. binary compile/decompile과 adapter 학습은 계속 보류합니다.
5. 다음 공급 감사는 patch-localized CWE 근거를 가진 MegaVul/CVEfixes
   계열과 source–binary alignment 전용 Assemblage/Decompile-Bench를
   역할별로 분리해 진행합니다.

MegaVul/CVEfixes는 vulnerability-label supply 후보이고,
Assemblage/Decompile-Bench는 source–binary representation 후보입니다.
두 역할을 섞어 alignment 데이터에 취약점 gold label이 있는 것처럼
취급하지 않습니다.

## Related Documents

- [Phase F plan](PHASE_F_DATASET_AND_BINARY_EXPERIMENT_PLAN.md)
- [Fine-tuning test workbook](FINETUNING_TEST_WORKBOOK.md)
- [Dataset candidates](DATASET_CANDIDATES.md)
- [Binary strict target decision](PHASE_F_BINARY_ROLE_TARGET_DECISION_20260731.md)
