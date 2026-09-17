# Phase F 커밋 리뷰 안내서

이 문서는 `origin/main..codex/phase-f-source-v3` 사이의 20개 커밋을
사용자가 시간순으로 검토하기 위한 한국어 안내서입니다.

코드의 세부 구현을 모두 설명하는 문서가 아니라 다음 질문에 답하기 위한
지도입니다.

1. 이 커밋을 왜 만들었는가?
2. 무엇을 실제로 구현하거나 검증했는가?
3. 결과가 성공인지 실패인지?
4. 어떤 파일부터 읽어야 하는가?
5. 현재 코드를 유지, 수정, 연구 보관, 제거 중 어디에 둘 것인가?

이 안내서의 판정은 현재 브랜치를 바로 `main`에 병합해도 된다는 뜻이
아닙니다. 현재 PR은 276개 파일과 약 4만 줄을 포함하므로, 리뷰가 끝난 뒤
채택할 기능만 작은 PR로 분리하는 것이 기본 방침입니다.

---

## 1. 먼저 알아야 할 최종 결과

20개 커밋 전체의 결과를 먼저 요약하면 다음과 같습니다.

| 영역 | 결과 | 현재 취급 |
| --- | --- | --- |
| Qwen source 판단 | 절대평가 PASS | 채택 후보 |
| Qwen source 근거 선택 | 절대평가 PASS | 채택 후보 |
| Binary-derived target | 일부 CWE 품질 PASS, 공급량 부족 | 학습 금지·연구 보관 |
| ARVO patch label | 수동 검토 FAIL | 학습 금지 |
| CVEfixes patch label | 수동 검토 FAIL | 학습 금지 |
| Decompile-Bench | source–assembly 정렬 96/100 PASS | 정렬 참고 전용 |
| Assemblage | strict metadata 완전 행 0 | metadata 참고 전용 |
| BinKit | artifact·license·schema 불충분 | 다운로드 보류 |
| EMBER2024 benchmark | 중복 제거 후 평가 데이터 사용 가능 | 독립 benchmark 전용 |
| EMBER2024 classifier | 시간 분리 절대평가 FAIL | NuriLab 연결 금지 |

현재 실제 성과는 다음 범위로 제한됩니다.

> NIST SARD/Juliet C/C++ 함수에서 지정된 CWE의
> `present / not_observed`를 판단하고, 그 판단의 근거 line을 선택하는
> Qwen3-Coder-Next 80B two-stage pipeline이 신규 blind 500건 절대 gate를
> 통과했습니다.

다른 언어, 실제 프로젝트, raw binary, 악성코드, 구체적 remediation,
NuriLab, RAG/MCP 성능은 아직 입증되지 않았습니다.

---

## 2. 커밋을 읽는 순서

20개를 같은 깊이로 읽지 않습니다.

| 묶음 | 커밋 | 읽는 목적 |
| --- | --- | --- |
| A. Source와 Binary 기반 | 1 | 채택할 source와 연구용 binary를 분리 |
| B. Binary target 반복 | 2–11 | 왜 binary 학습을 중단했는지 확인 |
| C. 외부 데이터 공급 감사 | 12–18 | 데이터가 많아도 학습에 쓰지 않은 이유 확인 |
| D. Malware feature benchmark | 19–20 | EMBER를 SFT와 분리한 이유 확인 |

각 커밋의 현재 판정은 다음 네 가지를 사용합니다.

- `유지`: 현재 핵심 경로에 필요합니다.
- `수정 후 유지`: 기능은 필요하지만 보안·구조 수정이 필요합니다.
- `연구 보관`: 실패 원인과 재현 증거로 보존하되 운영 핵심과 분리합니다.
- `제거 후보`: 중복되거나 현재 경로에서 더 이상 사용하지 않습니다.

---

# A. Source와 Binary 기반

## Commit 1 — `618db23 feat: advance Phase F source and binary validation`

### 변경 규모

- 파일 136개
- 추가 약 15,947줄
- source, binary, 학습, 추론, 평가, 문서, 설정, 테스트가 한 커밋에 포함

### 왜 만들었나

Phase E에서 학습·merge·vLLM lifecycle은 성공했지만 500건 모델 품질
평가가 실패했습니다. 이 실패를 해결하기 위해 다음 작업을 한 번에
진행했습니다.

1. SARD/Juliet에서 근거가 있는 source 데이터를 새로 추출
2. 판단과 근거 생성을 분리한 Qwen two-stage 학습
3. 신규 blind 평가와 vLLM serving 검증
4. binary-derived 데이터 가능성 검증을 위한 compile·Ghidra 기반 구축

### 1-A. SARD/Juliet source 데이터

지금까지 완료한 파일별 상세 리뷰와 발견 사항은
[Commit 1-A source 코드 리뷰](../commit-01/source/README.md)에
분리해 기록합니다.

핵심 흐름:

```text
SARD Juliet ZIP
→ C/C++ 단일 파일 후보
→ bad/good 함수 pair
→ 정답 힌트 제거
→ group 단위 split
→ Qwen tokenizer gate
→ 학습·검증·blind 데이터
```

중요한 구현:

- ZIP 안의 C/C++ source를 실행하지 않고 읽습니다.
- `bad`, `good`, `Juliet`, `POTENTIAL FLAW`, `FIX` 같은 정답 힌트를
  모델 입력에서 제거합니다.
- 같은 원본의 취약 함수와 수정 함수가 서로 다른 split에 들어가지 않도록
  `group_id`로 묶습니다.
- 문자 길이 추정이 아니라 실제 Qwen tokenizer로 2,048 token 제한을
  검사합니다.
- private label과 provenance를 prompt에 넣지 않습니다.

먼저 읽을 파일:

1. `scripts/build_sard_juliet_source_dataset.py`
2. `aegislm/datasets/sard_juliet.py`
3. `aegislm/datasets/source.py`
4. `aegislm/datasets/source_audit.py`
5. `tests/test_sard_juliet.py`

### 1-B. Q1R10 판단 + Q1R11 근거

하나의 모델이 긴 JSON 보고서를 모두 생성하도록 하지 않고 역할을
분리했습니다.

```text
Q1R10 decision
  입력: target CWE + supplied function
  출력: present / not_observed

Q1R11 evidence
  입력: Q1R10 판단 + line 번호가 붙은 함수
  출력: 판단을 뒷받침하는 line range

deterministic renderer
  두 결과를 versioned assessment JSON으로 조립
```

신규 blind 500건 결과:

- decision precision: `0.9881`
- decision recall: `1.0000`
- decision FPR: `0.0120`
- evidence precision: `0.9001`
- evidence recall: `0.9229`
- evidence F1: `0.9114`
- parse/schema/renderer: `1.0000`

두 adapter는 각각 base model에서 100-step 학습했습니다. 250/313-step
연장은 개선 근거가 없어 수행하지 않았습니다.

먼저 읽을 파일:

1. `aegislm/datasets/source_decision.py`
2. `aegislm/datasets/source_evidence_lines.py`
3. `aegislm/datasets/source_two_stage.py`
4. `aegislm/evaluation/source_decision.py`
5. `aegislm/evaluation/source_evidence_lines.py`
6. `aegislm/evaluation/source_two_stage.py`
7. `configs/llamafactory/b200/qwen3_coder_next_phase_f_q1r10_decision_100.yaml`
8. `configs/llamafactory/b200/qwen3_coder_next_phase_f_q1r11_evidence_100.yaml`

### 1-C. Binary compile·Ghidra 기반

SARD/Juliet source를 GCC·Clang으로 object로 컴파일하고, Ghidra로
pseudo-C를 생성해 source와 binary-derived 표현을 연결하려 했습니다.

중요한 경계:

- 생성 object를 실행하지 않았습니다.
- raw executable을 학습 prompt에 넣지 않았습니다.
- pseudo-C, 제한된 assembly, imports·sections 같은 정적 특징만
  normalized record 후보로 만들었습니다.

먼저 읽을 파일:

1. `scripts/run_phase_f_binary_b0_compile_canary.py`
2. `scripts/run_phase_f_binary_b0_decompile_canary.py`
3. `scripts/build_phase_f_binary_b0_records.py`
4. `scripts/ghidra/ExportJulietFunctions.java`
5. `aegislm/datasets/binary.py`

### 확인된 문제

이 커밋은 기능 범위가 너무 큽니다. 또한 현재 보안 리뷰에서 다음 수정
사항을 확인했습니다.

- manifest의 `archive_path`, `pair_id`, `object_ref` 경로 검증 부족
- compiler·Ghidra의 host 환경 격리 부족
- Ghidra가 전체 환경변수를 상속
- OpenAI-compatible endpoint의 scheme·host 제한 부재
- `.venv-serving`, `.venv-ember-eval`, `.codex-sync` Git ignore 누락
- inference CLI의 기본 model/backend가 과거 GPT-OSS/Unsloth 설정
- 문서와 설정에 서버 절대경로 포함

### 현재 판정

| 부분 | 판정 |
| --- | --- |
| SARD source 추출·검증 | `수정 후 유지` |
| Q1R10/Q1R11 학습·평가 | `수정 후 유지` |
| Binary compile·Ghidra 기반 | `연구 보관` |
| 136개 파일 통합 커밋 형태 | `분할 필요` |

---

# B. Binary target 반복

## Commit 2 — `9e8ff85 fix: accept F7 pilot queues in binary runner`

### 왜 만들었나

compile canary가 B0의 `primary` queue만 받고 F7의 `pilot` queue를
거부하는 연결 오류를 수정했습니다.

### 실제 변경

- `primary`와 `pilot` queue를 같은 bounded compile runner가 처리
- 회귀 테스트 추가

먼저 읽을 파일:

1. `scripts/run_phase_f_binary_b0_compile_canary.py`
2. `tests/test_phase_f_binary_b0_compile_canary.py`

### 현재 판정

`수정 후 유지`. 연구 runner에는 필요한 수정이지만, 외부 manifest 경로
검증과 격리 실행을 추가하기 전에는 안전한 일반 도구로 간주하지 않습니다.

---

## Commit 3 — `ac01070 fix: enforce strict binary target evidence`

### 왜 만들었나

초기 B0 검토가 “pseudo-C가 생성됐는가”에 치우쳐 실제 target CWE를
뒷받침하는 근거가 부족한 pair까지 승인할 수 있었습니다. 더 엄격한
target-evidence 정책을 과거 결과에 소급 적용했습니다.

### 결과

- 초기 B0: 145 pair 중 100 승인
- 엄격 재감사: 99 승인, 46 격리
- CWE-563 한 pair를 추가 격리

먼저 읽을 파일:

1. `scripts/finalize_phase_f_binary_b0_review.py`
2. `tests/test_phase_f_binary_b0_review_finalize.py`
3. `docs/experiments/plans/PHASE_F_DATASET_AND_BINARY_EXPERIMENT_PLAN.md`

### 현재 판정

`연구 보관`. 자동 생성 성공과 보안 근거 품질이 다른 문제라는 사실을
명확히 한 중요한 교정입니다.

---

## Commit 4 — `5ec763f feat: record second Phase F binary scale batch`

### 왜 만들었나

첫 500-pair 확대 결과만으로 공급량과 오류율을 단정하지 않고, 고정
정책을 유지한 두 번째 batch를 검토했습니다.

### 결과

- 두 번째 500-pair batch: `394/500` 승인
- 실패 decision과 수동 기록을 config·workbook에 보존

### 현재 판정

`연구 보관`. 새로운 운영 기능보다 실험 결과 동결이 중심입니다.

---

## Commit 5 — `6d26350 feat: record third Phase F binary scale batch`

### 결과

- 세 번째 500-pair batch: `410/500` 승인
- 같은 gate와 기록 형식을 반복 적용

### 현재 판정

`연구 보관`. 반복 batch의 수량 근거로 가치가 있습니다.

---

## Commit 6 — `f7e7d7b feat: record fourth Phase F binary scale batch`

### 결과

- 네 번째 500-pair batch: `419/500` 승인
- 앞선 batch와 같은 정책으로 결과 동결

### 현재 판정

`연구 보관`.

---

## Commit 7 — `f22ca95 feat: enforce model-ready binary target gates`

### 왜 만들었나

compile·decompile이 성공한 pair를 바로 학습에 넣지 않고 다음 lifecycle을
모두 통과하도록 만들었습니다.

```text
relation 검증
→ Qwen tokenizer gate
→ exact supply 선택
→ model-ready JSONL
→ 수동 100건 검토
→ PASS일 때만 학습 승인
```

### 주요 결과

- 다섯 번째 500-pair batch: `394/500`
- tail 160 pair 중 `121/160` 엄격 승인
- 1차 target-preservation qualified: `2,455`
- relation recovery 뒤 qualified: `2,536`
- tokenizer-qualified: `2,488`
- 선택: `2,450`, reserve: `38`

자동 gate는 통과했지만 target v1의 고정 100건 수동 검토에서 명백한
evidence 오류 6건이 발견돼 `FAIL EARLY`했습니다.

후속 flat-evidence target v2–v5·v7·v9도 자동 gate 또는 공급량을
통과한 경우가 있었지만, 수동 검토에서 관계 오류가 반복됐습니다.

먼저 읽을 파일:

1. `aegislm/datasets/binary.py`
2. `aegislm/datasets/binary_v1.py`
3. `scripts/build_phase_f_binary_tokenizer_gate.py`
4. `scripts/build_phase_f_binary_b0_records.py`
5. `aegislm/evaluation/binary.py`
6. `tests/test_binary_v1.py`

### 현재 판정

`연구 보관`. “자동 schema PASS는 의미적 근거 PASS가 아니다”라는 핵심
실패를 보존합니다. Binary adapter 학습은 승인하지 않습니다.

---

## Commit 8 — `1c2858b feat: add role-structured binary evidence contract`

### 왜 만들었나

flat evidence line 목록만으로는 security relation을 표현하기 어려웠습니다.
이를 해결하기 위해 evidence에 역할과 관계를 부여한 v2 contract를
추가했습니다.

핵심 개념:

- evidence role: `source`, `control`, `sink`, `bound`, `remediation`
- relation: `flows_to`, `constrains`, `bounds`, `remediates`
- exact code span
- 모든 핵심 relation은 실제 sink로 연결

먼저 읽을 파일:

1. `aegislm/schemas.py`
2. `aegislm/datasets/binary.py`
3. `tests/test_binary_contract.py`

### 현재 판정

`연구 보관`. 계약 설계는 의미가 있지만 이 계약을 적용한 dataset이 최종
학습 승인을 받지는 못했습니다.

---

## Commit 9 — `22d93ac feat: gate binary role-structured targets`

### 왜 만들었나

v2 role contract를 실제 Qwen tokenizer, 공급량, 고정 100건 수동 검토에
연결했습니다.

### 결과

| Iteration | 자동 공급 | 수동 결과 |
| --- | ---: | ---: |
| v2 r1 | `2,450/2,479` | `6/100 FAIL EARLY` |
| v2 r2 | `2,450/2,485` | `6/100 FAIL EARLY` |

generic identifier overlap이 실제 인과관계가 아닌데도 source와 sink를
연결한 것이 주요 실패 원인이었습니다.

먼저 읽을 파일:

1. `aegislm/datasets/binary_v2.py`
2. `scripts/build_phase_f_binary_role_review.py`
3. `scripts/finalize_phase_f_binary_role_review.py`
4. `docs/experiments/decisions/phase-f/PHASE_F_BINARY_ROLE_TARGET_DECISION_20260731.md`

### 현재 판정

`연구 보관`. 수량을 맞추기 위해 generic fallback을 사용하는 전략을
폐기한 근거입니다.

---

## Commit 10 — `989f6ac feat: audit strict binary role supply`

### 왜 만들었나

generic fallback을 끄고 CWE별 extractor가 완전한 범주만 다시
계산했습니다.

### 결과

- strict v3 tokenizer-qualified: `1,301/2,924`
- 기존 목표 2,450 pair 공급 실패
- 고정 100건 수동 검토: `6/100 FAIL EARLY`
- 오류 범위를 CWE-124/127/457/690으로 좁힘

### 현재 판정

`연구 보관`. 저신뢰 데이터를 추가해 2,450 pair를 억지로 채우지 않은
결정은 유지합니다.

---

## Commit 11 — `5a22e99 feat: finalize strict binary supply gate`

### 왜 만들었나

실패한 CWE를 단계적으로 격리하고 남은 extractor의 품질과 공급량을
다시 측정했습니다.

### 결과

| Iteration | 새 격리 | 적격 pair | 수동 검토 |
| --- | --- | ---: | ---: |
| strict v4 | CWE-124/127/457/690 | 1,228 | `6/100 FAIL` |
| strict v5 | + CWE-121 | 928 | `6/100 FAIL` |
| strict v6 | + CWE-122 | 661 | `6/100 FAIL` |
| strict v7 | + CWE-126 | 644 | `1/100 PASS` |

strict v7은 CWE-134/190/191/194/195 다섯 범주에서 target 품질은
통과했습니다. 그러나 공급량이 `644 < 2,450`이므로 binary adapter
학습은 시작하지 않았습니다.

### 현재 판정

`연구 보관`.

- 644 pair: `quality-approved / supply-blocked` seed
- Binary materialization: 보류
- Binary adapter 학습: 미실행
- raw executable/object 실행: 0

---

# C. 외부 데이터 공급 감사

## Commit 12 — `3ca58d3 feat: start ARVO buffer feasibility audit`

### 왜 만들었나

SARD/Juliet 외에 실제 공개 개발자 patch에서 buffer CWE 학습 근거를
확보할 수 있는지 ARVO metadata를 먼저 비실행 방식으로 감사했습니다.

### 안전 경계

- metadata만 조회
- PoC, crash output, reproducer command 미사용
- Docker image, object, executable 미실행

먼저 읽을 파일:

1. `aegislm/datasets/arvo.py`
2. `scripts/audit_phase_f_arvo_metadata.py`

### 현재 판정

`연구 보관`. 이 커밋 단독으로 학습 승인을 하지 않습니다.

---

## Commit 13 — `1320090 feat: complete ARVO patch feasibility gate`

### 왜 만들었나

ARVO crash metadata와 실제 공개 GitHub 개발자 patch가 동일한 buffer
취약점 관계를 뒷받침하는지 200건을 수동 검토했습니다.

### 결과

- metadata 후보: 2,675
- 공개 GitHub patch 후보: 2,144
- 고유 repository+commit review: 200
- 허용 오류: 최대 10/200
- 확정 오류: `11/200`
- 판정: `FAIL EARLY`

남은 레코드를 모두 정상으로 가정해도 오류율 5% 이하가 될 수 없으므로
검토를 중단했습니다.

먼저 읽을 파일:

1. `aegislm/datasets/arvo_patch.py`
2. `scripts/collect_phase_f_arvo_patches.py`
3. `scripts/finalize_phase_f_arvo_patch_review.py`
4. `docs/experiments/decisions/phase-f/PHASE_F_ARVO_PATCH_GATE_DECISION_20260731.md`

### 현재 판정

`연구 보관`. ARVO `crash_type`을 CWE-121/122/126 gold로 자동 변환하지
않습니다.

---

## Commit 14 — `12be684 feat: gate CVEfixes patch label supply`

### 왜 만들었나

ARVO 실패 뒤 patch-localized CWE를 제공할 가능성이 있는 CVEfixes의
공식 archive를 무결성 검사부터 read-only 공급량 감사까지 처리했습니다.

### 구현한 lifecycle

```text
고정 archive 검증
→ ZIP 비추출 inventory
→ 필요한 SQL gzip만 선택 추출
→ gzip CRC·정적 SQL 감사
→ 방어적 SQLite import
→ C/C++ before/after pair 공급량 계산
→ 수동 검토 queue
```

### 자동 공급 결과

- exact before/after method pair: 78,963
- single-CWE pair: 70,589
- C/C++ 후보: 6,248
- raw code/diff를 감사 보고서에 직접 반환하지 않음
- bulk processing/training 승인: false

먼저 읽을 파일:

1. `aegislm/datasets/archive_inventory.py`
2. `aegislm/datasets/sql_dump.py`
3. `aegislm/datasets/sqlite_import.py`
4. `aegislm/datasets/cvefixes_supply.py`
5. `aegislm/datasets/cvefixes_catalog.py`
6. `aegislm/datasets/cvefixes_review.py`

### 확인된 보안 문제

현재 SQLite importer는 사전 감사한 gzip과 실제 import 입력을 경로와
크기로만 비교합니다. 같은 크기의 다른 파일로 교체되는 경우를 막기 위해
import 중 digest를 다시 계산하고 감사 hash와 일치시켜야 합니다. 대형
untrusted SQL parser도 별도 제한 프로세스 또는 컨테이너로 격리해야
합니다.

### 현재 판정

`수정 후 연구 보관`. Archive 감사 도구는 재사용 가치가 있지만 SQL import
보안 보강이 필요하며, CVEfixes label은 다음 커밋에서 품질 gate를
실패했습니다.

---

## Commit 15 — `83ddb76 feat: fail CVEfixes manual label gate`

### 왜 만들었나

commit-level CWE와 before/after 함수가 실제로 같은 취약점 관계를
나타내는지 수동 검토했습니다.

### 결과

- review queue: 200
- 오류 예산: 10
- 28건 검토 시점의 오류·불확실: `11`
- 판정: `FAIL EARLY`
- 남은 172건: 미검토이며 PASS가 아님

먼저 읽을 파일:

1. `aegislm/datasets/cvefixes_review_decision.py`
2. `scripts/prepare_phase_f_cvefixes_manual_review.py`
3. `scripts/evaluate_phase_f_cvefixes_manual_review.py`
4. `docs/experiments/decisions/phase-f/PHASE_F_PATCH_LABEL_SUPPLY_DECISION_20260731.md`

### 현재 판정

`연구 보관`. CVEfixes commit-level CWE를 direct training label로 사용하지
않고 repository license 검토도 중단합니다.

---

## Commit 16 — `5687940 feat: gate Decompile-Bench alignment supply`

### 왜 만들었나

취약점 label 공급과 별도로 source–assembly 정렬 품질을 검사했습니다.

### 결과

- 고정 Arrow shard: 131,359행
- 수동 source–assembly 정렬: `96/100 PASS`
- 다른 함수가 잘못 연결된 오류: 4건
- 명시 repository 복원: 84.6581%
- repository별 license 증거: 불완전
- compiler·optimization metadata: 없음
- vulnerability label: 없음

먼저 읽을 파일:

1. `aegislm/datasets/decompile_bench.py`
2. `aegislm/datasets/decompile_bench_provenance.py`
3. `aegislm/datasets/decompile_bench_review.py`
4. `docs/experiments/decisions/phase-f/PHASE_F_DECOMPILE_BENCH_ALIGNMENT_DECISION_20260731.md`

### 현재 판정

`연구 보관`. Disposition은 `alignment_reference_only`이며
`approved_for_training=false`입니다.

---

## Commit 17 — `047cfb3 feat: audit Assemblage metadata supply`

### 왜 만들었나

Decompile-Bench에 없던 repository, compiler, optimization, architecture,
build trace를 Assemblage metadata가 같은 행에서 제공하는지
검사했습니다.

### 결과

- artifact integrity: PASS
- DuckDB schema: PASS
- 전체 binary metadata: 249,121행
- strict field를 모두 가진 행: `0`
- raw ELF 다운로드: false
- training 승인: false

먼저 읽을 파일:

1. `aegislm/datasets/assemblage_metadata.py`
2. `scripts/inventory_phase_f_assemblage_schema.py`
3. `scripts/audit_phase_f_assemblage_fields.py`
4. `docs/experiments/decisions/phase-f/PHASE_F_ASSEMBLAGE_METADATA_DECISION_20260731.md`

### 현재 판정

`연구 보관`. `metadata_reference_only`입니다.

---

## Commit 18 — `2e32539 docs: gate BinKit metadata supply`

### 왜 만들었나

Compiler·architecture·optimization 변형 benchmark 후보인 BinKit 2.0의
공개 artifact 계약을 문서와 metadata만으로 감사했습니다.

### 결과

- compile matrix 문서: 확인
- immutable code release: 확인
- GitHub release binary asset: 0
- 외부 dataset artifact size·SHA-256: 없음
- dataset license: 불명확
- row/function schema: 불명확
- pickle 다운로드·역직렬화: 0

먼저 읽을 파일:

1. `docs/experiments/decisions/phase-f/PHASE_F_BINKIT_METADATA_DECISION_20260731.md`
2. `configs/phase_f/binary_alignment_supply_preflight_v1.json`

### 현재 판정

`연구 보관`. Disposition은 `metadata_hold`이며 binary와 pickle을
다운로드하지 않습니다.

---

# D. Malware feature benchmark

## Commit 19 — `32c4c62 feat: gate EMBER2024 ELF benchmark`

### 왜 만들었나

LLM SFT와 별도로, raw executable 없이 ELF 정적 특징으로 malware
classifier 절대평가를 할 수 있는지 검사했습니다.

### 결과

- 고정 ELF test ZIP integrity·schema: PASS
- raw executable member: 0
- 원본 행: 12,000
- 동일 `(week_id, sha256)` 중복: 6,000
- 실제 평가 관측치: 6,000
- primary malware/benign label 충돌: 0
- SFT 승인: false
- raw binary 다운로드 승인: false

먼저 읽을 파일:

1. `aegislm/datasets/ember2024.py`
2. `scripts/inventory_phase_f_hf_zip.py`
3. `scripts/audit_phase_f_ember2024_elf_test.py`
4. `docs/experiments/decisions/phase-f/PHASE_F_EMBER2024_BENCHMARK_DECISION_20260731.md`

### 현재 판정

`수정 후 유지` 또는 별도 benchmark PR 후보입니다. Qwen source SFT와
섞지 않고 독립 malware-feature 평가로만 사용합니다.

---

## Commit 20 — `087ad94 feat: evaluate EMBER2024 ELF baseline`

### 왜 만들었나

안전하게 materialize한 EMBER2024 feature로 실제 시간 분리 classifier
절대평가를 수행했습니다.

### 데이터 분할

- fit: weeks 0–43, 22,000건
- calibration: weeks 44–51, 4,000건
- test: weeks 52–63, 6,000건
- calibration label로 threshold를 한 번 고정
- test label을 보고 threshold를 다시 고르지 않음

### 자체 temporal LightGBM 결과

| 지표 | 결과 | 판정 |
| --- | ---: | --- |
| precision | 0.9793 | PASS |
| recall | 0.9293 | PASS |
| FPR | 0.0197 | FAIL |
| 주별 최대 FPR | 0.056 | FAIL |

### 공식 EMBER2024 모델 결과

| 지표 | 결과 | 판정 |
| --- | ---: | --- |
| precision | 0.9002 | FAIL |
| recall | 0.9897 | PASS |
| FPR | 0.1097 | FAIL |
| 주별 최대 FPR | 0.208 | FAIL |

두 모델 모두 낮은 FPR과 주별 안정성 gate를 통과하지 못했습니다.

먼저 읽을 파일:

1. `aegislm/evaluation/malware_classifier.py`
2. `scripts/run_phase_f_ember2024_lgbm_baseline.py`
3. 같은 runner의 `--pretrained-model` 경로
4. `scripts/diagnose_phase_f_malware_threshold.py`
5. `docs/experiments/decisions/phase-f/PHASE_F_EMBER2024_CLASSIFIER_BASELINE_DECISION_20260731.md`

### 현재 판정

`연구 보관`.

- NuriLab static-signal 연결: 승인하지 않음
- Qwen SFT 혼합: 승인하지 않음
- 다음 연구: FP 집중 주차의 feature drift 감사

---

## 3. 리뷰 후 권장 PR 분리

현재 20개 커밋을 그대로 하나의 PR로 병합하지 않습니다. 리뷰 결과에 따라
다음 단위로 재구성하는 것을 권장합니다.

### PR 1 — Source Qwen core

- SARD/Juliet 추출·검증
- source contract
- Q1R10 decision
- Q1R11 evidence
- deterministic renderer
- source 절대평가
- merge·vLLM lifecycle 설정

### PR 2 — Security hardening

- manifest 경로 검증
- compiler·Ghidra 격리
- 환경변수 allowlist
- OpenAI-compatible endpoint 제한
- SQL audit/import digest 결합
- 가상환경·동기화 디렉터리 Git ignore
- 절대경로 대신 root alias·relative path

### PR 3 — Binary research archive

- B0/F7 compile·decompile 실험
- target v1–v9 실패 이력
- role contract v2와 strict v3–v7
- 644-pair `quality-approved / supply-blocked` seed

운영 경로가 아니라 연구·회귀 benchmark임을 디렉터리와 문서에서
명시해야 합니다.

### PR 4 — External dataset audits

- ARVO
- CVEfixes
- Decompile-Bench
- Assemblage
- BinKit

학습 데이터가 아니라 공급 감사 도구와 결정 기록으로 분리합니다.

### PR 5 — EMBER2024 benchmark

- deduplicated temporal benchmark
- classifier evaluator
- 실패 기준선

Qwen SFT 또는 NuriLab 기능과 분리합니다.

---

## 4. 사용자와 함께 볼 첫 번째 코드

첫 코드 리뷰는 Commit 1의 source 부분으로 제한합니다.

```text
scripts/build_sard_juliet_source_dataset.py
→ aegislm/datasets/sard_juliet.py
→ aegislm/datasets/source.py
→ aegislm/datasets/source_decision.py
→ aegislm/datasets/source_evidence_lines.py
→ aegislm/evaluation/source_two_stage.py
```

각 파일은 다음 기준으로 검토합니다.

1. 입력은 무엇인가?
2. 출력은 무엇인가?
3. 모델이 볼 수 있는 정보는 무엇인가?
4. private label은 어디에 보관되는가?
5. 실패하면 학습을 중단하는가?
6. 사람이 이해하기 어려운 부분에 설명이 있는가?
7. 현재 핵심 경로에 반드시 필요한가?

이 검토가 끝난 뒤에만 해당 파일에 역할 중심 주석을 추가합니다. Binary와
외부 데이터 코드는 보존 여부를 먼저 결정하고 나중에 주석을 추가합니다.

Commit 1 리뷰 중 제기된 “기존 analyzer MCP가 절대 gate를 통과하면 해당
능력의 fine-tuning을 생략할 수 있는가”라는 가설은
[로컬 LLM과 분석 MCP 책임 경계 아이디어](../../docs/design/architecture/LOCAL_LLM_MCP_BOUNDARY_IDEA.md)에
별도로 기록했습니다. 아직 채택된 결정이 아닙니다.
