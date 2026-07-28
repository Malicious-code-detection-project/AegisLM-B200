# Phase F 데이터 재설계 및 바이너리 분석 실험 계획

이 문서는 Phase F의 데이터, 학습, 서빙, 평가 순서와 중단 조건을
고정하는 SSOT입니다. 실행 상태와 운영자 기록은
[FINETUNING_TEST_WORKBOOK.md](FINETUNING_TEST_WORKBOOK.md)에 남깁니다.

## 1. Phase E 판정과 연구 질문

Qwen3-Coder-Next 80B LoRA 실험의 인프라 목표는 통과했습니다.

- 332,807건, 10,401 step, 1 epoch 학습 완료
- adapter 저장·재로드와 BF16 merge 완료
- Hugging Face API와 merged vLLM serving 완료
- 5건 smoke와 500건 label-blind 평가 완료

그러나 모델 품질은 실패했습니다.

| 항목 | 결과 |
| --- | ---: |
| TP / FP / TN / FN | `84 / 116 / 0 / 166` |
| Precision | `0.420` |
| Recall | `0.336` |
| FPR | `0.464` |
| Abstention | `0.598` |
| JSON parse / schema | `0.556 / 0.530` |

전체 DiverseVul prompt에 label·target·provenance가 노출됐고 BigVul은
모든 target이 `high`였습니다. 낮은 loss는 실제 보안 분석 능력이 아니라
노출된 label과 반복 target 재현에 수렴한 것으로 판정합니다.

Phase F는 다음을 검증합니다.

1. 정제된 1만~1.2만 건 source data로 절대 gate를 통과할 수 있는가?
2. pseudo-C·정적 특징·제한된 assembly를 사용한 별도 adapter가
   바이너리 분석 절대 gate를 통과할 수 있는가?

## 2. 단계와 책임

| 단계 | 산출물 | 다음 단계 조건 |
| --- | --- | --- |
| F0 | 기존 run 동결, raw catalog | Phase E 증거와 hash 보존 |
| F1 | `phase-f-source-v2` | leakage·중복·group split 검사 통과 |
| F2 | source adapter | 100-step 진단 후 500건 절대 gate |
| F3-B0 | binary 100 pair feasibility | compile/decompile/pair 보존 gate |
| F3-B1 | binary-derived adapter | source와 독립된 binary absolute gate |
| F4 | NuriLab/RAG/MCP 연결 | 앞 단계 adapter가 독립 gate 통과 |

Project NuriLab 또는 승인된 offline extractor는 PE/ELF의 컴파일,
디컴파일, 정적 특징 추출을 담당합니다. AegisLM은 normalized record
계약, 학습 데이터 변환, adapter와 평가를 담당합니다.

Raw byte 직접 학습, byte-level model, live/disarmed malware 실행과 새
아키텍처는 Phase G로 보류합니다.

## 3. 세 계층 데이터 구조

### `raw_catalog.parquet`

원본 payload가 아니라 다음 index만 저장합니다.

- dataset·revision·license·source URI
- source/content/near-duplicate hash
- repository/function/patch group
- 언어, CWE, label task/value/confidence
- target template hash와 token 추정치
- prompt leakage flag
- executable 여부
- `eligible / quarantine / reject`와 사유

### `eligible_manifest.parquet`

선택된 record의 profile, split, group ID, label, representation, disposition을
저장합니다. 같은 repository/function/patch/compiler group은 서로 다른
split에 들어갈 수 없습니다.

### Materialized JSONL

실제 학습·평가 입력만 생성합니다.

- `train.jsonl`
- `validation.jsonl`
- `challenge.jsonl`
- `gold.jsonl`
- `dataset_manifest.json`

Parquet은 GPU 학습 파일이 아니라 감사·분류·표본추출용입니다. 학습
직전에 선택된 record만 JSONL로 materialize합니다.

## 4. Source Dataset v2

설정 정본은 `configs/phase_f/source_v2.json`입니다.

- profile: `phase-f-source-v2`
- seed: `20260728`
- train: DiverseVul positive 5,000 + benchmark-negative 5,000
- validation: 500 + 500
- blind test: 250 + 250
- BigVul: 검증된 before/after·CWE·수정 위치가 있을 때만 최대 2,000 pair
- Cybersecurity QA: code vulnerability SFT에서는 0건

현재 canonical BigVul에는 fixed code body와 충분한 CWE 근거가 없으므로
기본 catalog에서는 `quarantine`입니다. 부족한 BigVul quota는 저신뢰
record로 채우지 않습니다.

`target=0`은 프로그램 전체가 안전하다는 뜻이 아닙니다. “해당 benchmark
target vulnerability가 제공된 함수 범위에서 관찰되지 않음”으로만
해석합니다.

허용되는 변이는 고정 seed 기반 표본, 네 가지 의미 동등 prompt, 순서
shuffle, compiler/optimization 선택뿐입니다. label, risk 의미, CWE,
output schema와 코드 의미는 변경하지 않습니다.

### 빌드

```bash
uv run python scripts/build_phase_f_source_dataset.py \
  --input /approved/data/hf-full-v1/train.jsonl \
  --input /approved/data/hf-full-v1/validation.jsonl \
  --input /approved/data/hf-full-v1/test.jsonl \
  --output-dir /approved/data/phase-f-source-v2
```

예상 결과:

```text
raw_catalog.parquet
eligible_manifest.parquet
train.jsonl
validation.jsonl
challenge.jsonl
gold.jsonl
dataset_manifest.json
```

코드와 executable payload는 catalog Parquet에 저장하지 않습니다.
동일 입력·seed로 재실행하면 manifest와 JSONL의 논리 내용이 같아야
합니다.

## 5. Model-visible 경계

Source v1 output contract는 F2까지 유지해 데이터 변경 효과를 분리합니다.
다만 prompt formatter는 다음을 모델에 전달하지 않습니다.

- record ID
- source object와 dataset 이름
- metadata, split, notes
- target, label, gold, expected output

모델에게 전달되는 것은 task, code context, 관찰 가능한 정적 signal뿐입니다.
`aegislm.datasets.phase_f.assert_no_model_visible_leakage()`가 materialization
단계에서 이를 검사합니다.

## 6. Source adapter 실험

| Run | 모델 | 실행 | 진행 조건 |
| --- | --- | --- | --- |
| S0 | base model | 500건 평가 | 실패 기준선 보관 |
| S1 | `openai/gpt-oss-20b` | 100 step | 진단 gate |
| S2 | 동일 20B | 최대 1 epoch | 500건 absolute |
| S3 | Qwen3-Coder-Next 80B | 100 step | save/reload/serve 포함 진단 gate |
| S4 | 동일 80B | 250 step, 최대 1 epoch | 최종 absolute |

Global batch 32일 때 10,000~12,000건은 약 313~375 step입니다. 한
epoch를 넘기지 않습니다.

100-step 진단 gate:

- 누락 0
- parse/schema ≥ 0.99
- safety = 1.00
- abstention ≤ 0.10
- precision·recall ≥ 0.75
- FPR ≤ 0.20
- positive·negative prediction 모두 존재
- 반복·비정상 길이 ≤ 0.01
- checkpoint save/reload와 실제 serving 요청 성공

최종 500건 absolute gate:

- precision ≥ 0.90
- recall ≥ 0.95
- FPR ≤ 0.05
- abstention ≤ 0.05
- parse/schema ≥ 0.99
- safety = 1.00
- evidence ≥ 0.90

20B canary가 실패하면 80B full run으로 넘어가지 않습니다.

## 7. Binary-derived contract와 B0

“바이너리 데이터”는 raw executable byte가 아니라 다음 안전한 파생
표현입니다.

- pseudo-C/decompiler output
- imports, sections, strings, symbols
- 근거에 필요한 제한된 assembly
- format, architecture, compiler, optimization, stripped

`aegislm.binary-analysis-record.v1`은 artifact hash와 외부 참조를
보존하지만 prompt formatter는 hash, 외부 경로, dataset, label, split을
제외합니다. `raw_bytes`, `byte_dump`, `payload`, executable content key는
validation에서 거부합니다.

B0는 build 가능한 before/after 100 pair, 총 200 함수를 대상으로 합니다.

| Gate | 기준 |
| --- | ---: |
| compile 성공률 | ≥ 0.90 |
| decompile 성공률 | ≥ 0.90 |
| source–binary–function 연결 | ≥ 0.95 |
| target CWE·patch 위치 보존 | 필수 |
| raw payload prompt 유입 | 0 |
| label·dataset·split 유입 | 0 |

B0 실패 시 binary adapter를 학습하지 않습니다.

## 8. Binary Dataset v1과 평가

B0 통과 후 검증된 2,000 patch pair를 목표로 합니다.

- before 2,000: `present`
- after 2,000: `not_observed`
- train 최대 4,000
- validation 400
- blind test 500
- train compiler: GCC·Clang, `O0/O2`
- robustness: 학습에 없는 `O3 + stripped`
- consistency: 같은 함수 100건의 compiler variant

2,000 pair를 확보하지 못하면 낮은 신뢰도의 record로 채우지 않고
B0 보고서까지만 보존합니다.

Binary output은 `aegislm.binary-assessment-output.v1`을 사용합니다.

- `scope`: target CWE, format, architecture
- `assessment`: `present / not_observed / uncertain`
- `findings`: function ID, representation, observation, confidence
- `limitations`
- `recommendations`

Source와 같은 absolute gate에 다음을 추가합니다.

- compiler consistency ≥ 0.95
- observable evidence linkage ≥ 0.90
- provenance/source symbol 의존 근거 0
- raw byte·실행 payload 출력 0

Source와 binary adapter는 별도로 학습합니다. 둘 다 독립 gate를 통과한
뒤에만 multitask/adapter composition을 실험합니다.

Normalized B0/B1 JSONL을 준비한 뒤의 추론·평가 명령:

```bash
uv run python scripts/run_binary_inference.py \
  --dataset /approved/data/phase-f-binary-derived-v1/challenge.jsonl \
  --predictions /approved/artifacts/binary-run/predictions.jsonl \
  --model-id aegislm-binary-adapter \
  --run-id phase-f-binary-b1 \
  --base-url http://127.0.0.1:8000/v1

uv run python scripts/evaluate_binary_challenge.py \
  --dataset /approved/data/phase-f-binary-derived-v1/challenge.jsonl \
  --predictions /approved/artifacts/binary-run/predictions.jsonl \
  --summary-json /approved/artifacts/binary-run/summary.json
```

## 9. Dataset 후보

| 후보 | Phase F 용도 |
| --- | --- |
| BigVul buildable pair | target CWE before/after 우선 후보 |
| [Assemblage](https://assemblage-dataset.net/) | source–binary 정렬과 compiler variant |
| [Decompile-Bench](https://arxiv.org/abs/2505.12668) | source–binary–decompile representation |
| [BinKit 2.0](https://github.com/SoftSec-KAIST/BinKit) | compiler·architecture 강건성 |
| [LLM4Decompile](https://github.com/albertan017/LLM4Decompile) | representation·decompilation 참고 |
| [EMBER2024](https://github.com/FutureComputing4AI/EMBER2024) | metadata-only malware benchmark |

SOREL-20M full download, BODMAS raw binary, BIG 2015는 용량·라이선스·
payload 처리 계획이 생길 때까지 보류합니다.

## 10. NuriLab 연결 순서

```text
source adapter
→ binary-derived adapter
→ NuriLab normalized signal
→ source+binary multitask
→ signals+RAG
→ signals+RAG/MCP
```

각 단계는 독립 absolute gate를 적용합니다. 앞 단계 실패를 후속 도구
연결로 가리지 않습니다.

## 11. 자동 검사와 중단

자동 검사:

- exact/near duplicate와 group leakage
- model-visible label/provenance
- template-label 상관
- seed 재현성
- raw executable/byte dump
- before/after split 분리
- canonical → JSONL → serving 왕복
- save → reload → serve → evaluate

즉시 중단:

- prompt leakage 발견
- checkpoint 저장·재로드 실패
- GPU당 peak VRAM 약 165 GiB 초과
- 누락·반복 출력 5% 초과
- negative prediction 0으로 붕괴
- 두 평가 지점 연속 개선 없음
- 12시간 이상 checkpoint·평가 없이 지속
- binary pair/CWE 정렬 실패

## 12. 구현 확인

```bash
uv run pytest tests/test_phase_f_dataset.py tests/test_binary_contract.py
uv run ruff check .
uv run ruff format --check .
uv run mypy aegislm/ tests/
```

현재 구현은 catalog/manifest Parquet, source profile materialization,
prompt leakage 차단, binary input/output schema와 binary absolute evaluator를
포함합니다. 실제 compiler/decompiler 실행과 raw binary 관리는 NuriLab
또는 승인된 offline extractor의 후속 구현입니다.
