# Phase F EMBER2024 ELF Static-Feature Benchmark Gate 결정

## 결정

EMBER2024의 고정 ELF test artifact를 raw executable 없이 독립
malware static-feature 절대평가에 사용할 수 있다. 단, 공식 archive의
12,000개 JSONL 행을 그대로 12,000개 표본으로 세지 않고
`(week_id, sha256)`로 중복 제거한 6,000개 관측치만 materialize한다.

- archive integrity·safety inventory: `PASS`
- JSONL schema·feature-shape audit: `PASS`
- primary binary label consistency: `PASS`
- static-feature duplicate consistency: `PASS`
- deterministic deduplication: `REQUIRED`
- final disposition: `independent_benchmark_with_required_dedup`
- `approved_for_benchmark_materialization=true`
- `approved_for_sft_training=false`
- `approved_for_raw_binary_download=false`

이 결정은 Qwen source/binary adapter 학습 데이터를 승인한 것이 아니다.
EMBER2024는 별도 malware-feature benchmark이며 source CWE 절대평가와
점수를 합치지 않는다.

## 고정한 공급 계약

| 항목 | 값 |
| --- | --- |
| upstream dataset | `joyce8/EMBER2024` |
| fixed revision | `3d23efef7c0f0b702c5024400cfff4c3744a3832` |
| artifact | `ELF_test.zip` |
| artifact bytes | `16,763,975` |
| artifact SHA-256 | `c86fa72164d7ac5d47ac4798d27b65978402f39f8cad0b2186b01ba55d528bfe` |
| license | Apache-2.0 |
| archive members | 12 weekly JSONL files |
| uncompressed bytes | `52,676,217` |
| raw executable members | 0 |
| raw JSONL rows | `12,000` |
| primary labels | benign `6,000`, malware `6,000` |
| post-dedup observations | `6,000` |
| evaluation weeks | week ID 52–63 |

archive는 추출하지 않고 ZIP member stream으로 읽었다. 개별 파일 hash,
feature vector, raw payload는 감사 JSON에 내보내지 않았다.

## 원본 중복 발견과 처리

공식 artifact는 각 주차에 1,000행을 포함하지만 동일
`(week_id, sha256)` 관측치가 500개씩 한 번 더 나타난다.

- within-week duplicate rows: `6,000`
- post-dedup observations: `6,000`
- unique file SHA-256: `5,989`
- 여러 주차에 다시 등장한 file hash group: `11`
- primary label conflict: `0`
- static-feature conflict: `0`
- 완전한 record 차이가 있는 duplicate observation: `1,268`

완전한 record 차이는 `caps` 1,263건, `mbc` 1,235건, `ttps` 1,111건에서
발생했다. static feature와 binary `label`은 일치하지만 보조 annotation이
한쪽 행에만 들어 있다. 따라서 다음 규칙을 적용한다.

1. binary malware/benign 평가 단위는 `(week_id, sha256)`다.
2. 동일 평가 단위의 static feature 또는 primary label이 충돌하면
   materialization을 중단한다.
3. 여러 주차에 재등장한 같은 file hash는 시간별 관측치로 유지하되,
   hash-level aggregate도 함께 보고한다.
4. CAPS/MBC/TTP와 기타 보조 label은 merge 계약을 별도로 만들기 전까지
   평가 target으로 사용하지 않는다.
5. 원본 12,000행을 중복 제거 없이 사용한 점수는 유효한 결과로 인정하지
   않는다.

## 실행 기록

```bash
uv run python scripts/inventory_phase_f_hf_zip.py \
  --archive data/raw_data/ember2024/3d23efef7c0f0b702c5024400cfff4c3744a3832/ELF_test.zip \
  --config configs/phase_f/ember2024_elf_test_inventory_v1.json \
  --output data/processed/phase-f-ember2024-elf-test-v1/archive-inventory.json

uv run python scripts/audit_phase_f_ember2024_elf_test.py \
  --archive data/raw_data/ember2024/3d23efef7c0f0b702c5024400cfff4c3744a3832/ELF_test.zip \
  --inventory data/processed/phase-f-ember2024-elf-test-v1/archive-inventory.json \
  --expected-records 12000 \
  --expected-materialized-records 6000 \
  --output data/processed/phase-f-ember2024-elf-test-v1/benchmark-audit.json
```

Evidence hash:

- archive inventory:
  `99ca5beccd2e5bcab32b3714cb635bc6b528faa458500190adc995d66ce96e9c`
- benchmark audit:
  `f37ae45b619ad2274827ebba2d37c9a06f8448406b4dc9e4c6cba639ca618a8e`
- raw executable read / execution: `0 / 0`
- feature vector export: `0`

## NuriLab 연결 판단

EMBER2024는 LLM prompt용 pseudo-C가 아니라 정적 특징 벡터와 malware
label이다. 따라서 첫 활용 위치는 AegisLM SFT가 아니라 NuriLab의
deterministic feature pipeline 또는 별도 classifier benchmark다.

권장 순서는 다음과 같다.

1. deduplicated 6,000관측치의 binary malware/benign classifier 절대평가
2. 주차별 precision·recall·FPR과 hash-level aggregate 기록
3. NuriLab normalized static-signal contract로 변환
4. 통과한 deterministic signal만 AegisLM의 근거 입력 후보로 검증

LLM이 수치 feature vector를 직접 설명하도록 만드는 실험은 별도
formatter·근거 계약과 사람 검토 gate 없이는 시작하지 않는다.

## 다음 단계

1. [완료] `(week_id, sha256)` 중복 제거 materializer와 재현 hash 구현
2. [완료] train 26,000건·test 6,000건의 label·주차 계약 검증
3. [실패] 자체 temporal LightGBM과 공식 모델의 6,000건 절대평가
4. [차단] NuriLab static-signal 연결과 Qwen SFT 혼합
5. [다음] FP 집중 주차의 label-blind feature drift·오류 원인 감사

실제 classifier 결과와 다음 중단 기준은
[EMBER2024 classifier 결정문](PHASE_F_EMBER2024_CLASSIFIER_BASELINE_DECISION_20260731.md)에
보존한다.

## 근거

- [EMBER2024 repository](https://github.com/FutureComputing4AI/EMBER2024)
- [EMBER2024 dataset](https://huggingface.co/datasets/joyce8/EMBER2024)
- [EMBER2024 paper](https://arxiv.org/abs/2506.05074)
