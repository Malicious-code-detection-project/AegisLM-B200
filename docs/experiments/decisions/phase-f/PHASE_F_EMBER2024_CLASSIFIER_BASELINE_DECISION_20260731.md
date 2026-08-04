# Phase F EMBER2024 ELF Classifier 절대평가 결정

## 결정

EMBER2024 ELF 정적 특징은 안전하게 materialize하고 독립 classifier로
평가할 수 있었지만, 현재 두 모델 모두 사전 등록한 시간 분리 절대 gate를
통과하지 못했다.

- 자체 temporal LightGBM: `absolute_gate_fail`
- 공식 EMBER2024 ELF 공개 모델: `absolute_gate_fail`
- NuriLab static-signal 연결 승인: `false`
- Qwen SFT 혼합 승인: `false`
- raw executable 다운로드·실행: `false`

따라서 이 결과를 AegisLM 또는 NuriLab의 malware 판정 신호로 채택하지
않는다. 다음 작업은 연결 구현이 아니라 시간 변화에 따른 FP 증가와
feature drift를 분석하는 것이다.

## 데이터와 재현 계약

| 항목 | 값 |
| --- | --- |
| dataset | `joyce8/EMBER2024` |
| dataset revision | `3d23efef7c0f0b702c5024400cfff4c3744a3832` |
| train archive | `ELF_train.zip`, 52 weekly JSONL |
| train archive SHA-256 | `dd22c65c1a4b6b1c0680717814c74c1569256cf4ef6e7629c1b2b94b8e11afe3` |
| train observations | raw 52,000 → deduplicated 26,000 |
| test observations | raw 12,000 → deduplicated 6,000 |
| fit / calibration / test | weeks 0–43 / 44–51 / 52–63 |
| fit / calibration / test count | 22,000 / 4,000 / 6,000 |
| train materialization manifest | `a02100e4494a3a665afd731244afe04c55e4a6aaf3539e32b7171eeb835be71d` |
| test materialization manifest | `a2eecfcf41b1bee4c1b46e32d4fd90e3712a278fd959d80d36cecf71d7c6b773` |

materialized feature JSONL에는 `label`, file hash, provenance를 넣지 않았고
별도 gold JSONL에 `observation_id`, `label`, `week_id`, file hash만
보관했다. train은 classifier 학습 전용이고 test는 평가 전용이다. 둘 다
Qwen SFT 입력으로 승인하지 않았다.

## 절대 gate

calibration weeks에서 recall이 가장 높으면서 FPR이 1% 이하인 threshold를
한 번 고정하고, 이후 test weeks에 그대로 적용했다.

| 지표 | Gate |
| --- | ---: |
| precision | ≥ 0.95 |
| recall | ≥ 0.90 |
| FPR | ≤ 0.01 |
| ROC AUC | ≥ 0.95 |
| average precision | ≥ 0.95 |
| 주별 최소 recall | ≥ 0.80 |
| 주별 최대 FPR | ≤ 0.02 |
| prediction 누락·초과 | 0 |

## 자체 temporal LightGBM 결과

고정 500-round LightGBM을 weeks 0–43의 22,000건으로 학습하고 weeks
44–51의 4,000건으로 threshold를 정했다. 별도 `.venv-ember-eval`을
사용했으며 Qwen 학습·서빙 환경은 변경하지 않았다.

| 항목 | 결과 | 판정 |
| --- | ---: | --- |
| calibration threshold | `0.9873143465` | 고정 |
| calibration FPR / recall | `0.0100 / 0.9260` | threshold 선택 |
| test precision | `0.979276` | PASS |
| test recall | `0.929333` | PASS |
| test FPR | `0.019667` | **FAIL** |
| ROC AUC | `0.985425` | PASS |
| average precision | `0.987340` | PASS |
| 주별 최소 recall | `0.844` | PASS |
| 주별 최대 FPR | `0.056` | **FAIL** |
| prediction completeness | `6,000/6,000` | PASS |

FP는 week 57에서 14건(FPR 5.6%), week 61에서 13건(FPR 5.2%)으로
집중됐다. 총 confusion matrix는 TP 2,788, FP 59, TN 2,941, FN 212다.

test label을 보고 사후 선택한 threshold는 배포에 사용할 수 없으므로
진단용으로만 계산했다. 이 oracle 조건에서도 FPR 1%일 때 recall은
87.53%로 recall gate 90%를 넘지 못했다. 따라서 자체 모델의 실패는
threshold calibration만 다시 하면 해결되는 문제가 아니다.

### 자체 모델 artifact

- model SHA-256:
  `411e36fb161f0551a1e53001d63018f2b198e679de86b74a73487d8a54a5c51c`
- calibration prediction SHA-256:
  `fff6ce2caa94cc0cfae34140122ca8e1c16191baf4867fa6126928e972c4e194`
- test prediction SHA-256:
  `fda3ea237e3658c9bc135ed0f1b7c4e1c9b201816f8b2977791bae9e9e617e9c`
- evaluation report SHA-256:
  `7280272204e5682a3d3a3b653cf2920d6fd1fa3ab4db3ced699b2334ac0b720f`
- environment freeze SHA-256:
  `86a6319d3fdf05fcc989fe8ea74e57e9ea94d0f8676320f9db1adf249b1a98a7`
- 관찰한 wall time: 약 77분, CPU 16개 thread 사용

## 공식 공개 모델 통제 실험

고정된 공식 `EMBER2024_ELF.model`을 같은 feature materialization과 같은
절대 gate로 평가했다.

| 항목 | 결과 | 판정 |
| --- | ---: | --- |
| model SHA-256 | `8e407293…b9c43` | exact match |
| calibration threshold | `0.0401578651` | 고정 |
| calibration FPR / recall | `0.0045 / 0.9995` | 참고 |
| test precision | `0.900243` | **FAIL** |
| test recall | `0.989667` | PASS |
| test FPR | `0.109667` | **FAIL** |
| ROC AUC | `0.992900` | PASS |
| average precision | `0.992962` | PASS |
| 주별 최소 recall | `0.980` | PASS |
| 주별 최대 FPR | `0.208` | **FAIL** |

공식 모델의 학습 분할은 이 프로젝트의 독립 calibration 계약과 같다고
가정할 수 없으므로 calibration 결과를 채택 근거로 쓰지 않는다. test
oracle에서는 FPR 1%에서 recall 91.4%로 aggregate gate를 만족했지만,
주별 최대 FPR은 4.8%여서 주별 gate를 통과하지 못했다. 이 oracle
threshold 역시 test label을 사용했으므로 배포 승인이 아니다.

- evaluation report SHA-256:
  `f4990838a3ed78292798e08ad89ae8f3df85518b675c9ed8e50f3584cc79d7c5`
- test prediction SHA-256:
  `d1684fd6edc9d53afc8e0eb3d7c4997162a091cea31369b75f6e21d4c0968ee8`

## 구현 호환성 기록

고정 `thrember` 소스는 `StringExtractor.dim`에서 string-count 차원을
76으로 선언하지만 실제 정규식 key는 77개다. 반대로 선언식의 scalar
항목은 실제 출력보다 1개 많아 두 차이가 상쇄되고 최종 벡터 길이는 공식
선언과 같은 2,568이다.

서버에서 `thrember`를 직접 import하면 `signify/oscrypto`가 시스템
`libcrypto`를 감지하지 못했다. 시스템 OpenSSL을 변경하지 않고 고정
`features.py`를 AST로 읽어 공식 string key 순서를 복구했으며, ELF에
공통인 general·byte histogram·byte-entropy histogram·string feature
696차원 뒤 PE-only 1,872차원을 0으로 채웠다. raw executable은 읽거나
실행하지 않았다.

## 해석과 다음 gate

1. AUC와 average precision만 높다고 상용 gate를 통과한 것은 아니다.
   낮은 허용 FPR과 주별 안정성이 실제 차단 원인이다.
2. 자체 모델은 test oracle에서도 aggregate recall/FPR 동시 gate를
   만족하지 못했다. 단순 threshold 조정으로 진행하지 않는다.
3. 공식 모델은 aggregate ranking 여지는 보였지만 calibration과 주별
   안정성이 실패했다. 공식 모델을 바로 NuriLab 신호로 쓰지 않는다.
4. 다음 실험은 FP가 집중된 weeks 56·57·59·61의 label-blind feature
   drift와 FP/FN 원인을 감사한다.
5. drift 근거가 확인된 경우에만 더 최근 week를 fit에 포함하고 독립
   calibration을 유지하는 temporal remediation 1회를 사전 등록한다.
6. 그 재실행도 동일 gate를 통과하지 못하면 EMBER2024 ELF static-feature
   경로는 `research_hold`로 종료한다.

## 근거

- [EMBER2024 repository](https://github.com/FutureComputing4AI/EMBER2024)
- [공식 LightGBM 설정](https://github.com/FutureComputing4AI/EMBER2024/blob/0ef753e81d98bf209f71b03cd331dfc190b5b54d/examples/lgbm_config.json)
- [공식 평가 코드](https://github.com/FutureComputing4AI/EMBER2024/blob/0ef753e81d98bf209f71b03cd331dfc190b5b54d/examples/eval_lgbm.py)
- [EMBER2024 dataset](https://huggingface.co/datasets/joyce8/EMBER2024)
- [EMBER2024 paper](https://arxiv.org/abs/2506.05074)
