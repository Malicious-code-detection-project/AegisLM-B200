# AegisLM 절대평가 테스트 환경

## 목적

파인튜닝의 성공 여부는 학습 loss나 base model 대비 상대 점수가 아니라, 정답 단서가 없는 보안 코드에서 사전에 정한 품질 기준을 통과하는지로 판단합니다.

첫 번째 테스트 환경의 범위는 다음과 같습니다.

```text
정규화된 test split
-> label-blind challenge + 별도 gold 생성
-> LoRA adapter를 OpenAI-compatible API로 서빙
-> 고정된 challenge에 temperature 0으로 추론
-> 절대 품질 gate 판정
-> JSON + HTML 결과 보존
```

이 테스트는 AegisLM 자체의 source-code 분석 능력만 확인합니다. Project NuriLab, RAG, MCP, LangChain/LangGraph는 연결하지 않습니다. 이 상태에서 기준을 넘지 못하면 외부 검색이나 도구 연결이 모델 자체의 부족을 가릴 수 있기 때문입니다.

## 현재 v1의 한계

- v1 challenge는 현재 정규화 데이터에서 양성과 음성을 모두 제공하는 DiverseVul만 사용합니다.
- BigVul은 현재 변환본이 취약 코드만 제공하고 일부 patch-pair 무결성 문제가 있어 binary classification gold로 사용하지 않습니다.
- 이 평가는 C/C++ 함수 excerpt의 취약성 분류와 설명을 측정합니다.
- 악성코드 실행파일, 바이너리, 동적 분석, Python·Java·Rust 등 다언어 능력은 아직 증명하지 않습니다.
- label 자체도 공개 데이터셋의 주석이므로, 운영 환경의 취약점 확정 판정으로 간주하지 않습니다.

## 1. Challenge 생성

학습 데이터와 test 데이터의 exact source hash를 비교해 중복을 제외합니다. 모델 입력 파일에는 원본 데이터셋 이름, source URL, `target`, `label`, `expected_output`, code hash를 넣지 않습니다. 정답 파일은 추론 프로세스에서 읽지 않습니다.

```bash
.venv/bin/python scripts/build_blind_code_challenge.py \
  --test-dataset data/processed/hf-full-v1/aegislm_security_test.jsonl \
  --train-dataset data/processed/hf-full-v1/aegislm_security_train.jsonl \
  --challenge-output artifacts/evaluation/blind-code-v1/challenge.jsonl \
  --gold-output artifacts/evaluation/blind-code-v1/gold.jsonl \
  --per-class 250 \
  --seed 20260727
```

기본 평가 규모는 취약 250건, 정상 250건으로 총 500건입니다. `challenge.jsonl`과 `gold.jsonl`은 같은 실험의 한 쌍으로 보존하되, 추론 runner에는 challenge만 전달합니다.

## 2. Adapter 서빙

현재 학습이 끝나고 최종 adapter가 저장된 뒤 실행합니다. 아래 명령은 vLLM의 OpenAI-compatible server와 LoRA startup loading 방식을 사용한 기준 명령입니다. 설치된 vLLM 버전에서 `vllm serve --help`와 모델 지원 여부를 먼저 확인합니다.

```bash
CUDA_VISIBLE_DEVICES=0,1 vllm serve model/base/qwen3-coder-next \
  --tensor-parallel-size 2 \
  --dtype bfloat16 \
  --enable-lora \
  --max-lora-rank 8 \
  --lora-modules aegislm-qwen3-coder-next=training_artifacts/qwen3-coder-next/lora/full
```

서버가 준비되면 모델 목록에 adapter 이름이 나타나는지 확인합니다.

```bash
curl -s http://127.0.0.1:8000/v1/models
```

vLLM은 `/v1/chat/completions`를 제공하며, `--lora-modules name=path`로 등록한 이름을 request의 `model` 값으로 사용합니다. 정확한 option은 사용 중인 vLLM 버전의 공식 문서를 기준으로 합니다.

## 3. 고정 추론

API key를 설정한 경우에만 환경 변수로 전달합니다. key 자체는 command, prediction metadata, Git에 기록하지 않습니다.

```bash
.venv/bin/python scripts/run_adapter_inference.py \
  --backend openai-compatible \
  --base-url http://127.0.0.1:8000/v1 \
  --dataset artifacts/evaluation/blind-code-v1/challenge.jsonl \
  --predictions artifacts/evaluation/blind-code-v1/predictions.jsonl \
  --model-id aegislm-qwen3-coder-next \
  --run-id blind-code-v1-20260727 \
  --temperature 0 \
  --max-new-tokens 1024 \
  --request-timeout 300
```

## 4. 절대 기준 판정

기본 gate는 다음과 같습니다.

| 항목 | 통과 기준 |
| --- | ---: |
| 전체 표본 | 200건 이상 |
| prediction 완전성 | 누락·초과 0건 |
| precision | 0.90 이상 |
| recall | 0.95 이상 |
| false positive rate | 0.05 이하 |
| abstention rate | 0.05 이하 |
| JSON parse 성공률 | 0.99 이상 |
| output schema 통과율 | 0.99 이상 |
| safety 통과율 | 1.00 |
| evidence 포함률 | 0.90 이상 |

`risk_level`의 `high`와 `critical`은 취약, `low`는 정상으로 판정합니다. `medium`과 `unknown`, JSON/schema 오류, unsafe output은 기권으로 처리합니다. 취약 샘플에서의 기권은 recall을 낮추므로 위험한 미탐을 숨길 수 없습니다.

```bash
.venv/bin/python scripts/evaluate_absolute_challenge.py \
  --gold artifacts/evaluation/blind-code-v1/gold.jsonl \
  --predictions artifacts/evaluation/blind-code-v1/predictions.jsonl \
  --summary artifacts/evaluation/blind-code-v1/summary.json \
  --report artifacts/evaluation/blind-code-v1/report.html \
  --fail-on-gate
```

`--fail-on-gate`를 빼면 FAIL이어도 리포트를 만든 뒤 exit code 0으로 종료합니다. 초기 진단에서는 리포트를 먼저 보고, 자동화 단계에서는 이 옵션을 사용합니다.

## 결과 해석

- **PASS**: 현재 C/C++ blind-code challenge 범위에서는 파인튜닝 모델을 다음 평가 단계로 진행할 근거가 있습니다.
- **FAIL**: loss 수렴과 관계없이 현재 adapter를 보안 분석 모델로 채택할 근거가 부족합니다.
- **PASS도 상용화 증명은 아님**: 이후 독립 데이터셋, CWE별 slice, 프로젝트 단위 split, 다언어·바이너리/NuriLab 연동 평가가 필요합니다.

base model 비교는 원인 분석용 보조 실험으로만 사용합니다. 최종 채택 여부는 이 절대 gate로 결정합니다.

## 재현성 기록

각 run에는 다음을 함께 기록합니다.

- base model 경로와 revision
- adapter 경로와 checkpoint 또는 training run ID
- challenge seed, 표본 수, challenge/gold SHA-256
- vLLM, CUDA, PyTorch 버전
- GPU 종류와 수
- inference command와 평가 threshold
- prediction JSONL, summary JSON, HTML report

대용량 결과와 adapter는 Git 밖의 artifact 경로에 보관합니다.

## References

- [vLLM OpenAI-Compatible Server](https://docs.vllm.ai/en/latest/serving/online_serving/openai_compatible_server/)
- [vLLM LoRA Adapters](https://docs.vllm.ai/en/latest/features/lora/)

## Phase F 확장

기존 v1은 C/C++ source challenge 전용입니다. Phase F binary-derived
평가는 기존 risk-level contract를 재사용하지 않고
`aegislm.binary-assessment-output.v1`을 사용합니다.

- assessment: `present / not_observed / uncertain`
- positive finding은 function ID와 pseudo-C/assembly/static-feature 근거 필요
- compiler group별 assessment consistency ≥ 0.95
- label, dataset, split, artifact path/hash는 prompt에서 제외
- raw bytes와 executable payload는 입력·출력 모두 금지

구현은 `aegislm/evaluation/binary.py`에 있으며 source와 binary adapter를
별개의 absolute result로 기록합니다.
