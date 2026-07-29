# AegisLM

## AegisLM-B200 Profile

This repository adds a reproducible two-GPU B200 profile for full-dataset
LoRA training of `Qwen/Qwen3-Coder-Next`. It pins LlamaFactory v0.9.5 as a
submodule, locks the training stack with `uv`, separates persistent model/data
storage, and mirrors the latest complete checkpoint without signaling the
trainer.

Start with [docs/B200_2GPU_SETUP.md](docs/B200_2GPU_SETUP.md) and hand training
control to the operator with
[docs/B200_TRAINING_HANDOFF.md](docs/B200_TRAINING_HANDOFF.md).

`AegisLM`은 Project NuriLab과 연계할 수 있는 별도 LLM 모델 개발 프로젝트입니다.

이 저장소는 보안 분석 시스템 자체를 구현하기보다, 보안 분석에 특화된 로컬 LLM을 학습, 평가, 개선하는 데 집중합니다. Project NuriLab이 분석 파이프라인과 운영 시스템을 담당한다면, AegisLM은 그 시스템에 연결될 수 있는 모델, 어댑터, 데이터셋, 평가 방법을 준비합니다.

## 왜 별도 프로젝트인가

LLM 모델 개발은 분석 파이프라인 구현과 다른 속도로 움직입니다. 학습 데이터, GPU 환경, 모델 체크포인트, 평가 기준, 안전 정책은 별도의 실험 관리가 필요합니다.

따라서 이 프로젝트는 Project NuriLab의 코드 구조나 릴리스 일정에 종속되지 않고, 모델 개발 관점에서 독립적으로 실험을 축적합니다.

## 핵심 목표

- 로컬 LLM 파인튜닝 실험
- LoRA / QLoRA 기반 학습 경로 검증
- 보안 분석 특화 데이터셋 구성과 정제
- JSON 구조화 출력 학습
- 모델 출력 품질 평가 harness 준비
- 장기적으로 보안 분석 특화 LLM 모델 직접 구축

## 현재 초점

현재 저장소 단계는 **Phase F: 데이터 재설계 + adapter 복구 실험**입니다.

Phase E에서는 Qwen3-Coder-Next 80B LoRA를 학습하고 adapter 저장·재로드,
merge, vLLM serving, 5건 smoke와 500건 절대평가까지 완료했습니다. 인프라
경로는 통과했지만 500건 품질 gate는 실패했습니다. Phase F에서는
label·provenance 누출과 반복 target을 제거하고 1만~1.2만 건의 균형 잡힌
source dataset부터 다시 검증합니다.

현재 주 실험 모델은 Phase E와 동일한 `Qwen/Qwen3-Coder-Next` 80B입니다.
먼저 정제 데이터에서 base와 기존 Phase E adapter를 각각 절대평가하고,
그 다음 새 LoRA를 base에서 100 step 학습합니다. 진단 gate를 통과한
경우에만 250 step, 필요하면 1 epoch(약 313 step)까지 이어갑니다.
`openai/gpt-oss-20b`는 Qwen 실험 결론 이후 파이프라인 이식성을 확인하는
보조 후보이며 Qwen 재학습의 선행 조건이 아닙니다.

2026-07-29 감사에서 현재 `phase-f-source-v2`는 분할·중복·누출 검사는
통과했지만 정답 표현 반복과 2,048-token 초과 사례가 발견됐습니다. 따라서
현재 materialization은 학습 승인본이 아니라 재설계 대상입니다.

F1 raw catalog에 이어 group-first pool, 보안 범주화, category sampling,
reserve와 cross-dataset holdout 구현 및 full materialization 감사를
완료했습니다. 최종 `phase-f-source-v2-r2`는 train 10,000건,
validation 1,000건, blind test 500건, BigVul·PrimeVul cross-dataset
test 각 200건과 reserve 272,904건으로 고정했습니다. Language는
분류·샘플링·프롬프트·품질 gate에서
제외하고, 원본이 제공한 값만 감사 metadata로 보존합니다. Phase F의
핵심은 언어명을 맞히는 것이 아니라 코드·pseudo-C·정적 특징에서 위험한
연산, 데이터 흐름, API 사용과 악성 행위 패턴을 근거로 찾는 것입니다.

v0 단계에서는 악성코드 유사 스크립트 동작 설명, 취약점 맥락 요약, CTI 메타데이터 정리, ATT&CK 매핑, 위험도 우선순위화를 JSON 형식으로 생성하는 모델을 목표로 합니다.

모델은 최종 보안 판단자가 아닙니다. 판단 근거는 deterministic analyzer, rule signal, curated evidence에 두고, 모델은 설명, 요약, 매핑, 보고서 구조화를 담당합니다.

## 개발 로드맵

**Phase A: 문서/저장소 정체성 정리 (완료)**

이 프로젝트는 Project Nurilab : 로컬 LLM 기반 악성코드 분석 자동화 시스템 개발 프로젝트에서 `로컬 LLM 파인 튜닝 또는 LLM 모델링` 부분을 담당하는 프로젝트입니다. `README.md`, `AGENTS.md`, `docs/CONTRIBUTING.md`의 방향성은 이 기준에 맞춰 정리했습니다.


**Phase B: 최소 코드 뼈대 생성 (완료, 최초 push 준비)**

학습 코드를 바로 크게 만들기보다, 데이터, 평가, 학습, 추론의 책임 경계를 나누는 얇은 scaffold를 만듭니다. 이 단계의 목표는 전체 구조를 이해할 수 있는 최소 패키지와 디렉터리 구조를 만드는 것입니다. 실제 학습 방식, notebook/script/config 중심 선택, TRL/Unsloth 우선순위는 Phase B 이후에 결정합니다.

**Phase C: 데이터 전략 + JSON schema + tiny dataset (완료)**

데이터 활용 전략을 먼저 정리한 뒤 모델이 생성해야 할 JSON output contract를 코드와 문서 양쪽에서 고정하고, 5-20개 수준의 작은 synthetic 또는 metadata-only 학습 예시를 준비합니다. 이 단계에서는 대형 데이터셋, 실제 악성 샘플, GPU 학습, RAG embedding index 생성을 다루지 않습니다.

**Phase D: baseline inference + evaluation (완료)**

초기 scaffold에서는 `openai/gpt-oss-20b`를 기준 모델로 가정해 baseline
inference와 평가 구조를 마련했습니다. 이후 실제 B200 lifecycle 검증
대상이 Qwen3-Coder-Next 80B로 확정됐으므로, 현재 Phase F 기준선도 Qwen
base입니다. GPT-OSS 관련 내용은 차기 모델 후보 기록으로만 유지합니다.


**Phase E: SFT lifecycle PoC (완료 — infrastructure PASS / model quality FAIL)**

Qwen3-Coder-Next 80B에서 학습, adapter 저장·로드, merge, 실제 API serving,
5건 smoke, 500건 label-blind 평가 흐름을 끝까지 검증했습니다. 낮은 loss와
별개로 precision, recall, FPR, schema gate를 통과하지 못해 현재 adapter는
채택하지 않습니다.

-> **Phase F: dataset 재설계 + source/binary adapter 개선 (F1 완료, F2 진행 중)**

기존 33만 건을 확대하지 않고 catalog→eligible manifest→materialized JSONL
세 계층으로 재구성합니다. 구조 검사를 통과한 데이터에 대해 코드 근거가
있는 정답, 출력 다양성, tokenizer cutoff를 추가로 검증한 뒤 Qwen 80B
source adapter를 새로 학습합니다. 통과 후 pseudo-C·정적 특징·제한된
assembly 기반 binary-derived adapter를 별도로 검증합니다.

**Phase G: 직접 모델/레이어 연구**

LoRA / QLoRA, dataset, evaluation이 충분히 안정된 뒤 직접 모델 구조 변경, custom layer, continued pretraining 같은 연구를 검토합니다. 이 단계는 장기 목표이며, v0에서는 architecture modification을 하지 않습니다.

## Project NuriLab과의 관계

이 프로젝트는 Project Nurilab : 로컬 LLM 기반 악성코드 분석 자동화 시스템 개발 프로젝트에서 `로컬 LLM 파인 튜닝 또는 LLM 모델링` 부분을 담당하는 프로젝트입니다.

Project NuriLab은 나중에 AegisLM에서 만든 모델, LoRA adapter, 평가 결과, JSON output contract를 가져다 쓸 수 있습니다. 반대로 AegisLM은 Project NuriLab의 분석 결과나 synthetic fixture를 학습 데이터 후보로 활용할 수 있습니다.

두 프로젝트는 연결될 수 있지만, 책임은 분리합니다.

## 범위 밖

- 정적 분석 pipeline 구현
- Python analyzer rule 관리
- HTML 운영 보고서 생성기 구현
- 사용자 CLI 제품화
- Project NuriLab의 전체 배포 정책 정의
- 실제 악성 샘플 저장 또는 실행
- secrets, private CTI, private customer data 저장

## 문서

- `AGENTS.md` - 협업 운영 규칙
- `CONTRIBUTING.md` - 기여 절차 안내
- `docs/README.md` - 세부 문서 인덱스와 문서 관리 규칙
- `docs/ARTIFACT_STORAGE_POLICY.md` - fine-tuning 산출물 저장 정책
- `docs/DATASET_CANDIDATES.md` - 공개 데이터셋 후보 registry와 안전성/용도 분류
- `docs/DATA_STRATEGY.md` - Phase C 데이터 활용 전략
- `docs/EVALUATION_PLAN.md` - Phase D/E 평가 계획과 결과 리포트 기준
- `docs/ABSOLUTE_EVALUATION.md` - label-blind 코드 challenge, adapter 서빙, 절대평가 gate
- `docs/FINETUNING_TEST_WORKBOOK.md` - B200 수동 파인튜닝 검증 진행표, 실행 명령, 기록·판정 워크북
- `docs/PHASE_F_DATASET_AND_BINARY_EXPERIMENT_PLAN.md` - Phase F F0–F9 데이터 감사, Qwen 신규 학습, source/binary gate와 NuriLab 연결 기준
- `docs/EXPERIMENT_LOG_TEMPLATE.md` - baseline/adapter 평가 결과 기록 템플릿
- `docs/PHASE_D_EXIT_CRITERIA.md` - Phase D 완료 조건과 Phase E 착수 gate
- `docs/PHASE_E_TEAM_ONBOARDING.html` - Phase E 이슈 처리와 팀 교육 주제 인포그래픽
- `docs/FINETUNING_EXPERIMENT_PLAN.md` - 파인튜닝 실험 계획
- `docs/PR_DESCRIPTION_TEMPLATE.md` - PR 본문 작성 템플릿
- `docs/QUALITY_GATES.md` - 코드 변경 PR 검사 기준
- `docs/TEST_CRITERIA.md` - Phase C 테스트 기준과 평가 레퍼런스

README에는 프로젝트의 큰 방향과 현재 상태만 유지합니다. 세부 기준, 실험 계획, 기여 규칙, 테스트 기준은 `docs/` 아래 문서에 기록합니다.
