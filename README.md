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

2026-07-30 현재 source model-only 최종 후보는 Q1R10 decision 100-step과
Q1R11 evidence 100-step을 순차 실행하는 two-stage pipeline입니다. 기존
학습·검증·평가의 5,750 pair와 group/code hash가 겹치지 않는 신규 blind
500건에서 decision precision/recall/FPR
`0.9881/1.0000/0.0120`, evidence precision/recall/F1
`0.9001/0.9229/0.9114`, parse/schema/renderer `1.0000`으로 고정 절대
gate를 모두 통과했습니다. Q1R10과 Q1R11은 각각 base-start 100-step이며
추가 250/313-step 학습은 수행하지 않습니다.

이 PASS는 NIST SARD/Juliet 기반 C/C++ 함수에서 지정된 CWE의
`present / not_observed` 판단과 근거 line 선택에 한정됩니다. 고정 seed
TP 10/TN 10 검토에서는 판단 20/20과 evidence overlap 20/20을
확인했지만, 20건 모두 confidence가 `high`였고 deterministic report의
recommendation은 일반적인 재확인 문구입니다. 따라서 calibration,
구체적인 remediation, 실제 프로젝트·다른 언어·binary 분석 성능은 아직
검증되지 않았습니다. 두 adapter의 개별 BF16 merge와 vLLM TP2 lifecycle은
완료했습니다. Evidence endpoint는 자유 JSON 생성 시 500건 중 1건이
8-range 상한을 넘었으므로 `response_format=json_schema` constrained
decoding과 AegisLM semantic validator를 배포 필수조건으로 고정합니다.
이 조건에서 decision과 evidence의 전체 절대 gate가 통과했습니다.

F6-A binary 후보·서버 preflight와 F6-B B0 lifecycle을 완료했습니다.
SARD/Juliet CC0 원천과 사용자 영역의 GCC·Clang 18·Ghidra 12.1.2
toolchain을 동결했습니다. 최초 B0 판정은 후보 145쌍 중 100쌍을
승인했지만, F7의 더 엄격한 target-evidence 정책을 소급 적용하면서
`CWE-563` 1쌍을 추가 격리했습니다. 따라서 엄격 재감사 기준 B0는
99쌍 승인·46쌍 탈락이며, 부족분은 F7 공급에서 대체합니다.

최초 승인 pair는 present/not_observed를 분리한 normalized record
800건으로 materialize했고 schema, pseudo-C, bounded assembly,
static-feature linkage `1.00`, prompt provenance·gold label·source symbol
누출과 raw payload·object 실행 `0`을 확인했습니다. 다만 최종 데이터에는
재감사에서 격리된 1쌍을 포함하지 않습니다.

F7은 구조 적격 4,643 pair의 전체 queue를 동결했습니다. 엄격 정책으로
과거 250-pair pilot을 `198/250`, B0를 `99/145`로 정정하고, 첫 500-pair
확대 배치에서 compile `2,000/2,000`, decompile·function link
`1,997/2,000`, target-preservation `420/500`을 확인했습니다. 현재 누적은
`717/895`이며 Wilson 95% 승인률 하한 `0.77370`에서도 목표 2,450 pair
확보 후 1,508 pair의 공급 여유가 남아 다음 500-pair 배치를 승인했습니다.

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

2026-07-29 F2 감사에서 source 전용 v2 계약과 실제 Qwen tokenizer gate를
적용했습니다. 기존 core 11,500건은 exact code/patch 근거가 없어 모두
제외하고, SARD/Juliet 함수에서 직접 증명할 수 있는 setup·guard·effect만
남겼습니다. 최종 `phase-f-sard-grounded-v2`는 5,750쌍으로 train
10,000건, validation 1,000건, blind test 500건을 구성하며 자동
품질·수량·2,048-token gate와 고정 100건 수동 gate를 모두 통과했습니다.
수동 검토 오류는 `0/100`이고 정답의 Juliet `good/bad` 용어 누출도
`0`입니다. 이 자료를 다시 검증·승격한 `phase-f-source-v3`은
train 10,000건, validation 1,000건, blind challenge 500건으로
동결됐습니다. split·content overlap과 canonical round-trip 오류는 모두
`0`, 최대 실제 Qwen token은 `1,913/2,048`이며 동일 입력 재빌드 hash도
일치했습니다. F3 상태는 `approved_for_training=true`입니다. F4에서는
새 학습 전 Qwen base와 Phase E legacy adapter에 고정 20건
source-v2 contract smoke를 수행했습니다. 두 모델 모두 prediction은
완료했지만 schema는 `0/20`이어서 500건 확장은 중단했습니다. 동일 gold
target oracle은 `20/20` PASS해 평가 경로는 정상으로 확인됐습니다.

F5-Q1은 Phase E checkpoint를 재사용하지 않고 base에서 100-step LoRA를
완료했습니다. 저장·checkpoint mirror·재로드·HTTP serving은 통과했지만,
고정 20건 진단 smoke는 precision `0.7778`, recall `0.7000`, FPR
`0.2000`, schema `0.9000`으로 실패했습니다. control-flow, buffer
capacity, allocation provenance와 exact span을 보정한 `phase-f-source-v4`로
Q1R1 100-step을 다시 수행했습니다. lifecycle과 schema는 통과했지만 새
blind 20건에서 precision `0.7500`, recall `0.3000`, FPR `0.1000`으로
semantic gate가 다시 실패했습니다. 같은 사례에서 base raw label은
precision `0.7000`, recall `0.7000`, FPR `0.3333`이어서, 100-step SFT가
형식 준수와 FPR을 개선하는 대신 관계 추론 recall을 훼손했을 가능성이
확인됐습니다. 25-step semantic-preservation canary는 raw recall을
`0.8000`으로 보존했지만 raw FPR `0.9000`, schema `0.6000`으로 반대
방향의 실패를 보였습니다. 이어 수행한 50-step boundary canary도
precision `0.6667`, recall `0.2000`, schema `0.5000`으로 실패했고,
6건은 1,024-token에서 JSON이 잘렸습니다. 따라서 500건 평가와 Q2
250-step은 계속 중단하며 step 탐색도 종료했습니다. 현재 다음 단계는
label·근거·split을 보존하면서 장문 code excerpt와 중복 boilerplate를
제거하는 compact target 및 semantic/contract 학습 목표 재설계입니다.

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

-> **Phase F: dataset 재설계 + source lifecycle PASS / binary F7 scale audit**

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
