# AGENTS.md - AegisLM Collaboration Manual

이 문서는 `AegisLM` 저장소에서 코드를 작성하는 모든 주체가 따르는 협업 운영 규칙이다. 사람, Codex, Claude Code, Cursor, 기타 코딩 에이전트는 이 문서를 기준으로 작업한다.

`AegisLM`은 Project NuriLab과 연계할 수 있는 별도 LLM 모델 개발 프로젝트다. 이 저장소의 책임은 보안 분석 특화 LLM의 학습, 데이터셋 구성, 평가, 추론 검증, adapter 개선, 장기적인 모델 구조 연구다.

Project NuriLab과 협업 방식과 보안 철학은 공유하지만, 이 저장소는 Project NuriLab의 내부 구현 모듈이 아니다.

---

## 1. 시작 전 필독 - SSOT 지도

| 알고 싶은 것 | 정본 위치 |
| --- | --- |
| 프로젝트 정체성, 현재 단계, 전체 로드맵 | `README.md` |
| 세부 문서 인덱스와 문서 관리 규칙 | `docs/README.md` |
| fine-tuning adapter, checkpoint, model card, evaluation artifact 저장 정책 | `docs/operations/policies/ARTIFACT_STORAGE_POLICY.md` |
| 공개 데이터셋 후보 registry와 안전성/용도 분류 | `docs/design/datasets/DATASET_CANDIDATES.md` |
| Phase E 이슈 처리와 팀 교육 주제 인포그래픽 | `docs/onboarding/PHASE_E_TEAM_ONBOARDING.html` |
| Phase C 데이터 활용 전략 | `docs/design/datasets/DATA_STRATEGY.md` |
| Phase D/E 평가 계획과 리포트 기준 | `docs/evaluation/EVALUATION_PLAN.md` |
| label-blind 코드 challenge와 절대평가 gate | `docs/evaluation/ABSOLUTE_EVALUATION.md` |
| B200 수동 파인튜닝 검증 실행·기록 워크북 | `docs/operations/b200/FINETUNING_TEST_WORKBOOK.md` |
| Phase F 데이터 재설계·binary-derived 실험 정본 | `docs/experiments/plans/PHASE_F_DATASET_AND_BINARY_EXPERIMENT_PLAN.md` |
| Sol·Terra·implementation agent 역할과 수동 orchestration 규칙 | `docs/governance/AGENT_WORKFLOW.md` |
| 현재 Phase F 브랜치 20개 커밋의 한국어 리뷰 지도 | `review/guides/COMMIT_REVIEW_GUIDE_KO.md` |
| 커밋·영역·파일별 상세 코드 리뷰와 발견 사항 | `review/README.md` |
| 로컬 LLM과 analyzer MCP의 미확정 책임 경계 아이디어 | `docs/design/architecture/LOCAL_LLM_MCP_BOUNDARY_IDEA.md` |
| ARVO patch↔buffer-family 수동 gate 결정 | `docs/experiments/decisions/phase-f/PHASE_F_ARVO_PATCH_GATE_DECISION_20260731.md` |
| Patch-localized label 공급·archive gate 결정 | `docs/experiments/decisions/phase-f/PHASE_F_PATCH_LABEL_SUPPLY_DECISION_20260731.md` |
| source label·근거 수동 검토 기준 | `docs/evaluation/SOURCE_MANUAL_REVIEW_RUBRIC.md` |
| baseline/adapter 평가 결과 기록 템플릿 | `docs/templates/EXPERIMENT_LOG_TEMPLATE.md` |
| Phase D 완료 조건과 Phase E 착수 gate | `docs/evaluation/PHASE_D_EXIT_CRITERIA.md` |
| 파인튜닝 학습 로드맵과 실험 전략 | `docs/experiments/plans/FINETUNING_EXPERIMENT_PLAN.md` |
| Phase C 테스트 기준과 평가 레퍼런스 | `docs/evaluation/TEST_CRITERIA.md` |
| 팀 기여 절차, 브랜치, 커밋, 검증 규칙 | `docs/governance/CONTRIBUTING.md` |
| PR 본문 작성 템플릿 | `docs/templates/PR_DESCRIPTION_TEMPLATE.md` |
| 코드 변경 PR 검사 기준 | `docs/governance/QUALITY_GATES.md` |
| 에이전트/개발자 공통 운영 규칙 | `AGENTS.md` |
| Python 패키지 설정 | `pyproject.toml` |
| 테스트 | `tests/` |

**규칙 0 - 현황을 단정하기 전에 동기화한다.**

작업 전에는 로컬 브랜치와 원격 상태를 확인한다.

```bash
git fetch origin
git status
```

로컬 상태가 뒤처진 채로 "없다", "미구현이다", "충돌 없다"라고 단정하지 않는다.

---

## 2. 프로젝트 방향

이 프로젝트의 목표는 보안 분석에 특화된 로컬 LLM을 학습, 평가, 개선하는 것이다.

현재 README의 Phase A-G 로드맵을 기준으로 진행한다.

```text
Phase A: 문서/저장소 정체성 정리
Phase B: 최소 코드 뼈대 생성
Phase C: 데이터 전략 + JSON schema + tiny dataset
Phase D: baseline inference + evaluation
Phase E: SFT lifecycle PoC와 절대평가
Phase F: dataset 재설계 + source/binary adapter 개선
Phase G: 직접 모델/레이어 연구
```

Phase E는 `infrastructure PASS / model quality FAIL`로 종료했다. 현재
Phase F의 우선순위는 다음과 같다.

- 기존 33만 건과 80B adapter를 실패 기준선으로 동결
- source/metadata/label/target을 model-visible prompt에서 제거
- catalog→eligible manifest→materialized JSONL 세 계층을 유지
- F3 `phase-f-source-v3` 10,000건과 독립 500건 challenge 동결 완료
- F4 base·legacy source-v2 smoke는 schema `0/20`으로 종료
- oracle `20/20` PASS로 evaluator 정상 확인
- F5의 최종 source 후보는 Q1R10 decision과 Q1R11 evidence를 순차
  실행하는 two-stage pipeline
- 신규 blind 500건에서 decision P/R/FPR
  `0.9881/1.0000/0.0120`, evidence P/R/F1
  `0.9001/0.9229/0.9114`, schema/renderer `1.00`으로 PASS
- 두 adapter의 개별 BF16 merge와 vLLM TP2 lifecycle 완료
- evidence serving은 guided JSON Schema constrained decoding과
  AegisLM semantic validator를 필수조건으로 사용
- F6-A binary candidate/toolchain inventory는 PASS
- F6-B B0 최초 판정은 145 pair 중 100 pair 승인으로 종료했지만, F7의
  엄격 target-evidence 정책을 소급 적용해 CWE-563 1 pair를 추가 격리
- 엄격 재감사 기준 B0는 99/145이며 부족분은 F7 공급에서 대체
- 승인 pair의 normalized binary record 800건은 schema·pseudo-C·assembly·
  static-feature linkage 1.00, prompt provenance/label/source-symbol 누출 0
- F7 구조 적격 공급 4,643 pair를 동결하고 엄격 정책으로 과거
  250-pair pilot을 198/250, B0를 99/145로 정정
- 다섯 차례 500-pair 확대의 target preservation은 r1 `420/500`,
  r2 `394/500`, r3 `410/500`, r4 `419/500`, r5 `394/500`
- r5까지 누적 승인/검토는 `2,334/2,895`; Wilson gate에 따라 tail을
  500이 아닌 160 pair로 제한
- tail은 compile·decompile·function link `640/640`, 엄격 승인
  `121/160`; 1차 target-preservation qualified `2,455`
- 실제 pseudo-C relation recovery r1·r2 뒤 qualified `2,536`; target v1
  + Qwen tokenizer gate는 `2,488`, 선택 `2,450`, reserve `38`
- target v1 model-ready data는 자동 gate를 통과했지만 수동 100건에서
  명백한 evidence error 6건으로 `FAIL EARLY`; 학습 승인 false
- target v2·v3·v4도 고정 수동 검토에서 각각 여섯 번째 오류에 도달해
  `FAIL EARLY`; 실패 artifact와 hash-bound 결정을 보존
- `strict-pair-grounded-evidence-v5`는 recovery r4·r5 뒤 공급
  `2,450/2,477`과 자동 gate를 통과했지만 수동 100건에서 evidence
  error 6건으로 다시 `FAIL EARLY`
- `complete-fixed-role-evidence-v6`는 remediation과 constrained sink를
  모두 요구하며 공급 `2,123/2,450`으로 FAIL
- Ghidra 표현 정규화를 추가한
  `decompiler-normalized-role-evidence-v7`은 recovery r6 뒤 공급
  `2,450/2,468`과 자동 gate를 통과했지만 수동 연결 오류 발견
- `linked-role-evidence-v8`은 동일 변수 연결을 강제해 공급
  `2,326/2,450`으로 FAIL
- `memory-write-read-linked-evidence-v9`은 공급 `2,450/2,498`과 자동
  gate를 통과했지만 수동 100건에서 capacity·loop bound·null guard·
  negative offset 누락 6건으로 `FAIL EARLY`
- frozen queue는 모두 소진됐으며 flat evidence target으로 binary
  adapter를 학습하지 않음
- `aegislm.binary-role-assessment-output.v2` schema와 semantic validator를
  추가해 exact span, role, sink-directed relation을 강제
- 다음은 v2 role-structured target builder → tokenizer gate → 고정
  100건 수동 review 순서
- v2 r1은 자동 공급 `2,450/2,479`, r2는 `2,450/2,485`를 확보했지만
  두 고정 review 모두 evidence 오류 `6/100`에서 `FAIL EARLY`
- generic identifier-overlap fallback으로 2,450 pair를 채우지 않음;
  다음은 CWE별 완전한 role extractor가 있는 범주만 eligible로 재산정
- strict v3 공급은 `1,301/2,924` pair, review-eligible PASS였지만
  CWE-124/127/457/690 오류 6건으로 수동 gate `FAIL EARLY`
- CWE-124/127/457/690은 quarantine; 남은 extractor도 새 수동 gate 전
  학습 금지
- 초기 19,600 전량 학습 가정은 폐기; pair당 한 compiler variant를
  균형 선택한 4,900건과 별도 800건 compiler-consistency set으로 구성
- 수동 target review가 `≤5/100`을 통과하기 전 binary 학습 금지
- Q2 250-step과 313-step 연장은 개선 근거가 없어 미실행
- GPT-OSS 20B는 Qwen 결론 이후 보조 이식성 실험으로만 진행
- source와 binary-derived adapter를 서로 분리해 절대평가
- binary는 raw byte가 아니라 pseudo-C, 정적 특징, 제한된 assembly를 사용
- 두 adapter가 독립 gate를 통과하기 전에는 NuriLab/RAG/MCP 연결을 보류
- GPU/runtime, HF access, model/cache/adapter 저장 경로를 Git 밖으로 분리
- 모델, checkpoint, adapter, raw dataset, generated prediction/report는 계속 Git 밖에 보관

---

## 3. 작업 선택 규칙

작업은 자유롭게 선택하되, 다음 순서를 지킨다.

```text
문서/정체성 정리
-> 저장소 scaffold 설계
-> 데이터 활용 전략 정의
-> schema와 prompt contract 정의
-> tiny dataset 준비
-> baseline inference 확인
-> evaluation 구현
-> tiny SFT PoC
-> adapter 개선과 dataset 확장
```

착수 전 체크리스트:

- [ ] 작업 목적이 README의 Phase A-G 로드맵과 맞는가?
- [ ] 같은 작업을 다른 사람이 진행 중이지 않은가?
- [ ] 데이터, 모델, checkpoint, adapter 저장 위치가 Git 밖으로 분리되는가?
- [ ] schema, dataset format, prompt contract, evaluation 기준에 영향이 있는가?
- [ ] 영향이 있다면 테스트와 문서 갱신 계획이 있는가?

의존성이 있는 작업은 상위 작업을 먼저 끝낸다.

- 학습 스크립트 전: schema와 tiny dataset 확인
- schema 작성 전: 데이터 활용 전략 확인
- adapter 학습 전: baseline inference와 evaluation 확인
- dataset 확장 전: 안전/저장 정책 확인
- 모델 구조 연구 전: LoRA / QLoRA 한계와 평가 목표 확인

---

## 3.1 다중 모델 직접 배정과 수동 orchestration

사용자가 여러 모델에 작업을 직접 지시할 때 사용자가 Owner이자
orchestrator이고, 메인 에이전트는 사용자가 승인할 Work Order를 작성하고
판정을 종합한다. 요구사항과 gate의 설계 권한을 검토 에이전트에 넘기지
않는다.

**서브에이전트와 재위임은 금지다.** 사용자가 Terra에게 배정한 작업은
Terra가 직접 수행하고, Luna에게 배정한 구현은 Luna가 직접 수행하며, Sol에게
배정한 검토는 Sol이 직접 수행한다. 어떤 에이전트도 `spawn_agent`, 자동
handoff, 하위 작업자 생성 또는 다른 모델로의 재위임을 사용하지 않는다.
개별 Work Order는 이 금지를 해제할 수 없다. 향후 서브에이전트를 도입하려면
사용자가 이 운영 규칙 자체의 개정을 별도로 명시하고 승인해야 한다. 일반적인
작업 승인, 파일 범위 승인이나 모델 선택은 재위임 승인으로 해석하지 않는다.

| 역할 | 책임 | 변경 권한 |
| --- | --- | --- |
| 사용자 / Owner | 목적·불변 조건·PASS/BLOCK gate 동결, 파일·설치·GPU·Git 승인 | 최종 결정권 |
| 메인 에이전트 | Work Order 작성, 증거 종합, 다음 gate와 최종 판정 보고 | 사용자가 승인한 범위만 |
| Sol reviewer | 요구사항·안전성·고위험 결과의 독립 검토 | 읽기 전용 |
| Terra planner | 저장소 조사와 파일 단위 변경·테스트 계획 | 읽기 전용 |
| implementation agent | 승인된 파일만 구현하고 테스트 증거 제출 | 승인된 파일만 |
| Terra reviewer | 사용자가 직접 연 별도 Terra 작업에서 diff·테스트·범위 회귀 검토 | 읽기 전용 |

`implementation agent`는 사용자가 직접 선택해 연 모델 작업에 부여하는
역할명이다. Luna를 선택하면 Luna가 직접 구현하고, Terra를 선택하면 Terra가
직접 구현한다. 배정받은 모델이 다른 에이전트에게 구현을 넘겨서는 안 된다.
같은 대화나 작업이 구현과 독립 검토를 동시에 맡아서는 안 된다.

기본 순서는 다음과 같다.

```text
메인 Work Order 동결
-> 사용자가 직접 연 Sol 작업의 요구사항·안전성 독립 검토
-> 사용자가 직접 연 Terra 작업의 읽기 전용 파일 계획
-> 사용자 파일 범위 승인
-> 사용자가 직접 지정한 implementation agent의 순차 구현·테스트
-> 사용자가 직접 연 별도 Terra 작업의 diff·증거 검토
-> 고위험 변경이면 사용자가 직접 연 별도 Sol 작업의 최종 검토
-> 메인 판정과 사용자 보고
```

운영 규칙:

- 구현과 검토는 순차 실행하고 같은 파일을 여러 에이전트가 병렬 수정하지 않는다.
- 배정받은 에이전트는 작업을 직접 수행하며 서브에이전트 생성, 자동 handoff,
  재위임과 대리 수행을 하지 않는다.
- 다른 모델의 검토나 구현이 필요하면 현재 작업을 `BLOCK`하고 사용자가 직접
  새 작업을 열어 배정하도록 요청한다.
- 검토자는 요구사항이나 gate를 수정하지 않고 `PASS`,
  `REQUEST_CHANGES`, `BLOCK` 중 하나만 판정한다.
- 동결된 gate를 바꿔야 하면 현재 작업을 `BLOCK`하고 새 Work Order 버전과
  사용자 재승인을 요구한다.
- 승인 파일 밖의 변경이 필요하면 implementation agent는 작업을 중단한다.
- 의존성 설치, 모델·데이터 다운로드, GPU 실행, Git stage/commit/push는
  각각 별도 사용자 승인 없이는 수행하지 않는다.
- 모델 revision, 데이터·평가 artifact hash, schema, 학습 금지 범위와 과거
  실험 보존 조건은 Work Order의 불변값으로 기록한다.
- `PASS` 증거에는 실행 명령, 종료 코드, 핵심 출력, 변경 파일, 실패·skip·
  미실행 항목, 알려진 제한과 `delegation_used: false`를 포함한다.

상세 역할 지시문, Work Order, 구현 증거와 검토 양식은
`docs/governance/AGENT_WORKFLOW.md`를 따른다. 특정 모델·데이터·gate 값은 이 문서에
고정하지 않고 작업별 Work Order와 `review/workflows/<task>/`에 기록한다.

---

## 4. 네이밍 표준

모든 브랜치, 커밋, PR은 작업 목적을 드러내야 한다.

| 대상 | 형식 | 예시 |
| --- | --- | --- |
| 문서 브랜치 | `docs/<topic>` | `docs/project-identity` |
| 기능 브랜치 | `feat/<topic>` | `feat/scaffold-training-layout` |
| 실험 브랜치 | `experiment/<topic>` | `experiment/tiny-sft-poc` |
| 테스트 브랜치 | `test/<topic>` | `test/evaluation-json-contract` |
| 버그 브랜치 | `fix/<topic>` | `fix/dataset-validator` |
| 커밋 | `<type>: <summary>` | `docs: define model development roadmap` |
| PR 제목 | `[AegisLM] <summary>` | `[AegisLM] Add tiny SFT evaluation harness` |

`<type>`은 다음 중 하나를 사용한다.

- `feat`
- `fix`
- `docs`
- `test`
- `refactor`
- `chore`
- `experiment`

커밋 메시지는 Conventional Commits 형식을 권장한다.

---

## 5. 개발 가드레일

**Must Do**

- 작은 단위로 변경한다.
- 데이터, 평가, 학습, 추론 책임을 분리한다.
- public 함수와 주요 데이터 모델에는 타입 힌트를 유지한다.
- schema, prompt contract, dataset format 변경은 문서와 테스트를 함께 갱신한다.
- 학습 전 baseline inference와 evaluation 기준을 먼저 마련한다.
- 모델, adapter, checkpoint, raw dataset은 Git 저장소 밖에 둔다.
- 실험 결과는 재현 가능하도록 package version, command, dataset path, GPU 정보를 기록한다.

**Must Not**

- 실제 악성 샘플, secrets, API key, private CTI, 민감 데이터를 커밋하지 않는다.
- raw dataset, model checkpoint, adapter artifact를 커밋하지 않는다.
- `main`에 직접 push하지 않는다.
- LLM 응답을 최종 보안 판단 기준으로 삼지 않는다.
- 공격 실행 절차, 우회 로직, credential theft workflow를 학습 데이터로 만들지 않는다.
- 평가 기준 없이 대형 학습부터 시작하지 않는다.
- v0에서 직접 model architecture 변경을 시작하지 않는다.

**판단 기준**

- 모델은 설명, 요약, TTP 매핑, 우선순위화, 구조화된 보고 출력을 담당한다.
- 판단 근거는 deterministic evidence, curated labels, human review, evaluation result를 기준으로 한다.
- fine-tuning 성공 여부는 loss만이 아니라 JSON 유효성, 필드 완성도, 안전성, hallucination rate로 평가한다.

---

## 6. 코드 구조와 책임

Phase B 이후의 기본 책임 경계는 다음을 목표로 한다.

| 영역 | 책임 |
| --- | --- |
| `aegislm/schemas.py` | JSON output contract, dataset record shape |
| `aegislm/prompts/` | system/user prompt template |
| `aegislm/datasets/` | dataset formatting, validation, split helpers |
| `aegislm/evaluation/` | JSON validity, required fields, safety checks |
| `aegislm/inference/` | base model and adapter inference helpers |
| `aegislm/training/` | TRL / Unsloth training helpers |
| `scripts/` | one-command entrypoints for dataset, inference, train, evaluate |
| `configs/` | baseline and tiny SFT experiment configs |
| `tests/` | schema, dataset, evaluation regression tests |

새 모듈을 만들기 전에 기존 책임 경계에 들어갈 수 있는지 먼저 확인한다. 단일 사용처를 위한 추상화는 만들지 않는다.

---

## 7. 테스트 규칙

문서만 바꾸는 작업은 별도 코드 테스트가 필요하지 않다.

코드가 추가된 뒤 PR 전에는 가능한 범위에서 다음을 실행한다.

```bash
uv run pytest tests/
uv run ruff check .
uv run ruff format --check .
uv run mypy aegislm/ tests/
```

테스트 코드는 pytest-style function/assert를 기본으로 작성한다. `unittest.TestCase`, `unittest.main()`, `self.assert*` 패턴은 새로 추가하지 않는다.

변경 영역별 테스트 기준:

- schema 변경: JSON contract와 required field 테스트
- dataset 변경: dataset record validation, split, unsafe sample exclusion 테스트
- prompt 변경: formatting snapshot 또는 expected message shape 테스트
- evaluation 변경: invalid JSON, missing fields, hallucinated mapping, unsafe guidance 테스트
- training helper 변경: config parsing과 dry-run 가능한 단위 테스트
- inference helper 변경: mock model 또는 fixture output 기반 테스트

실제 GPU, 대형 모델, 외부 dataset이 필요한 검증은 일반 PR 필수 테스트로 만들지 않는다. 그런 검증은 별도 experiment log에 기록한다.

---

## 8. PR 제출 체크리스트

PR 생성 전:

- [ ] 최신 `main` 기준 브랜치에서 작업했는가?
- [ ] 브랜치명이 네이밍 표준을 따르는가?
- [ ] PR 제목이 `[AegisLM] <summary>` 형식을 따르는가?
- [ ] 문서 변경만인지, 코드 변경인지 명확한가?
- [ ] 코드 변경이면 관련 테스트를 추가하거나 갱신했는가?
- [ ] 가능한 경우 `uv run pytest tests/` 통과
- [ ] 가능한 경우 `uv run ruff check .` 통과
- [ ] 가능한 경우 `uv run ruff format --check .` 통과
- [ ] 가능한 경우 `uv run mypy aegislm/ tests/` 통과
- [ ] schema, dataset format, prompt contract 변경 시 README 또는 실험 계획을 갱신했는가?
- [ ] raw dataset, checkpoint, adapter artifact, secrets, 민감 데이터가 포함되지 않았는가?
- [ ] 실험 결과를 주장한다면 command, package version, GPU, dataset path를 기록했는가?

PR 본문은 `docs/templates/PR_DESCRIPTION_TEMPLATE.md`를 기준으로 작성한다. 최소한 다음을 포함한다.

- 변경 목적
- 주요 변경 내용
- 검증 명령과 결과
- 제한사항 또는 후속 작업
- 관련 Linear 이슈와 GitHub PR/Issue

---

## 9. 거버넌스

- `README.md`는 프로젝트 정체성, 현재 단계, 전체 로드맵의 정본이다.
- `docs/README.md`는 세부 문서 인덱스와 문서 관리 규칙의 정본이다.
- `docs/design/datasets/DATA_STRATEGY.md`는 Phase C 데이터 활용, 전처리, tokenization/chunking, split, RAG/vector 분리 기준의 정본이다.
- `docs/evaluation/EVALUATION_PLAN.md`는 Phase D/E 평가 계획, 점수화 기준, 결과 리포트 형식의 정본이다.
- `docs/operations/b200/FINETUNING_TEST_WORKBOOK.md`는 B200 수동 검증의 진행 상태, 실행 명령, 증거 기록, 최종 연구 결정의 정본이다.
- `docs/experiments/plans/PHASE_F_DATASET_AND_BINARY_EXPERIMENT_PLAN.md`는 Phase F catalog, source/binary adapter, 중단 gate와 NuriLab handoff의 정본이다.
- `docs/evaluation/SOURCE_MANUAL_REVIEW_RUBRIC.md`는 source target의 label·경로·exact span·인과관계 수동 판정 기준의 정본이다.
- `docs/evaluation/PHASE_D_EXIT_CRITERIA.md`는 Phase D 완료 조건과 Phase E 착수 gate의 정본이다.
- `docs/experiments/plans/FINETUNING_EXPERIMENT_PLAN.md`는 학습 로드맵, 실험 전략, dataset/evaluation 기준의 정본이다.
- `docs/governance/AGENT_WORKFLOW.md`는 모델별 역할, 권한, 수동 orchestration, Work Order와 증거 형식의 정본이다.
- `docs/templates/PR_DESCRIPTION_TEMPLATE.md`는 PR 본문 작성 형식과 체크리스트의 정본이다.
- `docs/evaluation/TEST_CRITERIA.md`는 Phase C 테스트 기준과 평가 레퍼런스의 정본이다.
- `AGENTS.md`는 작업 규칙과 에이전트 행동 기준의 정본이다.
- `docs/governance/CONTRIBUTING.md`는 팀원이 PR을 올리기 위한 절차 문서다.
- `CONTRIBUTING.md`는 GitHub 관례를 위한 안내 링크 문서다.
- GitHub Issue는 작업 단위와 상태 추적의 정본이다.
- PR은 코드 리뷰와 변경 이력의 정본이다.

schema, dataset format, prompt contract, evaluation metric, artifact storage policy 변경은 반드시 문서와 테스트를 함께 갱신한다.

문서 추가/수정 규칙:

- README에는 프로젝트의 큰 방향과 현재 상태만 적는다.
- 세부 기준, 실험 계획, 기여 규칙, 테스트 기준은 `docs/` 아래 문서에 기록한다.
- 새 기준이 생기면 가장 가까운 기존 문서에 추가한다.
- 성격이 독립적인 기준이면 `docs/`에 새 문서를 만든다.
- 문서를 추가하거나 이동하면 `README.md`, `docs/README.md`, `AGENTS.md`의 링크와 작업 규칙을 함께 갱신한다.

모호하거나 막히면 임의로 확장하지 말고 GitHub Issue 또는 PR 코멘트에 남긴 뒤 Owner 확인을 받는다.

---

## 10. 유지보수 TODO

- Phase B scaffold 구조 확정
- GitHub Issue template과 PR template 추가
- GitHub Actions 기반 문서/테스트 CI 검토
- CODEOWNERS 도입 여부 검토
- branch protection 설정 검토

## 11. Phase F Binary Strict Gate 현황

- strict v7 지원 범위는 CWE-134/190/191/194/195이다.
- 고정 seed 100건 수동 검토는 오류 `1/100`으로 품질 gate를 통과했다.
- 적격 공급은 `644/2,450` pair이므로 binary adapter 학습은 승인하지 않는다.
- 격리된 CWE를 수량 확보 목적으로 다시 포함하지 않는다.
- 644 pair는 `quality-approved / supply-blocked` seed와 회귀
  benchmark로만 보존한다.
- 상세 근거는
  `docs/experiments/decisions/phase-f/PHASE_F_BINARY_ROLE_TARGET_DECISION_20260731.md`를 따른다.
- ARVO 공개 개발자 패치 200건 수동 gate는 오류 `11/200`으로
  `FAIL EARLY`했다. crash type을 gold CWE로 자동 변환하지 않는다.
- ARVO는 binary adapter 학습 supply로 승인하지 않는다.
- 다음 공급 감사는 MegaVul/CVEfixes의 patch-localized CWE와
  Assemblage/Decompile-Bench의 alignment 역할을 분리한다.
- 해당 metadata 감사에서 MegaVul은 immutable artifact와 dataset
  license가 없어 hold했다.
- CVEfixes v1.0.8은 exact size/MD5/SHA-256, 비추출 ZIP inventory,
  선택적 SQL gzip CRC, 정적 SQL 감사, 방어적 SQLite import를 통과했다.
- read-only 공급량은 C/C++ exact before/after `6,248`쌍이며 숫자형 CWE만
  허용한 200쌍 review queue의 구조 오류는 0건이다.
- CVEfixes patch↔CWE 수동 gate는 고정 순서 28건에서 오류·불확실
  `11/28`로 예산 10건을 초과해 `FAIL EARLY`했다.
- 남은 172건은 미검토이며 PASS가 아니다. CVEfixes commit-level CWE를
  direct training label로 사용하지 않고 repository license gate도
  착수하지 않는다.
- Decompile-Bench 고정 Arrow shard의 source–assembly 수동 정렬은
  `96/100`으로 통과했다. 오류 4건은 모두 다른 함수가 짝지어진
  `different_function + semantic_mismatch`다.
- 전체 `131,359`행 중 명시 repository 복원은
  `111,206`행(`84.6581%`)이고 repository별 license,
  compiler·optimization metadata가 없다.
- Decompile-Bench disposition은 `alignment_reference_only`이며
  `approved_for_training=false`다.
- Assemblage LinuxELF compressed DuckDB의 artifact·zstd·schema gate는
  통과했지만 license 상한 70.91%, architecture 68.84%,
  format·commit·build mode 약 31.15%로 field gate는 실패했다.
- build trace가 있는 63,031행과 architecture가 있는 113,329행의 strict
  교집합은 0건이다. `metadata_reference_only`로 보존하며 raw ELF
  다운로드와 training은 false다.
- BinKit 2.0 compile matrix는 확인했지만 GitHub release asset 0개,
  외부 Drive artifact의 size·SHA-256·dataset license·row schema 부재로
  `metadata_hold`다.
- BinKit binary와 pickle은 받지 않으며 pickle을 역직렬화하지 않는다.
- EMBER2024 ELF test는 archive·schema·static-feature gate를 통과했지만
  원본 12,000행의 동일 `(week_id, sha256)` 중복을 제거한 6,000관측치만
  독립 malware benchmark로 허용한다.
- EMBER2024의 primary label과 static feature 충돌은 0건이다. 서로 다른
  CAPS/MBC/TTP annotation은 별도 merge 계약 전까지 사용하지 않는다.
- EMBER2024는 SFT에 혼합하지 않고 raw executable도 받지 않는다.
- train 26,000건·test 6,000건 materialization은 label-blind
  feature/gold 분리와 재현 hash gate를 통과했다.
- 자체 temporal LightGBM은 test FPR `0.0197`, 주별 최대 FPR `0.056`으로
  절대 gate에 실패했다. 공식 모델도 calibration threshold에서 test FPR
  `0.1097`, 주별 최대 FPR `0.208`로 실패했다.
- 두 classifier 모두 NuriLab static-signal 연결과 Qwen SFT 혼합 승인은
  false다. 다음 작업은 FP 집중 주차의 feature drift 감사다.
- PoC, crash output, reproducer command를 읽거나 Docker image·object를
  실행하지 않는다.
