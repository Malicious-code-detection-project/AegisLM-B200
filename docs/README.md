# AegisLM Docs

## Browse by area

### Governance

- [Agent workflow](governance/AGENT_WORKFLOW.md)
- [Contributing](governance/CONTRIBUTING.md)
- [Quality gates](governance/QUALITY_GATES.md)

### Design

- [Architecture boundary idea](design/architecture/LOCAL_LLM_MCP_BOUNDARY_IDEA.md)
- [Data strategy](design/datasets/DATA_STRATEGY.md)
- [Dataset candidates](design/datasets/DATASET_CANDIDATES.md)

### Evaluation

- [Absolute evaluation](evaluation/ABSOLUTE_EVALUATION.md)
- [Evaluation plan](evaluation/EVALUATION_PLAN.md)
- [Phase D exit criteria](evaluation/PHASE_D_EXIT_CRITERIA.md)
- [Source manual review rubric](evaluation/SOURCE_MANUAL_REVIEW_RUBRIC.md)
- [Test criteria](evaluation/TEST_CRITERIA.md)

### Experiments

- [Fine-tuning experiment plan](experiments/plans/FINETUNING_EXPERIMENT_PLAN.md)
- [Phase F dataset and binary experiment plan](experiments/plans/PHASE_F_DATASET_AND_BINARY_EXPERIMENT_PLAN.md)
- [Phase F decisions](experiments/decisions/phase-f/)

### Operations

- [B200 operations](operations/b200/)
- [Policies](operations/policies/)
- [Troubleshooting](operations/troubleshooting/)

### Shared resources

- [Templates](templates/)
- [Onboarding](onboarding/)
- [Review guide](../review/guides/COMMIT_REVIEW_GUIDE_KO.md)

## B200 2-GPU Runbook

- [B200_2GPU_SETUP.md](operations/b200/B200_2GPU_SETUP.md) - Server layout, install, data/model recovery, and preflight.
- [B200_TRAINING_HANDOFF.md](operations/b200/B200_TRAINING_HANDOFF.md) - Operator command, global batch, paths, and resume flow.
- [B200_SERVER_READINESS_REPORT.md](operations/b200/B200_SERVER_READINESS_REPORT.md) - Verified server, model, dataset, and checkpoint status.
- [CHECKPOINT_POLICY.md](operations/policies/CHECKPOINT_POLICY.md) - Latest-only local/persistent checkpoint mirror policy.
- [ENVIRONMENT_PROFILES.md](operations/b200/ENVIRONMENT_PROFILES.md) - Stable and optional fast kernel profiles.
- [ABSOLUTE_EVALUATION.md](evaluation/ABSOLUTE_EVALUATION.md) - Label-blind challenge, serving, and absolute pass/fail gates.
- [FINETUNING_TEST_WORKBOOK.md](operations/b200/FINETUNING_TEST_WORKBOOK.md) - Manual B200 test progress, copyable commands, evidence, and decision workbook.
- [PHASE_F_DATASET_AND_BINARY_EXPERIMENT_PLAN.md](experiments/plans/PHASE_F_DATASET_AND_BINARY_EXPERIMENT_PLAN.md) - Phase F F0–F9 data audit, Qwen retraining, source/binary gates, and NuriLab handoff.
- [AGENT_WORKFLOW.md](governance/AGENT_WORKFLOW.md) - 역할 기반 custom agent, 승인 경계, Work Order와 검토 증거 형식.
- [COMMIT_REVIEW_GUIDE_KO.md](../review/guides/COMMIT_REVIEW_GUIDE_KO.md) - 현재 Phase F 브랜치 20개 커밋의 목적, 결과, 읽기 순서, 유지 판정을 설명하는 한국어 리뷰 안내서.
- [코드 리뷰 기록](../review/README.md) - 커밋·영역·파일별 상세 리뷰, 발견 사항, 수정 상태 기록.
- [LOCAL_LLM_MCP_BOUNDARY_IDEA.md](design/architecture/LOCAL_LLM_MCP_BOUNDARY_IDEA.md) - 기존 analyzer MCP가 절대 gate를 통과할 때 fine-tuning을 생략할 수 있는지 검증하는 미확정 architecture 아이디어.
- [PHASE_F_BINARY_ROLE_TARGET_DECISION_20260731.md](experiments/decisions/phase-f/PHASE_F_BINARY_ROLE_TARGET_DECISION_20260731.md) - Binary role target v2 r1/r2 supply PASS, manual FAIL, and strict CWE extractor decision.
- [PHASE_F_ARVO_PATCH_GATE_DECISION_20260731.md](experiments/decisions/phase-f/PHASE_F_ARVO_PATCH_GATE_DECISION_20260731.md) - ARVO public developer-patch collection, 200-record manual FAIL EARLY, and training rejection.
- [PHASE_F_PATCH_LABEL_SUPPLY_DECISION_20260731.md](experiments/decisions/phase-f/PHASE_F_PATCH_LABEL_SUPPLY_DECISION_20260731.md) - CVEfixes verified archive/import and 6,248-pair supply PASS followed by manual `11/28 FAIL EARLY`.
- [PHASE_F_DECOMPILE_BENCH_ALIGNMENT_DECISION_20260731.md](experiments/decisions/phase-f/PHASE_F_DECOMPILE_BENCH_ALIGNMENT_DECISION_20260731.md) - Decompile-Bench 100-pair alignment `96/100 PASS`, partial repository provenance, and training hold.
- [PHASE_F_ASSEMBLAGE_METADATA_DECISION_20260731.md](experiments/decisions/phase-f/PHASE_F_ASSEMBLAGE_METADATA_DECISION_20260731.md) - Assemblage artifact/schema PASS and strict metadata intersection `0`, with raw ELF and training rejected.
- [PHASE_F_BINKIT_METADATA_DECISION_20260731.md](experiments/decisions/phase-f/PHASE_F_BINKIT_METADATA_DECISION_20260731.md) - BinKit matrix documentation PASS and external dataset artifact/license/schema hold.
- [PHASE_F_EMBER2024_BENCHMARK_DECISION_20260731.md](experiments/decisions/phase-f/PHASE_F_EMBER2024_BENCHMARK_DECISION_20260731.md) - EMBER2024 ELF archive/schema PASS and required 12,000-to-6,000 observation deduplication contract.
- [PHASE_F_EMBER2024_CLASSIFIER_BASELINE_DECISION_20260731.md](experiments/decisions/phase-f/PHASE_F_EMBER2024_CLASSIFIER_BASELINE_DECISION_20260731.md) - Temporal LightGBM and official model absolute-gate FAIL, with NuriLab signal integration held.
- [SOURCE_MANUAL_REVIEW_RUBRIC.md](evaluation/SOURCE_MANUAL_REVIEW_RUBRIC.md) - Source label, execution path, exact span, and causal-evidence review rubric.

이 디렉터리는 `AegisLM`의 세부 기준과 실험 문서를 관리합니다.

루트 [README.md](../README.md)는 프로젝트 정체성, 현재 Phase, 큰 로드맵, 주요 문서 링크만 유지합니다. 세부 기준, 실험 계획, 기여 절차, 테스트 기준은 이 디렉터리 아래 문서에 기록합니다.

## 문서 지도

| 문서 | 역할 |
| --- | --- |
| [CONTRIBUTING.md](governance/CONTRIBUTING.md) | 팀원이 작업을 시작하고 PR을 제출하기 위한 실행 가이드 |
| [ARTIFACT_STORAGE_POLICY.md](operations/policies/ARTIFACT_STORAGE_POLICY.md) | fine-tuning adapter, checkpoint, model card, evaluation artifact 저장 정책 |
| [DATASET_CANDIDATES.md](design/datasets/DATASET_CANDIDATES.md) | Phase D/E 이후 공개 데이터셋 후보 registry와 안전성/용도 분류 |
| [DATA_STRATEGY.md](design/datasets/DATA_STRATEGY.md) | Phase C 데이터 활용 전략, 전처리, tokenization/chunking, split, RAG/vector 분리 기준 |
| [EVALUATION_PLAN.md](evaluation/EVALUATION_PLAN.md) | Phase D/E 평가 계획, 점수화 기준, JSON/HTML 리포트 형식 |
| [FINETUNING_TEST_WORKBOOK.md](operations/b200/FINETUNING_TEST_WORKBOOK.md) | B200 수동 파인튜닝 검증 진행표, 실행 명령, 기록란, NuriLab 연결 가설, 120B 후보 |
| [PHASE_F_DATASET_AND_BINARY_EXPERIMENT_PLAN.md](experiments/plans/PHASE_F_DATASET_AND_BINARY_EXPERIMENT_PLAN.md) | Phase F F0–F9 데이터 감사, Qwen 신규 학습, source/binary 절대 gate와 실행 순서 |
| [AGENT_WORKFLOW.md](governance/AGENT_WORKFLOW.md) | 사용자·sol_main·역할 기반 custom agent의 권한, 승인과 증거 제출 규칙 |
| [COMMIT_REVIEW_GUIDE_KO.md](../review/guides/COMMIT_REVIEW_GUIDE_KO.md) | Phase F 브랜치 20개 커밋의 시간순 목적, 실제 결과, 핵심 파일, 현재 유지 판정을 설명하는 한국어 리뷰 지도 |
| [코드 리뷰 기록](../review/README.md) | 커밋·영역·파일 단위 상세 코드 리뷰와 데이터 품질·운영·구조별 발견 사항 추적 |
| [LOCAL_LLM_MCP_BOUNDARY_IDEA.md](design/architecture/LOCAL_LLM_MCP_BOUNDARY_IDEA.md) | Base local LLM+analyzer MCP 우선 검증, AegisLM/NuriLab 책임 경계와 보안 조건을 기록한 미확정 아이디어 |
| [PHASE_F_BINARY_ROLE_TARGET_DECISION_20260731.md](experiments/decisions/phase-f/PHASE_F_BINARY_ROLE_TARGET_DECISION_20260731.md) | Binary role target v2 실패, strict v4–v7 quarantine, 644-pair 품질 승인·공급 차단 결정 |
| [PHASE_F_ARVO_PATCH_GATE_DECISION_20260731.md](experiments/decisions/phase-f/PHASE_F_ARVO_PATCH_GATE_DECISION_20260731.md) | ARVO 200건 patch↔buffer-family 수동 `FAIL EARLY`와 학습 불승인 결정 |
| [PHASE_F_PATCH_LABEL_SUPPLY_DECISION_20260731.md](experiments/decisions/phase-f/PHASE_F_PATCH_LABEL_SUPPLY_DECISION_20260731.md) | CVEfixes archive·SQLite·6,248쌍 공급 PASS 뒤 수동 `11/28 FAIL EARLY`, direct-label 학습 거부 |
| [PHASE_F_DECOMPILE_BENCH_ALIGNMENT_DECISION_20260731.md](experiments/decisions/phase-f/PHASE_F_DECOMPILE_BENCH_ALIGNMENT_DECISION_20260731.md) | Decompile-Bench 정렬 `96/100 PASS`, repository provenance 84.66%, compiler·license metadata 부족으로 학습 보류 |
| [PHASE_F_ASSEMBLAGE_METADATA_DECISION_20260731.md](experiments/decisions/phase-f/PHASE_F_ASSEMBLAGE_METADATA_DECISION_20260731.md) | Assemblage artifact·schema PASS 뒤 strict complete row 0으로 raw ELF·학습 불승인 |
| [PHASE_F_BINKIT_METADATA_DECISION_20260731.md](experiments/decisions/phase-f/PHASE_F_BINKIT_METADATA_DECISION_20260731.md) | BinKit matrix 확인 뒤 고정 dataset artifact·license·schema 부재로 binary·pickle 다운로드 보류 |
| [PHASE_F_EMBER2024_BENCHMARK_DECISION_20260731.md](experiments/decisions/phase-f/PHASE_F_EMBER2024_BENCHMARK_DECISION_20260731.md) | EMBER2024 ELF 12,000행의 중복을 제거한 6,000관측치 독립 static-feature benchmark 승인 |
| [PHASE_F_EMBER2024_CLASSIFIER_BASELINE_DECISION_20260731.md](experiments/decisions/phase-f/PHASE_F_EMBER2024_CLASSIFIER_BASELINE_DECISION_20260731.md) | 자체 temporal LightGBM·공식 모델의 6,000건 절대평가 FAIL과 NuriLab 연결 보류 |
| [SOURCE_MANUAL_REVIEW_RUBRIC.md](evaluation/SOURCE_MANUAL_REVIEW_RUBRIC.md) | Source target의 label·실행 경로·exact span·인과관계 수동 검토 기준 |
| [EXPERIMENT_LOG_TEMPLATE.md](templates/EXPERIMENT_LOG_TEMPLATE.md) | baseline/adapter 평가 결과를 같은 형식으로 기록하기 위한 템플릿 |
| [PHASE_D_EXIT_CRITERIA.md](evaluation/PHASE_D_EXIT_CRITERIA.md) | Phase D 완료 조건과 Phase E tiny SFT PoC 착수 gate |
| [PHASE_E_TEAM_ONBOARDING.html](onboarding/PHASE_E_TEAM_ONBOARDING.html) | Phase E 이슈 처리와 팀 교육 주제를 한 장으로 정리한 온보딩 인포그래픽 |
| [FINETUNING_EXPERIMENT_PLAN.md](experiments/plans/FINETUNING_EXPERIMENT_PLAN.md) | 파인튜닝 학습 로드맵, 실험 전략, 데이터셋 계획 |
| [PR_DESCRIPTION_TEMPLATE.md](templates/PR_DESCRIPTION_TEMPLATE.md) | PR 본문 작성 템플릿과 체크리스트 |
| [QUALITY_GATES.md](governance/QUALITY_GATES.md) | 코드 변경 PR의 pytest, ruff, mypy 검사 기준 |
| [TEST_CRITERIA.md](evaluation/TEST_CRITERIA.md) | Phase C 테스트 기준, JSON schema 검증 기준, 평가 레퍼런스 |

## 문서 관리 규칙

- README에는 프로젝트의 큰 방향과 현재 상태만 적는다.
- 세부 기준, 실험 계획, 기여 규칙, 테스트 기준은 `docs/` 아래 문서에 기록한다.
- 새 기준이 생기면 가장 가까운 기존 문서에 추가한다.
- 성격이 독립적인 기준이면 `docs/`에 새 문서를 만든다.
- 문서를 추가하거나 이동하면 `README.md`, `docs/README.md`, `AGENTS.md`의 링크와 작업 규칙을 함께 갱신한다.
- schema, dataset format, prompt contract, evaluation metric 변경은 관련 문서와 테스트를 함께 갱신한다.
