---
type: Decision Note
title: Mistral F5-X Runtime Compatibility Matrix v1 Work Order
description: 기존 Qwen 환경을 보존하면서 Mistral 전용 probe 환경과 재현 가능한 runtime 후보 검사를 구현하기 위한 동결 작업 지시서
tags: [aegislm, mistral, axolotl, compatibility, work-order]
timestamp: 2026-08-08
status: active
---

# Work Order

```yaml
work_order_id: mistral-f5x-runtime-compatibility-matrix-v1
status: complete
owner: user
base_commit: cb520cdd132f86f23fc45a8800cb6c20c3ab9dc3
head_sha: cb520cdd132f86f23fc45a8800cb6c20c3ab9dc3
worktree_diff_sha256: eaa652b9eea6cec94f6d491f8e12817935174eb6ff9912d9a34532d50963b6f0
baseline:
  dirty_file_count: 22
  dirty_diff_sha256: eaa652b9eea6cec94f6d491f8e12817935174eb6ff9912d9a34532d50963b6f0
  serialization: "status<TAB>path<TAB>file SHA-256<LF>"
delegation: forbidden

orchestration:
  delegation_policy: orchestrator_only
  allowed_delegator: sol_main
  worker_delegation: forbidden
  max_delegation_depth: 1
  max_parallel_workers: 2

workers:
  - worker_id: terra-runtime-planner
    role: planner
    mode: plan
    required_sandbox_mode: read-only
    required_approval_policy: no external mutation
    allowed_files: []
    state: complete
  - worker_id: luna-runtime-implementer
    role: implementer
    mode: implementation
    required_sandbox_mode: workspace-write
    required_approval_policy: no install, download, SSH, GPU, symlink, or Git mutation
    allowed_files:
      - configs/runtime/mistral_f5x_compatibility_matrix.json
      - aegislm/experiments/runtime_compatibility.py
      - scripts/probe_mistral_f5x_compatibility.py
      - tests/test_mistral_runtime_compatibility.py
      - .gitignore
      - docs/operations/b200/B200_2GPU_SETUP.md
      - docs/operations/b200/FINETUNING_TEST_WORKBOOK.md
      - review/workflows/mistral-f5x-runtime-compatibility-matrix-v1/03-implementer-evidence.md
    state: complete

objective: >-
  기존 Qwen/AegisLM .venv와 root dependency lock을 변경하지 않고, 폐기 가능한
  Mistral probe 환경에서 Axolotl/Transformers 조합을 정직한 resolver와 uv pip check로
  평가하고, 통과한 조합만 최종 .venv-axolotl 후보로 승격할 수 있는 CPU 구현과
  B200 실행 계약을 만든다.

out_of_scope:
  - dependency 설치 또는 lock 생성
  - 모델·tokenizer·데이터 다운로드
  - SSH 또는 GPU 실행
  - 실제 symlink 생성
  - configs/experiment.yaml immutable pin 변경
  - 최종 runtime manifest pin 변경
  - G1/G2/G3 학습
  - Git stage, commit, push, PR

immutable_inputs:
  approved_axolotl_revision: 3c8334b6f9ae6bf5596f99a1845525c8ffc0a97a
  approved_transformers_revision: d24d79da55f7ee6e538a460d3025e41dcc41ab21
  approved_cut_cross_entropy_revision: 5f0c7a7778b5b17d37738fae10065ed3034373af
  python_version: "3.12"
  torch_version: 2.12.1
  cuda_version: "13.0"
  gpu_contract: 2x NVIDIA B200

candidate_policy:
  current_declared_pair: approved Axolotl commit with its declared Transformers 5.14.1
  approved_pair_negative_control: approved Axolotl and approved Transformers commits; expected conflict is preserved
  official_consistent_candidate: exact official Axolotl commit with Mistral Small 4 support and its declared Transformers dependency
  prohibited_overrides:
    - --no-deps
    - dependency metadata patching
    - ignored uv pip check failures
    - floating latest versions

allowed_files:
  - configs/runtime/mistral_f5x_compatibility_matrix.json
  - aegislm/experiments/runtime_compatibility.py
  - scripts/probe_mistral_f5x_compatibility.py
  - tests/test_mistral_runtime_compatibility.py
  - .gitignore
  - docs/operations/b200/B200_2GPU_SETUP.md
  - docs/operations/b200/FINETUNING_TEST_WORKBOOK.md
  - review/workflows/mistral-f5x-runtime-compatibility-matrix-v1/00-work-order-v1.md
  - review/workflows/mistral-f5x-runtime-compatibility-matrix-v1/01-sol-main-dispatch.md
  - review/workflows/mistral-f5x-runtime-compatibility-matrix-v1/02-planner-plan.md
  - review/workflows/mistral-f5x-runtime-compatibility-matrix-v1/03-implementer-evidence.md
  - review/workflows/mistral-f5x-runtime-compatibility-matrix-v1/05-sol-main-final.md

forbidden_files:
  - pyproject.toml
  - uv.lock
  - configs/experiment.yaml
  - configs/runtime/mistral_f5x_environment.json
  - .venv
  - .venv-axolotl
  - model
  - data
  - training_artifacts

gates:
  pass:
    - exact-schema compatibility matrix with no placeholders, secrets, absolute paths, or parent traversal
    - exclusive probe directory naming outside .venv and .venv-axolotl
    - validate and plan actions are filesystem-pure
    - probe action requires raw-byte matrix approval hash and refuses existing directories
    - commands use normal dependency resolution and uv pip check with no override escape hatch
    - candidate evidence records commands, exit codes, package versions, direct_url commits, imports, CUDA and GPU identity
    - existing Qwen .venv fingerprint contract is checked before and after probe
    - targeted tests, full pytest, Ruff check and format-check, and mypy pass
  block:
    - baseline HEAD or dirty hash changes before dispatch
    - allowlist expansion or immutable pin change is needed
    - dependency installation, download, SSH, GPU, symlink, or Git mutation is attempted
    - current Qwen .venv or root dependency files are modified

approvals_required:
  dependency_install: true
  model_or_data_download: true
  gpu_execution: true
  ssh_execution: true
  symlink_creation: true
  git_stage_commit_push: true

required_evidence:
  - actor_role
  - work_order_id
  - parent_work_order_id
  - head_sha
  - worktree_diff_sha256
  - result
  - delegation_used
  - delegated_to
  - effective_sandbox_mode
  - effective_approval_policy
  - commands
  - changed_files
  - out_of_allowlist_changes
  - preexisting_changes_preserved
  - failed_skipped_not_executed
  - evidence_complete
  - revalidation_basis
  - revalidation_reason
  - known_limitations
  - approval_required_next
```

# Baseline Dirty Files

기준선은 `git status --porcelain=v1 --untracked-files=all`의 상태와 경로를 정렬된
출력 순서대로 사용하며, 각 현재 파일의 SHA-256을 결합한다. 2026-08-08 재검증에서
tracked 변경 10개와 untracked 파일 12개, 합계 22개가 확인되었다. 이 변경은 앞선
통합 설정 및 runtime readiness 작업의 사용자 승인 변경으로 간주하고 보존한다.

# Related Concepts

- [에이전트 운영 가이드](../../../docs/governance/AGENT_WORKFLOW.md)
- [B200 설정](../../../docs/operations/b200/B200_2GPU_SETUP.md)
- [파인튜닝 워크북](../../../docs/operations/b200/FINETUNING_TEST_WORKBOOK.md)
