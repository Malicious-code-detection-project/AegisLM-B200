---
type: Decision Note
title: Mistral F5-X Runtime Compatibility Matrix v1 Sol Dispatch
description: 동결 Work Order에 따른 Terra 계획 검토와 Luna 구현의 역할·권한 경계
tags: [aegislm, mistral, agents, dispatch]
timestamp: 2026-08-08
status: active
---

# Dispatch

```yaml
work_order_id: mistral-f5x-runtime-compatibility-matrix-v1
actor_role: sol_main
parent_work_order_id: not_applicable
head_sha: cb520cdd132f86f23fc45a8800cb6c20c3ab9dc3
baseline_worktree_diff_sha256: eaa652b9eea6cec94f6d491f8e12817935174eb6ff9912d9a34532d50963b6f0
result: DISPATCHED
delegation_used: true
delegated_to:
  - terra-runtime-planner: read-only plan validation
  - luna-runtime-implementer: sequential implementation after planner evidence
effective_sandbox_mode: workspace-write
effective_approval_policy: managed; external mutation requires explicit approval
max_delegation_depth: 1
max_parallel_workers: 2
worker_delegation: forbidden
dispatch_order:
  - terra-runtime-planner
  - luna-runtime-implementer
permissions:
  dependency_install: false
  model_or_data_download: false
  ssh_execution: false
  gpu_execution: false
  symlink_creation: false
  git_stage_commit_push: false
```

Terra는 저장소를 수정하지 않는 계획 검토만 수행한다. Luna는 Terra의 증거를 Sol이
검토한 뒤에만 dispatch하며 Work Order의 implementer allowlist 안에서 CPU 구현과
테스트만 수행한다. 두 worker 모두 다른 worker를 호출할 수 없다.

# Related Concepts

- [Work Order](00-work-order-v1.md)
- [에이전트 운영 가이드](../../../docs/governance/AGENT_WORKFLOW.md)
