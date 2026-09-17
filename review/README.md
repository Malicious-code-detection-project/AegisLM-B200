# AegisLM 코드 리뷰 기록

이 디렉터리는 현재 Phase F 브랜치의 코드를 사용자와 커밋 순서대로 읽으며
확인한 내용을 보관합니다. `review/guides/COMMIT_REVIEW_GUIDE_KO.md`가 전체 20개
커밋의 지도라면, 이 디렉터리는 실제 파일 단위 리뷰와 수정 후보의 근거를
보관하는 곳입니다.

코드 리뷰 기록은 코드 수정 완료를 의미하지 않습니다. 발견 사항은 별도 상태를
가지며, 사용자가 수정 범위를 확정하기 전에는 코드에 반영하지 않습니다.

## 디렉터리 구조

```text
review/
├── README.md
└── commit-01/
    ├── README.md
    └── source/
        ├── README.md
        ├── 01-build-script.md
        ├── 02-sard-juliet.md
        └── findings/
            ├── README.md
            ├── data-quality.md
            ├── operations-and-reproducibility.md
            └── structure-and-boundaries.md
```

향후 리뷰는 `commit-NN/<area>/` 단위로 추가합니다. 하나의 커밋이 source,
binary, serving 등 여러 책임을 포함하면 area를 나누어 기록합니다.

## 진행 현황

| 커밋 | 영역 | 상태 | 다음 파일 |
| --- | --- | --- | --- |
| Commit 1 `618db23` | 1-A SARD/Juliet source | 진행 중 | `aegislm/datasets/source.py` |
| Commit 1 `618db23` | 1-B Q1R10/Q1R11 | 미시작 | 1-A 완료 후 시작 |
| Commit 1 `618db23` | 1-C Binary compile/Ghidra | 미시작 | 1-B 완료 후 시작 |
| Commit 2–20 | 각 커밋 | 미시작 | Commit 1 완료 후 시작 |

현재까지 완료한 파일 리뷰:

1. [`scripts/build_sard_juliet_source_dataset.py`](commit-01/source/01-build-script.md)
2. [`aegislm/datasets/sard_juliet.py`](commit-01/source/02-sard-juliet.md)

## 판정과 상태

파일 판정:

- `유지`: 현재 책임과 구현을 그대로 유지할 수 있습니다.
- `수정 후 유지`: 기능은 필요하지만 품질·구조·보안 보강이 필요합니다.
- `연구 보관`: 실패 원인이나 실험 증거로 보존하되 핵심 경로에서는 제외합니다.
- `제거 후보`: 중복되거나 현재 경로에서 사용하지 않는 코드입니다.

발견 사항 상태:

- `Open`: 리뷰에서 발견했으며 아직 수정하지 않았습니다.
- `Accepted`: 수정 범위와 방향을 사용자와 합의했습니다.
- `Fixed`: 코드·테스트·문서 수정과 검증이 끝났습니다.
- `Deferred`: 이유와 재검토 조건을 기록하고 보류했습니다.

우선순위:

- `P0`: 데이터 유출·파괴 또는 잘못된 학습 승인을 즉시 유발할 수 있습니다.
- `P1`: 학습 데이터 의미나 연구 결론을 왜곡할 가능성이 큽니다.
- `P2`: 구조·재현성·유지보수성을 약화합니다.
- `P3`: 가독성·주석·명명 개선 사항입니다.

## 기록 원칙

- 저장소 상대경로만 사용합니다.
- 서버 절대경로, token, secret, raw payload를 기록하지 않습니다.
- 확인된 사실과 개선 제안을 구분합니다.
- 성능 수치는 무엇을 gold로 삼았는지 함께 기록합니다.
- 리뷰 완료 전에는 코드 로직을 수정하지 않습니다.
- 수정할 때는 발견 사항 ID를 커밋 또는 PR 설명에서 연결합니다.

## 관련 문서

- [20개 커밋 한국어 리뷰 지도](guides/COMMIT_REVIEW_GUIDE_KO.md)
- [Source 수동 검토 기준](../docs/evaluation/SOURCE_MANUAL_REVIEW_RUBRIC.md)
- [로컬 LLM과 analyzer MCP 책임 경계 아이디어](../docs/design/architecture/LOCAL_LLM_MCP_BOUNDARY_IDEA.md)
