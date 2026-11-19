# 운영·재현성 발견 사항

## SRC-BUILD-01: tokenizer trust boundary

실제 Qwen tokenizer를 사용하는 결정은 정확하지만 `trust_remote_code=True`는
승인한 model repository와 revision에서만 허용해야 합니다.

제안:

- model identifier와 revision allowlist 기록
- revision을 실행 manifest에 기록
- 승인되지 않은 remote tokenizer code는 fail-closed

## SRC-BUILD-02: 공개 경로 정책

로컬·GPU 서버 절대경로는 재현 정보이면서 인프라 정보를 노출할 수 있습니다.
공개 문서와 manifest에는 다음처럼 기록합니다.

```text
data_root: <external-data-root>
artifact_root: <external-artifact-root>
relative_path: phase-f/source-v3/...
```

실제 root mapping은 Git 밖의 운영자 기록에 둡니다.

## SRC-BUILD-03: 출력 디렉터리 lifecycle

기존 실행과 새 실행이 같은 출력 디렉터리에 섞이면 checksums와 manifest의
의미가 불분명해집니다.

제안:

- run ID별 새 디렉터리 사용
- 비어 있지 않은 출력 디렉터리는 기본 거부
- overwrite가 필요하면 명시 옵션과 이전 manifest 확인 요구

## SRC-BUILD-04: token gate 이후 quota

선택된 pair가 token cutoff에서 탈락해도 reserve에서 자동 보충되지 않으면
목표 quota가 부족해질 수 있습니다. 수량을 억지로 채우면 안 되지만, 이미
품질 조건을 통과한 reserve는 deterministic하게 backfill할 수 있습니다.

제안:

- group split 뒤 각 계층 reserve 순서를 seed로 고정
- token 탈락 시 같은 계층·label의 eligible reserve만 보충
- 보충 후에도 부족하면 `evidence_supply_blocked` 유지

## 승인 우회 방지

`approved_for_training=false`는 manifest 필드만으로 끝나면 안 됩니다.
training entrypoint가 승인 manifest와 digest를 검증하도록 연결해야 합니다.

## Source audit 입력 결합

`source_audit.py`의 결과에는 dataset, manifest, evidence, tokenizer revision,
chat template와 system prompt digest가 모두 기록돼야 합니다. 현재는 tokenizer의
`name_or_path`만 기록하고 있어 local 절대경로가 노출될 수 있고 동일 렌더링 계약을
재현했다는 증거도 부족합니다.

또한 `enable_thinking=False` 호출이 TypeError를 내면 해당 인자를 제거해 재시도합니다.
모델 profile이 no-think를 보장하지 못하면 조용히 fallback하지 않고 실행을
차단해야 합니다.

## 검증 항목

- 동일 seed·동일 revision 재생성 hash 일치
- 다른 run의 파일 혼입 0
- 공개 artifact의 host 절대경로 0
- 승인되지 않은 tokenizer revision 실행 0
- semantic 오류 row의 materialized training shard 유입 0
- manifest·record의 빈 ID, 중복 ID, orphan row 0
- train·validation·challenge 파일 role과 manifest split 불일치 0
- audit 결과에 immutable input과 prompt contract digest 완비
