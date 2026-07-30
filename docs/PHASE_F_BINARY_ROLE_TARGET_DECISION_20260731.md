# Phase F Binary Role Target v2 Decision — 2026-07-31

## Outcome

Binary role target v2의 schema, semantic validator, 실제 Qwen tokenizer
gate, 고정 seed 수동 검토 경로를 구현했습니다. 두 iteration 모두 필요한
2,450 pair 공급은 확보했지만 수동 근거 품질 gate에서 `6/100`에 도달해
`FAIL EARLY`했습니다.

따라서 binary-derived dataset materialization, Qwen 80B LoRA 학습,
serving 평가는 승인하지 않습니다. raw executable 또는 object 실행 횟수는
계속 `0`입니다.

## Reproducible Results

| Iteration | 자동 공급 결과 | Gate SHA-256 | 수동 결과 | 승인 |
|---|---:|---|---:|---|
| v2 r1 | `2,450/2,479`, excluded 445 | `9b48a00c5be60f1fb3c8d2caf1f275086c510145ee540835355607d43d16577a` | `6/100 FAIL EARLY` | 아니오 |
| v2 r2 | `2,450/2,485`, excluded 439 | `bf910417b2830f2a962641665ee52adfcf8ab8afa434a149a99b65ffbf09f703` | `6/100 FAIL EARLY` | 아니오 |

r1 review 원본 SHA-256은
`f211482c893bf45557fc7eb89881ff88544d24680514e531ea9ffaffc908dc83`,
r2 review 원본 SHA-256은
`8f7844aa5bae111a111cf8749ae495b4188fd24cf7b48f0d9407bf8ee24a1990`
입니다. 결정 적용 후 r2 manifest SHA-256은
`b9a00eaa7a571dc1015228c669870fef40748d7d62486ffe90d50d6a437901f4`
입니다.

## What Failed

r1은 generic identifier-overlap fallback이 다음 관계를 잘못 만들었습니다.

- CWE-126: short buffer 선택·capacity 대신 `strlen(dest)` 연결
- CWE-134: 외부 format input 대신 로컬 pointer 대입 연결
- CWE-190/191: 입력 경로 대신 `data = 0` 연결
- CWE-194/195: signed conversion 대신 무관한 control/write 연결

r2는 이 여섯 회귀 사례를 교정했지만 다른 CWE에서 같은 구조적 문제가
다시 나타났습니다.

- CWE-23: 외부 path construction 대신 `close → open` 연결
- CWE-400: unbounded work 대신 `acceptSocket = -1 → recv` 연결
- CWE-401: missing release 대신 null guard를 allocation에 연결
- CWE-457: initialization 대신 서로 다른 struct read를 연결
- CWE-590: invalid pointer origin 대신 non-null guard를 delete에 연결
- CWE-606: untrusted iteration count 대신 `strlen → fgets` 연결

즉 JSON schema와 exact span 검사는 통과했지만, identifier가 겹친다는
사실만으로는 보안상 인과관계를 증명할 수 없습니다.

## Decision

다음 iteration은 전체 CWE에 generic fallback을 적용하지 않습니다.

1. CWE별 `source/control/bound/remediation/sink` extractor와 필수 role
   조합을 명시합니다.
2. extractor가 완전하지 않은 CWE는 `eligible`이 아니라 `quarantine`으로
   분류합니다.
3. 기존 2,450 pair 수량을 목표로 저신뢰 target을 채우지 않습니다.
4. strict extractor 공급량을 다시 측정하고, 실제 수량에 맞춰 binary
   dataset 규모를 축소합니다.
5. 새 고정 100건에서 오류가 `≤5/100`일 때만 materialization과 학습을
   허용합니다.

## Next Gate

- generic identifier-overlap fallback 사용 `0`
- 지원 CWE마다 role-completeness unit test 존재
- unsupported CWE가 명시적인 사유와 함께 quarantine됨
- 실제 Qwen tokenizer cutoff 통과 공급량 기록
- 고정 seed 100건 수동 evidence error `≤0.05`
- raw payload 및 object 실행 `0`

관련 기준은
[Phase F 계획](PHASE_F_DATASET_AND_BINARY_EXPERIMENT_PLAN.md)과
[수동 검증 워크북](FINETUNING_TEST_WORKBOOK.md)을 따릅니다.
