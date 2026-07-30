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

## Strict Supply v3 Result

generic fallback을 끄고 12개 CWE extractor만 허용한
`strict-cwe-role-evidence-v3` 공급 감사 결과는 다음과 같습니다.

- tokenizer-qualified: `1,301/2,924` pair
- original 2,450-pair quota: FAIL
- review eligibility: PASS
- gate SHA-256:
  `d5787e2a2dcbf24a8694aadbf7d022a2c4ef9d4b4b829fce7feeaf177a365e56`
- 고정 100건 검토: evidence error `6/100`, `FAIL EARLY`
- 결정 적용 manifest SHA-256:
  `4dac96b5fa2d7981559b07adf704f9c871e03b47c02a1c04b008273a98dd60a4`

strict v3는 문제를 CWE-124, CWE-127, CWE-457, CWE-690 extractor로
좁혔습니다. 이 네 범주는 다음 공급 계산에서 quarantine합니다. 나머지
extractor도 새 표본으로 다시 검증하기 전에는 학습 승인을 받지 않습니다.

관련 기준은
[Phase F 계획](PHASE_F_DATASET_AND_BINARY_EXPERIMENT_PLAN.md)과
[수동 검증 워크북](FINETUNING_TEST_WORKBOOK.md)을 따릅니다.

## Strict Supply v4–v7 Result

strict v3의 실패 CWE를 한 번에 숨기지 않고, 매 iteration마다 실패 범주만
추가 quarantine한 뒤 새 고정 seed 100건을 다시 검토했습니다.

| Iteration | 새 quarantine | 적격 pair | 수동 검토 | 결론 |
|---|---|---:|---:|---|
| strict v4 | CWE-124/127/457/690 | `1,228` | `6/100 FAIL EARLY` | CWE-121 근거 불완전 |
| strict v5 | + CWE-121 | `928` | `6/100 FAIL EARLY` | CWE-122 근거 불완전 |
| strict v6 | + CWE-122 | `661` | `6/100 FAIL EARLY` | CWE-126 근거 불완전 |
| strict v7 | + CWE-126 | `644` | `1/100 PASS` | 5개 CWE 한정 품질 승인 |

v4의 CWE-121은 source length와 `strlen/wcslen` 파생 길이를, v5의
CWE-122는 실제 allocation capacity 또는 wide-string length 계산을,
v6의 CWE-126은 실제 read length를 만드는 `strlen/wcslen`을 누락했습니다.
이 범주는 학습 수량을 맞추기 위해 되살리지 않습니다.

strict v7의 지원 범위와 수량은 다음과 같습니다.

- CWE-134: `140` pair
- CWE-190: `299` pair
- CWE-191: `175` pair
- CWE-194: `18` pair
- CWE-195: `12` pair
- 합계: `644/2,450` pair

수동 검토의 유일한 오류는 CWE-190 fixed case가 실제
`sqrt(UINT_MAX)` 범위 검사를 누락하고 앞선 부호 정규화 조건만 인용한
것입니다. 오류율은 `0.01`로 허용 기준 `≤0.05`를 통과했습니다.

재현용 SHA-256은 다음과 같습니다.

- strict v7 tokenizer gate:
  `d9305d43939e355a968217dd426f6cc7ba10426a2a51dabeebfba146216efd35`
- 판정 적용 수동 검토 JSONL:
  `53b59d1686d072f1dcf5353531f7b4827c95d3243e320ddd8de89a2308469eef`
- 최종 review manifest:
  `865789a5f15aaffc1965eb63e8d514cbe018dd53ca8dcf11f6b4d6c67bb96cde`

## Final Decision

strict v7은 target 품질 gate는 통과했지만 공급량 gate
`644 < 2,450`을 통과하지 못했습니다. 따라서 이 644 pair는
`quality-approved / supply-blocked` seed로 동결합니다.

- binary-derived materialization: 보류
- binary adapter 학습: 시작하지 않음
- raw executable/object 실행: `0`
- 다음 작업: 동일 5개 CWE의 독립 pair 공급 확대 또는 격리된 CWE
  extractor의 관계 완전성 재설계

추가 공급이 목표량에 도달하더라도 split, O3+stripped robustness,
validation 400, blind test 500을 다시 동결하기 전에는 학습하지 않습니다.
