# Phase F Decompile-Bench 정렬·출처 gate 결정

## 결정

고정 revision의 Decompile-Bench 첫 Arrow shard는 source–assembly 표현 정렬
참고 자료로 승인한다. 그러나 Phase F binary adapter의 학습 데이터로는
승인하지 않는다.

- alignment quality: `PASS` — 100건 중 96건 통과, 오류 4건
- provenance: `PARTIAL` — 131,359건 중 111,206건(84.6581%)만
  `owner[P]repository` 경로로 명시적 복원
- repository license: `BLOCKED` — 1,066개 명시 repository의 행별 license
  증거가 shard에 없음
- compiler/optimization: `BLOCKED` — 학습 compiler와 최적화 수준을 구분할
  metadata가 없음
- vulnerability label: 없음 — 취약점 존재 여부나 patch-localized CWE
  공급원으로 사용하지 않음
- 최종 disposition: `alignment_reference_only`
- `approved_for_training=false`

이 결과는 Decompile-Bench의 품질 전체를 부정하는 판정이 아니다. Phase F가
요구하는 상용화 가능한 출처 추적, compiler 변형 강건성, 취약점 근거 계약을
이 shard 단독으로 충족하지 못한다는 뜻이다.

## 동결한 입력

| 항목 | 값 |
| --- | --- |
| dataset | `LLM4Binary/decompile-bench` |
| revision | `4b708c2211cd7d4af403675db56322aa4ed7050c` |
| shard | `data-00000-of-00017.arrow` |
| bytes | `489,618,088` |
| shard SHA-256 | `2a68cfda840f0c1aa1b6846b78fa9cce961cd2da42be5043579c53c1f69332b5` |
| rows | `131,359` |
| exact duplicate rows | `1,298` (`0.9881%`) |
| review seed / size | `20260731 / 100` |
| queue SHA-256 | `01f6b95e545d23765abdc99a20fbb1877ba06a71006606a495eb505ec2a36c39` |

전체 17개 shard, Decompile-Bench-Eval, raw binaries와 executables는 받지
않았다. source와 assembly는 실행하지 않았으며, 고정 100건의 정적 검토에만
사용했다.

## 수동 alignment gate

판정 기준은 다음 세 가지다.

1. source와 assembly가 같은 함수인가
2. source가 완전하여 의미 판단이 가능한가
3. 주요 제어 흐름, 호출, 상태 변경이 assembly에 보존되는가

`uncertain`은 오류로 계산하고, 허용 예산은 최대 `5/100`으로 고정했다.
결과는 다음과 같다.

| 결과 | 건수 |
| --- | ---: |
| PASS | 96 |
| 오류 | 4 |
| 미검토 | 0 |
| 남은 오류 예산 | 1 |

오류 4건은 모두 compiler 최적화 차이가 아니라 다른 source 함수와 assembly가
짝지어진 명백한 `different_function + semantic_mismatch`였다.

- `bitset_container_get` source ↔ `bitset_container_get_index` assembly
- 한 줄 SIMD inequality source ↔ 대형 BVH traversal assembly
- `IsObject` source ↔ `FindMember` assembly
- `DepsLog Recompact` test source ↔ fixture destructor assembly

| artifact | SHA-256 |
| --- | --- |
| review decisions | `0bf418152ca87cad6fffdc1f2700d67580f96da75b43e23767c9454c79445c16` |
| review result | `87104c7b9225820b2f0f935dcdd71ecf6a8cb0ad612908517ef70243c9bc2795` |

## provenance gate

`file` 필드의 `/owner[P]repository/...` 형식은 명시적 repository만
보수적으로 복원한다. 형식이 다른 경로를 LLVM 등으로 추측하여 채우지
않았다.

| 항목 | 결과 |
| --- | ---: |
| 전체 행 | 131,359 |
| 명시 repository 행 | 111,206 |
| 명시 repository 비율 | 84.6581% |
| 미복원 행 | 20,153 |
| 고유 명시 repository | 1,066 |
| 수동 100건 중 명시 repository | 88 |
| 명시 repository이면서 alignment PASS | 84 |

provenance audit SHA-256은
`68b4b51d3968a53bd711886e3d75ea02d9de5c8794c6eef733bb5b06c5525c36`이다.

공식 Hugging Face dataset card는 dataset license를 `CC0-1.0`으로
표시한다. 공식 프로젝트 문서와 논문은 permissively licensed GitHub
프로젝트에서 수집했다고 설명한다. 그러나 공개 Arrow 계약은
`name/code/asm/file` 네 필드뿐이며 repository별 SPDX, commit, compiler,
optimization을 제공하지 않는다. 따라서 dataset-level 표기만으로 1,066개
원본 프로젝트의 행별 license 증거를 대체하지 않는다.

## 다음 단계

1. Decompile-Bench는 representation·정렬 회귀 참고 자료로만 보존한다.
2. 향후 사용 시 명시 repository 행만 대상으로 repository별 license를
   독립 검증하고, 미복원 행은 제외한다.
3. Phase F의 다음 alignment 공급 후보는 repository license와 build
   configuration을 보존하는 Assemblage metadata다.
4. Assemblage에서도 metadata와 필요한 소규모 함수 subset만 감사한다.
   전체 PE/ELF corpus나 executable을 다운로드·실행하지 않는다.
5. 취약점 label은 계속 SARD/Juliet 또는 검증된 patch/CWE 근거에서만
   공급한다.

## 근거

- [Decompile-Bench dataset card](https://huggingface.co/datasets/LLM4Binary/decompile-bench)
- [LLM4Decompile Decompile-Bench documentation](https://github.com/albertan017/LLM4Decompile/tree/main/decompile-bench)
- [Decompile-Bench paper](https://arxiv.org/abs/2505.12668)
