# Phase F BinKit 2.0 Metadata Gate 결정

## 결정

BinKit 2.0은 compiler·architecture·optimization robustness 설계 참고
자료로 보존하지만, precompiled binary dataset이나 함수 `.pickle`을
다운로드·역직렬화·학습하지 않는다.

- compile-matrix documentation: `PASS`
- immutable code release: `PASS`
- dataset artifact contract: `FAIL`
- dataset license: `FAIL`
- row/function schema: `FAIL`
- final disposition: `metadata_hold`
- `approved_for_download=false`
- `approved_for_training=false`

## 확인된 강점

공식 README는 다음 matrix를 명시한다.

- binaries: `371,928`
- compile-option combinations: `1,904`
- architectures: `8`
- optimization levels: `6`
- compilers: `23`
- known missing binaries: GSL `Ofast` 8건

compiler variant 강건성 benchmark의 개념 설계에는 매우 적합하다. 그러나
문서화된 전체 수량과 실제 artifact의 행 단위 계약은 별개다.

## 고정한 공개 근거

| 항목 | 값 |
| --- | --- |
| repository | `SoftSec-KAIST/BinKit` |
| release | `v2.0.0` |
| release commit | `82bc979122843d3f3953bc02cfc3cc359935ceb8` |
| published | `2023-03-09T06:28:35Z` |
| GitHub release assets | `0` |
| repository code license | MIT |
| dataset distribution | Google Drive |
| dataset artifact bytes / SHA-256 | 없음 / 없음 |
| dataset license | 확인 불가 |

repository의 MIT license는 build scripts의 license다. GNU source package,
compiled binaries, extracted function feature의 재배포·학습 license를
자동으로 승인하지 않는다.

## 실패 사유

자동 preflight의 실패 사유는 다음과 같다.

- `artifact_size_known=false`
- `artifact_sha256_known=false`
- `artifact_url_pins_revision=false`
- `dataset_license_declared=false`
- `required_fields_present=false`
- `selected_components_payload_free=false`
- `storage_headroom=false` — artifact size가 없어 계산 불가

필수 metadata 중 `sample_identity`, `source_package`,
`repository_license`의 실제 row 계약을 확인할 수 없다.

## Pickle 안전 경계

공식 README는 함수별 extracted feature와 정보를 `.pickle`로 제공한다고
설명한다. Python pickle은 역직렬화 중 임의 코드 실행이 가능하므로
출처가 공개됐다는 이유만으로 로드하지 않는다.

- pickle download: 0
- pickle deserialization: 0
- binary download: 0
- executable execution: 0

사용하려면 upstream checksum과 schema를 확보한 뒤 격리된 비실행
parser 또는 별도 변환본을 요구한다.

## Evidence

- metadata preflight SHA-256:
  `285c0e514b2c958620f7b060d5b0e3817df9423133e0a7f4acd7a99974c76530`
- final disposition: `metadata_hold`
- download / processing / training: `false / false / false`

## 다음 단계

1. BinKit binary와 pickle을 다운로드하지 않는다.
2. upstream이 versioned artifact, size, checksum, dataset license,
   row/function schema를 제공하면 새 preflight를 수행한다.
3. compile matrix는 향후 자체 build dataset의 quota 설계에만 참고한다.
4. 다음 후보는 EMBER2024의 metadata/static-feature benchmark 계약이다.
5. EMBER2024도 SFT 학습 데이터가 아니라 독립 절대평가 후보로 감사한다.

## 근거

- [BinKit repository and dataset documentation](https://github.com/SoftSec-KAIST/BinKit)
- [BinKit v2.0.0 release](https://github.com/SoftSec-KAIST/BinKit/releases/tag/v2.0.0)
