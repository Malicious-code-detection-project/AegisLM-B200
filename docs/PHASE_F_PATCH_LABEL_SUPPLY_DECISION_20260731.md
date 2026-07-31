# Phase F Patch-localized Label Supply Decision — 2026-07-31

## Outcome

ARVO patch gate 실패 뒤 patch-localized CWE 공급 후보를 공식 metadata부터
다시 감사했습니다. 현재 결정은 다음과 같습니다.

| 후보·단계 | 결과 | 허용 범위 |
| --- | --- | --- |
| MegaVul main metadata | `HOLD` | immutable dataset release·license·고정 artifact 정보 확보 전 다운로드 금지 |
| CVEfixes v1.0.8 acquisition | `PASS` | 고정 archive 확보 |
| archive·SQL·SQLite lifecycle | `PASS` | read-only 공급량 감사 |
| C/C++ before/after 공급량 | `PASS` | metadata catalog 생성 |
| 200쌍 catalog·선택 추출 | `PASS` | 수동 evidence review |
| 수동 patch↔CWE 검토 | `PENDING` | training 불승인 |

따라서 CVEfixes는 현재 `manual_review_ready`입니다. 이는 데이터 품질이나
학습 승인이 아닙니다. 200쌍 수동 검토와 repository code license 검토가
끝나기 전에는 bulk materialization, processing, training을 허용하지 않습니다.

## Official Source and License Boundary

CVEfixes v1.0.8은 공식 Zenodo record가 고정 버전, archive 크기와 MD5,
CC BY 4.0 database license를 제공합니다. collector 코드는 MIT입니다.

- version: `v1.0.8`
- Zenodo record: `13118970`
- DOI: `10.5281/zenodo.13118970`
- archive: `CVEfixes_v1.0.8.zip`
- expected bytes: `12,708,711,268`
- upstream MD5: `4586a358977acfa4c60b1a2cdd096221`
- database license: `CC-BY-4.0`
- collector license: `MIT`

CC BY 4.0 database license를 원 repository source code의 라이선스로
간주하지 않습니다. 각 repository code license는 학습 전 별도로 확인합니다.

MegaVul은 공식 repository의 GPL-3.0 code license를 dataset payload
license로 간주하지 않았습니다. immutable release, dataset license,
versioned HTTPS artifact URL, byte size, checksum이 없으므로 현재 main
commit `2b34eb3685b2a215d44c08d34fe9cec0f49eada3`만 기록하고 대기합니다.

## Acquisition and Integrity Results

공식 archive는 기존 2,146,467,840-byte prefix와 검증된 HTTP 206 range
8개를 정확한 offset으로 조립했습니다. 각 range의 길이와 연속성을 확인한
뒤 official MD5가 일치할 때만 최종 경로에 원자적으로 게시했습니다.

| 항목 | 결과 |
| --- | --- |
| archive path | `data/raw_data/cvefixes/v1.0.8/CVEfixes_v1.0.8.zip` |
| observed bytes | `12,708,711,268` |
| observed MD5 | `4586a358977acfa4c60b1a2cdd096221` |
| observed SHA-256 | `6acd55aaeb7ffcfc20fdcebf7df88d206f9892ef64b0f2a2e06864d5b44b3a83` |
| range assembly report SHA-256 | `124e599cb9e148dce74ef5d14ea62e624174c4cab044e58f653cd6a904cf12fc` |

비추출 ZIP inventory는 central directory만 읽었습니다.

| 항목 | 결과 |
| --- | --- |
| member count | `15` |
| unsafe/encrypted/symlink/executable members | `0 / 0 / 0 / 0` |
| outer uncompressed bytes | `12,776,181,655` |
| compression ratio | 약 `1.0053` |
| inventory report SHA-256 | `25d09d7bfe012eddd90bea39c87e1200457d8c6adfde8bfd0894b1c245ce55ea` |
| bulk extraction | `false` |

필요한 `CVEfixes_v1.0.8.sql.gz` 한 member만 선택 추출했습니다. log와
NVD archive는 추출하지 않았습니다.

- SQL gzip bytes: `12,660,640,828`
- SQL gzip SHA-256:
  `36ad1e786e5a40fdb6342aa1ce3e816d4c412be451917cd12c4dd240d5427043`
- selective extraction report SHA-256:
  `3943efe484d86debf33815a6489628f90b64a130499708042e354c459e17b742`
- full gzip CRC audit: `PASS`, decompressed output 저장 `0`, SQL 실행 `0`
- gzip audit report SHA-256:
  `803cf6028ffc7e8c98387a6db7e785945a354552e1cb6a7387515b9ec82a92f9`

## Static SQL and Defensive Import

gzip stream을 실행하지 않고 SQL statement start를 정적으로 감사했습니다.

- uncompressed SQL bytes: `51,797,823,337`
- lines: `383,032`
- uncompressed SHA-256:
  `6c52a49bed74e3b432661b0d9b00b98756716f77260b490c5d8f4d508ffcfe5f`
- INSERT starts: `382,912`
- dangerous statement starts: `0`
- static audit report SHA-256:
  `3012ab574373724e2f5762d9dec95d8acee57d1414559c8ad5313e6a320498ab`

서버에 sqlite3 CLI가 없어 Python 표준 SQLite로 방어적 import를
구현했습니다. extension loading을 끄고 authorizer로 attach, trigger,
virtual table, `load_extension`을 거부했습니다. 임시 DB의 `quick_check`
통과 후에만 원자적으로 게시했습니다.

| table | rows |
| --- | ---: |
| commits | 12,107 |
| cve | 11,873 |
| cwe | 272 |
| cwe_classification | 12,198 |
| file_change | 51,342 |
| fixes | 12,923 |
| method_change | 277,948 |
| repository | 4,249 |

- DB bytes: `51,688,558,592`
- DB SHA-256:
  `4cfba1ef46e363f702f4e72a7ca36e9afc70493a3adb798816f02e24ca60e84a`
- import report SHA-256:
  `633d7c063508b8daf07686959775349fd6874272ec05d7308a5f3df5827ba7c2`
- source/object execution, attach, extension load: 모두 `0`

## Supply Inventory and Diagnostic History

실패 결과를 덮어쓰지 않고 표현과 query plan 문제를 진단본으로 보존했습니다.

| revision | 결과 | 원인·결정 |
| --- | --- | --- |
| r1 | `FAIL` | `before_change`가 integer가 아니라 `True/False` 문자열 |
| r2 | `ABORTED` | self-join query plan이 비효율적 |
| r3 | `ABORTED` | disk temp sort가 약 54 GB를 기록 |
| r4 | `FAIL` | `change_type`이 `ModificationType.MODIFY` enum 문자열 |
| r5 | `PASS` | 표현 정규화와 memory temp store 적용 |

r4 진단본 SHA-256은
`18ebb1bacca3f71878b0a63523994b87f1f22119fd684bcc6ffc07454201c224`입니다.

r5 read-only 공급량 결과:

| 항목 | 결과 |
| --- | ---: |
| exact before/after method pairs | 78,963 |
| 양쪽 code 존재 | 78,963 |
| file diff 존재 | 78,963 |
| single-CWE pairs | 70,589 |
| C/C++ binary 후보 | 6,248 |
| C | 4,852 |
| C++ | 1,396 |
| distinct repositories | 631 |
| distinct fix commits | 2,855 |

- supply audit SHA-256:
  `7696a884b9c1ddd386975df9146e28c28b4f11d391c90dba0c0487602ebb4014`
- raw code/diff return: `0 / 0`
- metadata catalog approval: `true`
- bulk materialization·processing·training approval: 모두 `false`

## 200-pair Feasibility Catalog

첫 catalog r1은 구조상 PASS였지만 `NVD-CWE-Other/noinfo` 22건이 선택된
것을 결과 독해 중 발견했습니다. 이를 학습 후보로 승인하지 않고 진단본으로
보존했습니다.

- r1 diagnostic SHA-256:
  `0fab2de12f7202df517fef482fec5eb95fcab8487ef8758ad9dbe6e708767bfb`

r2는 `CWE-숫자` 형식만 허용합니다.

| 항목 | 결과 |
| --- | ---: |
| actionable candidate pool | 5,569 |
| C / C++ | `4,382 / 1,187` |
| selected | 200 |
| selected C / C++ | `150 / 50` |
| distinct commit groups | 200 |
| distinct CWE | 56 |
| CWE당 최대 | 20 |
| raw code/diff read·return | `0` |

- catalog SHA-256:
  `4993425b6fc605788a68c5f3c1635a2a2223cd62dc9a1dc71a6e032b2e420218`
- decision: `manual_evidence_gate_ready`
- selective review materialization: `true`
- bulk materialization·training: `false`

## Selective Manual-review Queue

catalog의 400개 method ID를 한 번의 batch scan으로 읽었습니다. 최초
구현은 인덱스가 없는 ID를 400번 개별 조회해 느렸으므로 실행을 중단하고
batch query로 수정했습니다. DB와 원본 artifact는 변경하지 않았습니다.

| 항목 | 결과 |
| --- | ---: |
| requested / materialized | `200 / 200` |
| 구조 오류 | `0` |
| 동일 before/after pair | `0` |
| unfinished operator decisions | `200` |
| whole-file diff read | `0` |
| selected function code read | `400` |
| PoC·source/object execution·Docker pull | 모두 `0` |

- queue path:
  `data/processed/phase-f-cvefixes-v1.0.8/manual-review-v1/review-queue.json`
- queue SHA-256:
  `8e73ac22f02127a14279d383d4ff529fa750f947355844240776486854429b2a`
- decision: `manual_review_ready`
- training approval: `false`

## Manual Gate and Next Decision

각 record에서 다음을 label 공개 전 확인합니다.

1. before/after 함수가 실제 같은 기능 단위인가
2. 수정된 operation이 commit-level target CWE와 직접 연결되는가
3. target CWE를 더 구체적인 다른 CWE로 바꿔야 하지 않는가
4. diff 밖의 문맥이 없으면 판단 불가능한가
5. repository code license가 연구·학습 사용을 허용하는가

`operator_patch_related`, `operator_cwe_supported`,
`operator_pair_quality`를 모두 확정해야 합니다. patch↔CWE 오류·불확실을
합친 값이 `10/200`을 초과하면 `FAIL EARLY`로 종료합니다. 통과해도
repository license 확인 전에는 training을 승인하지 않습니다.

## References

- [CVEfixes official repository](https://github.com/secureIT-project/CVEfixes)
- [CVEfixes v1.0.8 Zenodo record](https://zenodo.org/records/13118970)
- [MegaVul official repository](https://github.com/Icyrockton/MegaVul)

## Related Documents

- [Phase F plan](PHASE_F_DATASET_AND_BINARY_EXPERIMENT_PLAN.md)
- [Fine-tuning test workbook](FINETUNING_TEST_WORKBOOK.md)
- [Dataset candidates](DATASET_CANDIDATES.md)
- [ARVO patch gate decision](PHASE_F_ARVO_PATCH_GATE_DECISION_20260731.md)
