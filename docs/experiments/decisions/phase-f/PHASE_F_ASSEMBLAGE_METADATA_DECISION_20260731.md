# Phase F Assemblage LinuxELF Metadata Gate 결정

## 결정

Assemblage LinuxELF 고정 DuckDB metadata artifact는 schema와 데이터 계보
연구 참고 자료로 보존하지만, Phase F binary subset 설계와 raw ELF
다운로드에는 승인하지 않는다.

- artifact integrity: `PASS`
- schema inventory: `PASS`
- aggregate field quality: `FAIL`
- strict complete rows: `0 / 249,121`
- final disposition: `metadata_reference_only`
- `approved_for_binary_download=false`
- `approved_for_training=false`

이번 판정은 Assemblage 전체 연구 가치에 대한 평가가 아니다. 현재 공개
DuckDB의 두 metadata cohort가 Phase F의 동일 행 단위 provenance·license·
compiler·optimization·architecture 계약을 동시에 충족하지 못한다는
판정이다.

## 공식 artifact와 안전 경계

| 항목 | 값 |
| --- | --- |
| dataset | `changliu8541/Assemblage_LinuxELF` |
| revision | `5d58b08b500ea279a9880f80fd4b217e1897035a` |
| compressed artifact | `linux_licensed.duckdb.zst` |
| compressed bytes | `21,971,861,569` |
| upstream/local SHA-256 | `a5b12c3353cd0f653c9543e78343b45dca4207f072a7d5d17b2ab07a4540eb5e` |
| decompressed bytes | `136,143,712,256` |
| local DuckDB SHA-256 | `767b69efe0443827167f152a86ee04a04ab494cd186404503e3e64f9d25449ef` |
| DuckDB client | `1.5.5`, read-only |

공식 `binaries.tar.xz` raw ELF artifact는 받지 않았다. source code value,
binary path value, ELF payload를 export하거나 실행하지 않았다. schema
catalog와 `binaries` 테이블의 집계값만 읽었다.

## Schema 결과

공식 문서의 5개 테이블과 row 수가 실제 DB에 존재한다.

| Table | Rows |
| --- | ---: |
| `binaries` | 249,121 |
| `functions` | 613,573,055 |
| `rvas` | 685,044,264 |
| `lines` | 4,028,246,246 |
| `pdbs` | 0 |

`binaries`에는 `github_url`, `license`, `optimization`, `path`, `hash`,
`repo_commit`, `binary_format`, `toolset_version`, `build_mode`, `platform`이
있다. 별도 `compiler`와 `architecture` 컬럼은 없으며 compiler는
`toolset_version`의 `gcc/clang` 값으로만 해석했다.

## Aggregate field gate

| Field | Count | Coverage |
| --- | ---: | ---: |
| repository URL | 249,121 | 100.0000% |
| license 문자열 | 249,121 | 100.0000% |
| actionable license 상한 | 176,644 | 70.9069% |
| compiler (`gcc/clang`) | 248,815 | 99.8772% |
| optimization | 249,121 | 100.0000% |
| explicit architecture | 171,496 | 68.8404% |
| binary format | 77,611 | 31.1539% |
| repository commit | 77,615 | 31.1555% |
| build mode | 77,615 | 31.1555% |
| binary pointer/hash | 249,121 | 100.0000% |

`actionable license`는 법적 사용 승인이 아니다. 빈 값과
`other/Other/unknown`만 제외한 보수적 상한이다. 이 세 범주만
72,477건이므로 repository별 원문 license 확인 전에는 허용 목록으로
사용하지 않는다.

## 왜 strict supply가 0건인가

- build trace·commit·format을 갖지만 architecture가 불명확한 행:
  `63,031`
- architecture는 명시됐지만 build trace가 불완전한 행:
  `113,329`
- 모든 strict field를 동시에 갖는 행: `0`

새 cohort의 `platform=linux`는 OS이지 architecture가 아니다. 반대로
`platform=x86-64` 등 architecture가 명시된 older cohort는
`binary_format`, `build_mode`, `repo_commit`이 비어 있다. dataset-level
설명을 이용해 행별 결손을 추정하여 채우지 않는다.

## Evidence hashes

| Artifact | SHA-256 |
| --- | --- |
| metadata preflight | `4228ccaa1c0447e015091014facd01e42e5ed81c0be7812ab2aed9c152a8a270` |
| compressed verification | `670c4b105789a8bdd3d634311bda8d0ac3d0cfe89ad77d936068ed463dafba60` |
| schema inventory | `06af3f985316c3ae99fe06bd9be3012fe94b4f3b8d21ec9a5364872a9124a0ba` |
| aggregate field audit | `7951a4cc5a9f47f5dc4408195446fc67552bb197b1c5d335a4285b40309d770c` |

## 다음 단계

1. Assemblage raw ELF archive를 다운로드하지 않는다.
2. 공개 DuckDB는 schema·provenance 연구 참고 자료로만 보존한다.
3. upstream이 architecture와 build trace를 같은 행에 제공하는 새
   snapshot을 공개하면 새 revision으로 처음부터 재감사한다.
4. 다음 후보는 BinKit 2.0의 compiler·architecture·optimization metadata
   계약이다.
5. BinKit도 metadata gate 전에는 binary package를 받거나 실행하지 않는다.

## 근거

- [Assemblage LinuxELF dataset card](https://huggingface.co/datasets/changliu8541/Assemblage_LinuxELF)
- [Assemblage dataset access documentation](https://assemblagedocs.readthedocs.io/en/latest/dataset.html)
- [Assemblage dataset site](https://assemblage-dataset.net/)
- [Assemblage source repository](https://github.com/Assemblage-Dataset/Assemblage)
