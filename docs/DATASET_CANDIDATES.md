# Dataset Candidates

이 문서는 `AegisLM` Phase D/E 이후에 검토할 공개 데이터셋 후보를 기록합니다.

`docs/DATA_STRATEGY.md`가 데이터 사용 원칙과 안전 정책의 정본이라면, 이 문서는 외부 데이터셋 후보의 조사 상태와 AegisLM 적용 가능성을 추적하는 registry입니다.

이 문서는 실제 데이터 다운로드 목록이 아닙니다. 후보의 출처, 라이선스/이용 조건, 데이터 타입, raw malware 포함 가능성, AegisLM 사용 목적을 먼저 검토하기 위한 문서입니다.

## 1. Scope

이 문서에서 다루는 항목:

- 공개 CTI, 악성코드 분석 텍스트, malware family label, PE metadata, feature vector, benchmark dataset 후보
- fine-tuning, evaluation, benchmark, RAG/vector 용도 분류
- raw malware 포함 가능성 및 Git 저장 가능 여부 판단
- Phase D/E에서 우선 검토할 1차 후보

이 문서에서 다루지 않는 항목:

- 실제 데이터 다운로드
- raw malware sample 수집
- dataset 변환 스크립트 구현
- fine-tuning 실행 결과
- benchmark 점수 주장

## 2. Safety Rules

다음 항목은 이 저장소에 커밋하지 않습니다.

- 실제 악성 샘플
- executable malware payload
- packed binary, script payload, exploit payload
- raw downloaded dataset dump
- model checkpoint
- adapter artifact
- secrets, API keys, tokens, passwords
- private CTI
- private customer data

데이터셋 후보를 검토할 때는 다음 순서를 따릅니다.

1. source URL과 maintainer를 확인한다.
2. license 또는 terms of use를 확인한다.
3. raw malware binary 포함 여부를 확인한다.
4. Git 저장 가능 범위와 외부 artifact 저장 필요 여부를 분리한다.
5. AegisLM record shape로 변환 가능한 필드를 식별한다.
6. fine-tuning, evaluation, benchmark, RAG/vector 경로 중 어디에 사용할지 정한다.
7. 안전하지 않거나 범위가 큰 항목은 `hold` 또는 `avoid`로 둔다.

## 3. Usage Tags

| Tag | Meaning |
| --- | --- |
| `sft-candidate` | supervised fine-tuning 예시로 변환할 수 있는 후보 |
| `evaluation-candidate` | held-out fixture 또는 평가 기준으로 사용할 수 있는 후보 |
| `benchmark-candidate` | baseline/adaptor 비교를 위한 외부 benchmark 후보 |
| `metadata-evaluation` | raw sample 없이 hash, label, static feature, report metadata 중심으로 평가 가능한 후보 |
| `rag-candidate` | retrieval/vector index의 근거 문서 후보 |
| `hold` | 추가 법적/운영적 검토 전까지 보류 |
| `avoid` | v0 범위에서 사용하지 않는 것이 적절한 후보 |

## 4. First-Pass Candidates

| Candidate | Source type | Data type | Current use tags | Git policy | Notes |
| --- | --- | --- | --- | --- | --- |
| APTNotes | GitHub, public report index | APT/CTI report metadata, report links, CSV/JSON summaries | `sft-candidate`, `rag-candidate`, `evaluation-candidate` | Link and small metadata fixture only | Public APT/campaign reports are useful for summarization, evidence extraction, and ATT&CK mapping tasks. Full report redistribution and license terms must be checked per source. |
| MalwareTextDB | academic dataset | annotated malware-related text | `sft-candidate`, `evaluation-candidate` | Small curated fixture only after license review | Useful for entity/relation extraction and malware analysis language understanding. Need to verify dataset access, license, and annotation format before use. |
| MOTIF | academic dataset | malware family labels, aliases, report mapping | `sft-candidate`, `evaluation-candidate`, `rag-candidate` | Metadata and mapping fixture only after license review | Strong candidate for family-name normalization, alias handling, and report-grounded evaluation. Avoid treating family labels as final truth without provenance. |
| EMBER / EMBER2024 | GitHub, paper, benchmark dataset | PE static features, metadata, labels, feature vectors | `benchmark-candidate`, `metadata-evaluation`, `hold` | Do not commit dataset dump; external artifact only | Good benchmark direction for malware detection metadata and feature-vector evaluation. Not a first SFT source for AegisLM text generation. |
| SOREL-20M | GitHub, public S3, paper | large PE metadata/features, labels, disarmed binaries | `benchmark-candidate`, `metadata-evaluation`, `hold` | Do not commit dataset dump or binaries; external artifact only | Very large dataset. Only specific metadata or small derived safe fixtures should be considered. Raw/disarmed binaries remain out of Git and out of v0 scope. |
| Binary-30K | Hugging Face dataset | binary metadata, labels, tokenized binary representation, splits | `benchmark-candidate`, `metadata-evaluation`, `hold` | Do not commit dataset dump; inspect files before use | Potentially convenient benchmark because it exposes metadata and splits. Must audit dataset card, files, and loading path before use. |

## 5. Candidate Details

### APTNotes

- URL: `https://github.com/aptnotes/data`
- Primary fit: CTI summarization, APT/campaign context, evidence extraction, ATT&CK mapping examples
- Initial AegisLM role: SFT/RAG/evaluation candidate
- Raw malware risk: low, but linked reports may contain technical malware details
- Safety decision: use report metadata and selected excerpts only after source/license review

APTNotes should be treated as a report index, not as a ready-to-train dataset. The useful unit is likely one report section or one curated summary record with source provenance.

### MalwareTextDB

- URL: `https://aclanthology.org/P17-1148/`
- Primary fit: annotated malware-analysis language
- Initial AegisLM role: SFT/evaluation candidate
- Raw malware risk: low if dataset contains text only
- Safety decision: verify license and annotation files before any conversion

MalwareTextDB is attractive because it is closer to natural language malware analysis than PE feature datasets. It should be checked for field shape, annotation labels, and redistribution terms.

### MOTIF

- URL: `https://arxiv.org/abs/2111.15031`
- Primary fit: malware family labels, aliases, report-grounded references
- Initial AegisLM role: SFT/RAG/evaluation candidate
- Raw malware risk: medium if sample references are included; use metadata/report mappings only
- Safety decision: avoid binary sample handling; focus on alias and report mapping metadata

MOTIF is useful for evaluating whether AegisLM can avoid hallucinated family names and preserve uncertainty when evidence is incomplete.

### EMBER / EMBER2024

- EMBER URL: `https://github.com/elastic/ember`
- EMBER2024 paper: `https://arxiv.org/abs/2506.05074`
- Primary fit: malware detection benchmark, PE static feature evaluation
- Initial AegisLM role: benchmark/metadata evaluation candidate
- Raw malware risk: medium; dataset focuses on features and metadata, but related tooling can process PE files
- Safety decision: no raw PE files or dataset dumps in Git

EMBER-style data is better for benchmark and metadata evaluation than direct instruction tuning. AegisLM can use derived metadata summaries or evaluation labels, but should not claim malware-detection benchmark performance without a reproducible experiment log.

### SOREL-20M

- URL: `https://github.com/sophos/SOREL-20M`
- Primary fit: large-scale PE detection benchmark
- Initial AegisLM role: benchmark/metadata evaluation candidate
- Raw malware risk: high because the dataset includes very large binary-related artifacts
- Safety decision: hold until storage, terms, and artifact handling are explicitly planned

SOREL-20M is too large for immediate Phase D/E use. If used later, the first step should be a metadata-only review and a tiny derived fixture outside the raw dataset.

### Binary-30K

- URL: `https://huggingface.co/datasets/mjbommar/binary-30k`
- Primary fit: compact benchmark-style binary metadata and tokenized representation
- Initial AegisLM role: benchmark/metadata evaluation candidate
- Raw malware risk: medium; Hugging Face repositories must be audited before loading
- Safety decision: inspect dataset files and avoid executing remote loading code

Binary-30K may be useful as a compact benchmark candidate, but it should go through supply-chain review before use. Prefer metadata and labels first, not tokenized binary content for SFT.

## 6. Phase D/E Recommendation

For Phase D/E, prioritize candidates in this order:

1. APTNotes for CTI report metadata and RAG/evidence workflows.
2. MalwareTextDB for malware-analysis language and annotation-driven evaluation.
3. MOTIF for family alias/report mapping and hallucination checks.
4. EMBER or Binary-30K for metadata-based benchmark exploration.
5. SOREL-20M only after storage, legal, and safety handling are explicitly planned.

Phase E tiny SFT should start with text/metadata records, not raw binary datasets. Benchmark datasets should be used to define evaluation context or metadata-grounded prompts unless a separate ML benchmark experiment is opened.

## 7. Open Questions

- Which license terms allow derived training examples?
- Which candidates can produce metadata-only fixtures that are safe to commit?
- Which candidates should be kept entirely outside Git as external artifacts?
- How should dataset provenance be represented in `aegislm/schemas.py` records?
- Which candidates belong to held-out evaluation only and must never enter training data?

## 8. Related Work

- Linear: THE-62
- `docs/DATA_STRATEGY.md`
- `docs/EVALUATION_PLAN.md`
- `docs/FINETUNING_EXPERIMENT_PLAN.md`

## 9. Phase F Binary-derived Candidates

Phase F에서는 raw executable을 LLM에 직접 넣지 않습니다. 후보 데이터의
역할은 source–binary 정렬, compiler 강건성, pseudo-C·정적 특징 생성,
metadata benchmark로 나눕니다.

| Candidate | Phase F role | Decision |
| --- | --- | --- |
| BigVul buildable patch pair | target CWE before/after binary pair | `primary-if-verified` |
| [ARVO v3](https://github.com/n132/ARVO-Meta/releases/tag/v3.0.0) | 재현 가능한 C/C++ vulnerable/fixed patch와 buffer extractor 복구 | `manual-gate-failed`; 200건 중 오류 11건으로 `FAIL EARLY`, crash family→CWE 변환·학습 금지 |
| [Assemblage](https://assemblage-dataset.net/) | source-built PE/ELF와 compiler variant | `metadata-reference-only`; artifact·schema PASS, strict complete row 0으로 raw ELF·학습 불승인 |
| [Decompile-Bench](https://arxiv.org/abs/2505.12668) | source–assembly representation과 정렬 회귀 | `alignment-reference-only`; 첫 shard 수동 `96/100 PASS`, repository 명시 84.66%, 행별 license·compiler·optimization 부재로 학습 불승인 |
| [BinKit 2.0](https://github.com/SoftSec-KAIST/BinKit) | architecture/compiler/optimization robustness | `metadata-hold`; matrix 문서 PASS, Drive artifact size·checksum·dataset license·row schema 부재, pickle 역직렬화 금지 |
| [LLM4Decompile](https://github.com/albertan017/LLM4Decompile) | decompilation format와 representation 연구 | `reference` |
| [EMBER2024](https://github.com/FutureComputing4AI/EMBER2024) | malware static-feature absolute benchmark | `classifier_absolute_gate_fail`; train 26,000·test 6,000 materialization PASS, 자체·공식 모델 temporal FPR FAIL, SFT·NuriLab 연결 false |
| SOREL-20M full | 대규모 PE feature/disarmed binary | `hold` |
| BODMAS raw, BIG 2015 | raw malware/old byte·assembly corpus | `hold` |

Assemblage/Decompile-Bench/BinKit은 취약점 label을 자동으로 제공한다고
간주하지 않습니다. source–binary 정렬 또는 강건성 자료로 사용하고,
취약점 SFT label은 검증된 patch/CWE 근거와 별도로 연결해야 합니다.

Decompile-Bench 첫 Arrow shard 131,359건은 고정 100건 source–assembly
수동 gate에서 96건을 통과했습니다. 그러나 `file` 경로로 repository를
명시적으로 복원할 수 있는 행은 111,206건(84.66%)이고, 1,066개
repository의 행별 license와 compiler/optimization metadata는 제공되지
않습니다. 따라서 representation 참고 자료로만 보존하며, 세부 판정은
[Decompile-Bench alignment 결정문](PHASE_F_DECOMPILE_BENCH_ALIGNMENT_DECISION_20260731.md)을
따릅니다.

Assemblage LinuxELF metadata 249,121행은 repository·optimization·binary
pointer가 완전하고 compiler도 99.88% 복원됩니다. 그러나 검증 가능한
license 상한은 70.91%, architecture 68.84%, binary format·repo
commit·build mode는 약 31.15%입니다. build trace cohort와 architecture
cohort의 strict 교집합이 0건이므로 raw ELF를 받지 않고
`metadata_reference_only`로 종료합니다. 세부 판정은
[Assemblage metadata 결정문](PHASE_F_ASSEMBLAGE_METADATA_DECISION_20260731.md)을
따릅니다.

BinKit 2.0은 371,928 binaries와 8 architectures·23 compilers·6
optimization levels를 문서화합니다. 그러나 v2.0.0 release에 dataset
asset이 없고 실제 binary·pickle은 Google Drive에서만 배포되어
revision·size·checksum·dataset license·row schema를 고정할 수 없습니다.
따라서 다운로드하지 않으며 세부 판정은
[BinKit metadata 결정문](PHASE_F_BINKIT_METADATA_DECISION_20260731.md)을
따릅니다.

EMBER2024 ELF test 고정 artifact는 12개 weekly JSONL과 12,000행을
포함하지만 동일 `(week_id, sha256)` 6,000행이 중복입니다. primary
malware label과 static feature 충돌은 0건이므로 6,000개 시간 관측치로
중복 제거한 독립 절대평가는 승인합니다. CAPS/MBC/TTP 차이는 별도 merge
계약 전까지 사용하지 않고 source/binary SFT에는 혼합하지 않습니다.
세부 판정은
[EMBER2024 benchmark 결정문](PHASE_F_EMBER2024_BENCHMARK_DECISION_20260731.md)을
따릅니다.

ARVO의 sanitizer `crash_type`도 CWE gold label로 자동 등치하지 않습니다.
heap/stack buffer read·write는 CWE-121/122/126의 후보 범주일 뿐이며,
developer patch와 취약 함수 관계를 사람이 확인해야 합니다. ARVO v3
metadata DB의 SHA-256은
`331184ca807c2f136f98dac9f1df94c893f4ee2fdf9329dca517ff88e72f97ce`입니다.
PoC, crash output, reproducer command는 읽지 않았고 Docker image pull과
object 실행도 수행하지 않았습니다.

공개 개발자 패치 200건을 별도 수집해 검토했지만 확정 오류
`11/200`으로 5% gate를 초과했습니다. Git binary patch 13건과 C/C++
source hunk가 없는 패치 5건은 queue에서 자동 제외했습니다. ARVO는
현 상태에서 binary SFT label 공급원이 아니며, 상세 결과는
[ARVO patch gate 결정문](PHASE_F_ARVO_PATCH_GATE_DECISION_20260731.md)을
따릅니다.

SOREL-20M full 약 8 TB download는 현재 shared storage를 거의 소진하므로
시작하지 않습니다. EMBER2024도 초기 SFT에 섞지 않고 독립된
metadata benchmark로 유지합니다.

## 10. Phase F Source·Patch 보강 후보

Language coverage 자체는 quota로 사용하지 않습니다. 다음 후보는
언어 종류를 늘리기 위해서가 아니라 weakness·patch·code evidence가
명확한 레코드를 확보하기 위해 검토합니다.

| Candidate | Phase F role | Decision |
| --- | --- | --- |
| [PrimeVul](https://github.com/DLVulDet/PrimeVul) | 정제된 vulnerable/benign source와 paired evaluation | `acquired-and-materialized`; v0.1 paired 중 global dedup을 통과한 pair로 cross-dataset test 200건 구성 |
| [NIST SARD](https://samate.nist.gov/SARD/test-suites/112) / Juliet C/C++ 1.3 | 명시적 weakness, buildable source, 자체 source–binary pair 생성 | `ready-for-source-v3-integration`; 인과 filter 통과 11,540 pair·unique 8,191 pair 중 5,750쌍으로 10,000/1,000/500 구성, 자동 gate와 고정 100건 수동 gate PASS |
| [MegaVul](https://github.com/Icyrockton/MegaVul) | CVE/fix commit와 함수 전후·diff 근거 보강 | `metadata-hold`; dataset immutable release·license·고정 URL·size·checksum 확보 전 다운로드 금지 |
| [CVEfixes v1.0.8](https://zenodo.org/records/13118970) | CVE/CWE와 fixing commit, before/after function 공급량 감사 | `manual-gate-failed`; archive·SQL·SQLite·6,248쌍 공급 PASS 뒤 28건 중 오류·불확실 11건으로 `FAIL EARLY`, commit-level CWE direct-label 학습 금지 |

외부 다운로드 전에 현재 BigVul raw의 `func_after`, `lines_before`,
`lines_after`, `patch`를 target builder가 사용하지 못한 문제부터
수정합니다. 이미 가진 근거를 복구하는 것이 새 데이터를 추가하는 것보다
우선입니다.

### 권장 확보 순서

1. [완료] F2 source contract·code-grounded target·token gate 구현
2. [완료] NIST SARD/Juliet 고정 100건 수동 label·근거 감사
3. SARD 통과 자료를 `phase-f-source-v3`으로 통합·동결
4. [실패 종료] ARVO 200건 buffer patch↔CWE 수동 feasibility
5. [실패/보류] MegaVul·CVEfixes patch-localized CWE 공급 gate
   - MegaVul: metadata hold
   - CVEfixes: archive·import·공급량·200쌍 자동 materialization PASS 뒤
     수동 `11/28 FAIL EARLY`; 남은 172건 미검토, direct-label 사용 금지
6. [완료] Decompile-Bench 첫 shard alignment·provenance gate
   - alignment `96/100 PASS`
   - provenance 84.66%, repository license·compiler·optimization 미완료
   - `alignment_reference_only`, training false
7. [완료/실패] Assemblage metadata gate
   - artifact·zstd·schema PASS
   - strict complete row 0, raw ELF·training false
8. [완료/보류] BinKit compiler-robustness metadata gate
   - compile matrix 문서 PASS
   - 고정 dataset artifact·license·schema 부재로 download false
9. [완료/분류기 실패] EMBER2024 static-feature 독립 malware benchmark
   - archive·schema·feature shape PASS
   - raw 12,000행 → `(week_id, sha256)` 6,000관측치 필수 중복 제거
   - 자체 모델 FPR `0.0197`, 주별 최대 FPR `0.056`로 FAIL
   - 공식 모델 FPR `0.1097`, 주별 최대 FPR `0.208`로 FAIL
   - SFT·raw executable·NuriLab signal 연결 false

전체 raw binary corpus나 malware payload는 이 순서에 포함하지 않습니다.
세부 근거는
[patch label supply 결정문](PHASE_F_PATCH_LABEL_SUPPLY_DECISION_20260731.md)을
따릅니다.
