# 구조·책임 경계 발견 사항

## 현재 혼합된 책임

`sard_juliet.py`에는 다음 책임이 함께 있습니다.

- Juliet ZIP member 선택
- C/C++ 함수 정규식 추출
- bad/good pair 구성
- label identifier와 annotation 정리
- CWE별 evidence 휴리스틱
- 공통 exact-span·dedup·token gate
- group split과 materialization
- 수동 검토 요약

이 구조는 동작 흐름을 한 파일에서 볼 수 있다는 장점이 있지만, Juliet 전용
규칙과 재사용 가능한 dataset contract의 경계를 흐립니다.

## AegisLM 안에서 분리할 책임

```text
aegislm/datasets/
├── source.py                 # canonical record, schema, prompt contract
├── source_audit.py           # leakage, duplicate, split, token quality gate
├── juliet/
│   ├── archive.py            # ZIP member와 variant 선택
│   ├── functions.py          # Juliet bad/good 함수와 pair
│   ├── annotations.py        # FLAW/FIX supervision 해석
│   ├── cwe_evidence.py       # 지원 CWE별 target builder와 validator
│   └── materialize.py        # Juliet profile 구성
└── evidence.py               # 위치 기반 span과 공통 evidence contract
```

실제 분리 위치는 `source.py`와 `source_audit.py` 리뷰 후 확정합니다. 이미 있는
공통 기능을 중복 구현하지 않는 것이 우선입니다.

## NuriLab으로 보낼 책임

다음은 학습자료 변환보다 실제 분석 runtime의 책임입니다.

- 언어별 parser와 AST
- control/data-flow와 alias 분석
- source location 정규화
- decompiler/JADX/Ghidra 연결
- imports, strings, xref 등 deterministic signal
- MCP tool의 read-only 호출과 결과 normalization

AegisLM은 NuriLab이 만든 normalized evidence record를 학습·평가 계약으로
받을 수 있지만, 실제 파일 분석 engine을 이 저장소에 중복 구현하지 않습니다.

## MCP 아이디어와의 관계

JADX AI MCP 같은 도구는 APK/Dex에서 pseudo-Java, manifest, resource,
xref를 가져오는 역할을 대신할 수 있습니다. 그러나 Juliet의 FLAW/FIX 주석을
해석하거나 target CWE gold를 만들어 주지는 않습니다.

따라서 현재 가설은 다음과 같습니다.

```text
NuriLab analyzer/MCP
→ deterministic normalized evidence
→ local base 또는 fine-tuned LLM
→ versioned assessment
→ 절대 gate
```

Base model+MCP가 독립 절대 gate를 통과하면 해당 능력의 fine-tuning은 생략할
수 있습니다. 아직 결정이 아니라 검증할 아이디어이며, 자세한 내용은
[로컬 LLM과 analyzer MCP 책임 경계 아이디어](../../../../docs/design/architecture/LOCAL_LLM_MCP_BOUNDARY_IDEA.md)에
기록돼 있습니다.

## 리팩터링 결정 전 확인할 것

1. `source.py`가 이미 제공하는 공통 contract 범위
2. `source_audit.py`가 이미 제공하는 leakage·duplicate gate 범위
3. Q1R10/Q1R11이 실제로 사용하는 `sard_juliet.py` 공개 인터페이스
4. generated artifact와 config에서 import하는 함수 목록
5. 기존 hash 재현성을 유지할 필요가 있는 frozen dataset 범위

기존 frozen 실험의 재현 경로는 보존하고, 새 dataset version부터 구조를
정리하는 방식이 안전합니다.
