# 로컬 LLM과 분석 MCP의 책임 경계 아이디어

## 상태

`Idea / 검토 중`입니다. 채택된 architecture decision이나 구현 계획이
아닙니다. Commit 1 코드 리뷰 중 발견한 가설을 후속 검증할 수 있도록
기록합니다.

## 문제 제기

AegisLM의 목적은 로컬 보안 LLM을 구축하는 것이고, 메인 Project NuriLab은
로컬 LLM과 분석 도구를 결합해 악성코드·취약점을 분석하는 것입니다.

JADX-AI-MCP처럼 APK decompile 결과, class·method·smali·manifest·resource·
cross-reference를 LLM에 제공하는 기존 MCP가 있다면, 그 기능을 다시
fine-tuning으로 학습시키는 것이 필요한지 먼저 검증해야 합니다.

## 핵심 가설

> Base local LLM과 검증된 analyzer MCP의 조합이 동일한 절대 보안 gate를
> 통과하면, 해당 분석 표현을 LLM에 별도로 fine-tuning하지 않습니다.

Fine-tuning은 다음 조건에서만 후보가 됩니다.

1. MCP가 필요한 근거를 정확히 제공했습니다.
2. Base LLM이 그 근거를 반복적으로 잘못 해석합니다.
3. 실패 유형이 일관되고 학습 데이터로 교정 가능합니다.
4. Prompt, deterministic rule, RAG보다 fine-tuning이 적절하다는 근거가
   있습니다.

## 예상 책임 경계

| 영역 | AegisLM | Project NuriLab |
| --- | --- | --- |
| 로컬 모델 학습·adapter | 담당 | 사용 |
| source/binary 출력 contract | 담당 | normalized input 제공 |
| 절대평가·fine-tuning 필요성 판정 | 담당 | 통합 평가 참여 |
| APK·PE·ELF 파일 접수 | 비담당 | 담당 |
| JADX·Ghidra·SAST 등 analyzer 실행 | 비담당 | 담당 |
| analyzer MCP 연결·권한·sandbox | 비담당 | 담당 |
| 근거 기반 설명·보고서 생성 | 담당 | workflow 조정 |

AegisLM의 Juliet adapter는 학습용 gold를 만드는 offline 데이터 adapter로
남깁니다. 일반 코드·binary 분석 엔진으로 사용하지 않습니다.

## JADX-AI-MCP에서 확인한 범위

JADX-AI-MCP는 JADX GUI와 MCP client를 연결하고 다음과 같은 도구를
제공합니다.

- class·method source 조회와 검색
- smali, AndroidManifest, resource 조회
- class·method·field cross-reference
- main activity와 application class 탐색
- rename과 debugger 관련 기능

이는 APK 분석 context를 LLM에 전달하는 데 유용하지만, MCP 자체가
검증된 취약점 판정을 제공한다는 뜻은 아닙니다. JADX 공식 문서도 모든
코드를 100% decompile할 수 없고 오류가 발생할 수 있다고 명시합니다.

또한 JADX는 Android APK·DEX·AAB 등의 Java/smali 분석에 특화되어 있으므로
PE/ELF native malware와 일반 C/C++ executable을 대체하지 않습니다.

## 후속 절대평가 아이디어

Android 범위에서 다음 경로를 먼저 평가합니다.

```text
APK
→ JADX
→ read-only MCP tools
→ Base local LLM
→ versioned security report
→ 절대 gate
```

기록할 지표:

- 실제 존재하는 class·method·manifest 근거 비율
- hallucinated symbol·component 수
- 취약점 precision·recall·FPR·abstention
- decompiler warning을 불확실성에 반영한 비율
- tool failure와 누락 호출
- schema·evidence validation
- 위험한 mutation/debug tool 호출 수

판정:

| 결과 | 다음 행동 |
| --- | --- |
| Base+MCP가 절대 gate PASS | Android fine-tuning 생략 |
| MCP 근거가 누락·오류 | NuriLab analyzer/MCP 개선 |
| 근거는 정확하지만 LLM 판단 실패 | prompt/RAG 후 fine-tuning 검토 |
| 현재 C/C++ adapter가 분포 차이로 실패 | 필요성이 입증될 때 Android 전용 데이터 검토 |

모델 간 비교는 비용·오류 원인 분석용 보조 자료로만 사용하며, 각 경로에
동일한 절대 gate를 독립 적용합니다.

## 보안 조건

초기 연동에서는 다음 조건을 적용합니다.

- MCP는 stdio 또는 loopback에서만 실행
- remote `0.0.0.0` plain HTTP 금지
- class·method·manifest·resource 조회 도구만 allowlist
- rename과 debugger 도구는 기본 비활성화
- analyzer는 network-disabled sandbox에서 실행
- raw APK·binary를 LLM prompt에 직접 전달하지 않음
- analyzer version, input hash, warning, tool trace 기록

JADX-AI-MCP 공식 문서는 non-localhost HTTP binding이 인증과 TLS 없이
노출될 수 있다고 경고합니다.

## 이번 리뷰에 미치는 영향

Commit 1의 코드를 다음처럼 다시 구분해서 봅니다.

- Juliet label·annotation 해석: AegisLM offline adapter
- 공통 split·dedup·token gate: AegisLM dataset pipeline
- 일반 source·binary 분석: NuriLab analyzer 후보
- analyzer를 모델에 연결: NuriLab MCP 후보
- 분석 신호 해석과 보고서 contract: AegisLM 검증 대상

현재 코드 이동이나 삭제를 결정하지 않습니다. 전체 커밋 리뷰 후 별도
architecture decision으로 승격할지 판단합니다.

## 참고 자료

- [JADX-AI-MCP](https://github.com/zinja-coder/jadx-ai-mcp)
- [JADX](https://github.com/skylot/jadx)
