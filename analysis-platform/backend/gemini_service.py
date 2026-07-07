"""OpenRouter API를 통한 AI 분석 서비스.

OpenRouter는 OpenAI 호환 API를 제공하므로 requests로 직접 호출한다.
모델명에 '/'가 없으면 'google/' 접두사를 자동으로 붙인다.
"""
import json
from typing import Any

import requests

import config

_OR_URL = "https://openrouter.ai/api/v1/chat/completions"

_SYSTEM_PROMPT = """역할: 당신은 SOC 관제 담당자가 공격 대응에 곧바로 참고하는
'탐지 이벤트 요약 카드'를 작성하는 분석 보조입니다.
입력은 보안 장비의 탐지 이벤트 로그(공격 시도 기록)이며 침해 확정 사고가
아닙니다. '침해사고' 표현은 로그에 침해 성공 근거가 있을 때만 씁니다.

[원칙]
1. 로그 필드만 사실로 기술. 없는 값(차단 여부·성공 여부·피해 범위)은
   추정 금지, "로그 미기록"으로 표기.
2. "만약 성공했다면", "~가능성이 높다" 등 가정·추정 서술 금지.
3. 담당자가 바로 쓸 수 있게 짧게. 일반론·원론 설명, 재발 방지 권고 금지.
4. 조치는 탐지 수준에 비례. 단건 탐지에 소스코드 긴급점검·전사 모의해킹
   같은 과한 조치를 넣지 않는다.
5. MITRE는 증거 있는 단계만, ID와 한 줄 설명으로.
6. 반복성/빈도는 입력에 집계·반복 정보가 있을 때만 기재, 없으면 생략.
7. 위협 인텔(IP 평판·CVE)은 로그에 값이 있을 때만 인용하고 새로 생성하지 않는다.

[출력 — 이 순서·제목 그대로, 전체 15줄 이내]
■ 한 줄 요약: [시각] [공격유형] [출발지IP]→[목적지IP] [대상경로]
  · 위험도 [등급] · 차단 [값|미기록]
■ 바로 할 일: 탐지 수준에 맞는 조치 1~3개
1. 탐지 사실 — 로그값만
2. 위험도 근거 — 로그 사실 기반
3. MITRE — 근거 있는 기법만 (ID + 한 줄)
4. 반복성 — 입력에 빈도/반복 정보가 있을 때만
※ 확인 필요 — 로그에 없어 판단을 보류한 항목 (있을 때만)
원본 참조 — 이벤트 ID / Splunk 소스 (로그에 있을 때)"""

_CHAT_SYSTEM_PROMPT = """당신은 SOC(보안관제센터) 로그 분석을 돕는 챗봇입니다.
제공된 '수집된 보안 로그'는 보안 장비가 탐지한 공격 시도 이벤트입니다.
이를 근거로 사용자의 질문에 한국어로 간결하고 정확하게 답하세요.

- 로그에 근거가 있으면 구체적 수치/IP/시그니처를 인용해 답합니다.
- 로그에 없는 내용은 추측하지 말고 "수집된 로그에는 해당 정보가 없습니다"라고 답합니다.
- 차단 여부·공격 성공 여부 등 로그에 없는 값을 단정하지 않습니다.
- 답변은 요점 위주로 짧게. 표가 도움이 되면 간단한 목록을 사용하세요."""


def _model_name() -> str:
    m = config.GEMINI_MODEL
    return m if "/" in m else f"google/{m}"


def _call(system: str, user: str) -> str:
    resp = requests.post(
        _OR_URL,
        headers={
            "Authorization": f"Bearer {config.GEMINI_API_KEY}",
            "Content-Type": "application/json",
        },
        json={
            "model": _model_name(),
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
        },
        timeout=120,
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]


class GeminiService:
    def analyze_incident(self, events: list[dict[str, Any]], context: str = "") -> str:
        if config.SOC_MOCK:
            from mock_data import mock_analysis
            return mock_analysis(events)
        return _call(_SYSTEM_PROMPT, self._build_prompt(events, context))

    def chat(
        self,
        question: str,
        history: list[dict[str, str]],
        events: list[dict[str, Any]],
    ) -> str:
        if config.SOC_MOCK:
            from mock_data import mock_chat_answer
            return mock_chat_answer(question, events)

        events_json = json.dumps(events[:200], ensure_ascii=False, default=str)
        convo = ""
        for h in history[-10:]:
            speaker = "사용자" if h.get("role") == "user" else "챗봇"
            convo += f"{speaker}: {h.get('content', '')}\n"

        user_msg = (
            f"[수집된 탐지 현황 ({len(events)}건, 최근 24시간)]\n"
            f"※ 항목은 '한 공격=한 인시던트'로 병합된 탐지다. '발생건수'가 있으면 그 인시던트의 실제 이벤트 수이며, "
            f"'몇 건' 질문에는 해당 공격유형 항목들의 '발생건수' 합(없으면 항목 수)으로 답하라. "
            f"컨텍스트에 없는 공격유형만 '0건'이라 답하라.\n{events_json}\n\n"
            f"[이전 대화]\n{convo or '(없음)'}\n"
            f"[질문]\n{question}"
        )
        return _call(_CHAT_SYSTEM_PROMPT, user_msg)

    def _build_prompt(self, events: list[dict[str, Any]], context: str) -> str:
        events_json = json.dumps(events, ensure_ascii=False, default=str)
        parts = []
        if context:
            parts.append(f"[추가 컨텍스트]\n{context}\n")
        parts.append(f"[분석 대상 탐지 이벤트 ({len(events)}건)]\n{events_json}")
        parts.append(
            "\n위 탐지 이벤트로 시스템 지침의 출력 형식과 원칙을 그대로 지켜\n"
            "'탐지 이벤트 요약 카드'를 작성하세요. 로그에 없는 값은 추정하지 말고\n"
            "'로그 미기록'으로 표기하세요."
        )
        return "\n".join(parts)


gemini_service = GeminiService()
