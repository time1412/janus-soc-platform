"""AI 정/오탐(true/false positive) 판별 서비스 — 소통플랫폼의 핵심.

분석플랫폼에서 넘어온 보안 경보를 AI로 분석해
- 정탐(true_positive): 실제 공격
- 오탐(false_positive): 시그니처만 매칭된 정상 트래픽
으로 분류한다. 정탐만 소통플랫폼으로 전달하는 게 최종 목표.

단건 판별(classify)과 배치 판별(classify_batch)을 모두 제공한다.
배치는 여러 경보를 한 번의 API 호출로 처리해 시스템 프롬프트 비용을 분산한다.

OpenRouter(OpenAI 호환) API를 requests로 직접 호출한다.
"""
import json
import re
from typing import Any
from urllib.parse import unquote_plus

import requests

import config

# 판별 기준(공통) — 단건/배치 시스템 프롬프트가 공유한다.
_CRITERIA = """[판별 기준]
- 정탐(true_positive): 페이로드/URI에 실제 공격 의도가 명확히 드러남.
  · SQL Injection: ' OR 1=1, UNION SELECT, CTXSYS.DRITHSX, 주석(-- #) 등 SQL 구문
  · XSS: <script>, onerror=, <img src=x>, document.cookie 탈취 등
  · Path Traversal: ../../../etc/passwd, ..%2f 등 상위 경로 탐색
  · Command Injection: ;ls, |cat, $(...), &&whoami 등 OS 명령 결합
  · Brute Force: 동일 출발지에서 인증 엔드포인트(/login 등)로 짧은 간격 반복 시도
- 오탐(false_positive): 시그니처는 매칭됐으나 정상 트래픽일 가능성이 높음.
  · 정상 검색어/파라미터 (예: keyword=bts, keyword=콘서트)
  · 세션 식별자 (예: ;jsessionid=ABC123 — 'id'가 명령어가 아님)
  · 정상적인 파일 경로/확장자, 정상 로그인 1~2회
  · 내부 점검/인증된 스캐너로 보이는 트래픽

[판별 원칙]
1. 반드시 페이로드(URI/본문)의 '실제 내용'을 근거로 판단한다. 시그니처 이름만 믿지 않는다.
2. URL 인코딩은 디코딩된 값으로 해석한다 (%27 → ' , %3C → < ).
3. 애매하면 confidence를 낮추고, 보안상 안전한 쪽(정탐 의심)으로 기운다."""

_SYSTEM_PROMPT = f"""당신은 SOC(보안관제센터)의 시니어 침해대응 분석가입니다.
IDS/WAF가 탐지한 보안 경보가 '실제 공격(정탐)'인지 '오탐(false positive)'인지 판별합니다.

{_CRITERIA}

반드시 아래 JSON 형식 '하나만' 출력한다. 다른 설명/마크다운 금지.
{{
  "verdict": "정탐" 또는 "오탐",
  "confidence": 0~100 정수,
  "attack_type": "확정 공격 유형 (오탐이면 '해당없음')",
  "reasoning": "판단 근거 1~2문장 (한국어)",
  "indicators": ["근거가 된 페이로드 조각들"],
  "recommended_action": "권고 조치 (한 문장)"
}}"""

_BATCH_SYSTEM_PROMPT = f"""당신은 SOC(보안관제센터)의 시니어 침해대응 분석가입니다.
IDS/WAF가 탐지한 보안 경보 '여러 건'을 각각 정탐/오탐으로 판별합니다.

{_CRITERIA}

입력된 모든 경보를 판별해 'JSON 배열 하나만' 출력한다. 다른 설명/마크다운 금지.
각 원소는 입력 경보 번호(id)와 1:1 대응해야 한다.
[
  {{"id": 1, "verdict": "정탐|오탐", "confidence": 0~100, "attack_type": "...",
    "reasoning": "...", "indicators": ["..."], "recommended_action": "..."}},
  ...
]"""


def _decode(s: str) -> str:
    """URL 인코딩 페이로드를 사람이 읽을 수 있게 디코딩 (분석 정확도 향상)."""
    if not s:
        return ""
    try:
        return unquote_plus(s)
    except Exception:
        return s


def _alert_block(alert: dict[str, Any]) -> list[str]:
    """경보 한 건을 프롬프트용 텍스트 줄로 변환."""
    uri_raw = alert.get("uri", "") or ""
    uri_dec = _decode(uri_raw)
    body_dec = _decode(alert.get("status", "") or alert.get("body", "") or "")
    lines = [
        f"- 탐지 시그니처: {alert.get('signature', '(없음)')}",
        f"- 출발지 IP: {alert.get('src_ip', '?')}  목적지 IP: {alert.get('dest_ip', '?')}",
        f"- 탐지원: {alert.get('source', '?')}  위험도(원본): {alert.get('severity', '?')}",
        f"- URI(디코딩): {uri_dec or '(없음)'}",
    ]
    if body_dec:
        lines.append(f"- 본문/파라미터(디코딩): {body_dec}")
    return lines


def _build_user_prompt(alert: dict[str, Any]) -> str:
    lines = ["[판별 대상 보안 경보]"] + _alert_block(alert)
    lines.append("\n위 경보가 정탐인지 오탐인지 JSON으로만 판별하세요.")
    return "\n".join(lines)


def _build_batch_prompt(alerts: list[dict[str, Any]]) -> str:
    lines = [f"[판별 대상 보안 경보 {len(alerts)}건]"]
    for i, a in enumerate(alerts, 1):
        lines.append(f"\n■ 경보 #{i}")
        lines.extend(_alert_block(a))
    lines.append(f"\n위 {len(alerts)}건을 각각 판별해 id를 포함한 JSON 배열로만 출력하세요.")
    return "\n".join(lines)


def _extract_json(text: str) -> Any:
    """모델 응답에서 JSON(객체/배열)을 안전하게 추출 (마크다운 펜스 제거 포함)."""
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.IGNORECASE).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"(\[.*\]|\{.*\})", text, flags=re.DOTALL)
        if m:
            return json.loads(m.group(0))
        raise


def _call_ai(system: str, user: str) -> tuple[str, dict[str, Any]]:
    """AI 호출 → (본문, usage) 반환. usage엔 prompt/completion/total tokens 포함."""
    resp = requests.post(
        config.AI_URL,
        headers={
            "Authorization": f"Bearer {config.AI_API_KEY}",
            "Content-Type": "application/json",
        },
        json={
            "model": config.AI_MODEL if "/" in config.AI_MODEL else f"google/{config.AI_MODEL}",
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0,            # 판별 일관성 확보
            "usage": {"include": True},  # OpenRouter usage 포함
        },
        timeout=180,
    )
    resp.raise_for_status()
    data = resp.json()
    content = data["choices"][0]["message"]["content"]
    return content, data.get("usage", {})


def _normalize_verdict(result: dict[str, Any]) -> dict[str, Any]:
    result.setdefault("verdict", "정탐")
    result.setdefault("confidence", 0)
    result["is_true_positive"] = str(result.get("verdict", "")).startswith("정탐")
    return result


class TriageService:
    def classify(self, alert: dict[str, Any]) -> dict[str, Any]:
        """단일 경보 판별."""
        raw, _ = _call_ai(_SYSTEM_PROMPT, _build_user_prompt(alert))
        try:
            return _normalize_verdict(_extract_json(raw))
        except Exception:
            return {
                "verdict": "정탐", "confidence": 0, "attack_type": "판별불가",
                "reasoning": f"AI 응답 파싱 실패: {raw[:200]}",
                "indicators": [], "recommended_action": "수동 검토 필요",
                "is_true_positive": True, "_parse_error": True,
            }

    def classify_batch(
        self, alerts: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """여러 경보를 '한 번의 API 호출'로 판별 → (판정 리스트, usage)."""
        if not alerts:
            return [], {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

        raw, usage = _call_ai(_BATCH_SYSTEM_PROMPT, _build_batch_prompt(alerts))
        try:
            arr = _extract_json(raw)
            if isinstance(arr, dict):  # 모델이 단일 객체로 답한 예외 처리
                arr = [arr]
        except Exception:
            arr = []

        # id 기준으로 정렬 매핑 (id 없으면 순서대로)
        by_id: dict[int, dict] = {}
        for i, item in enumerate(arr, 1):
            if isinstance(item, dict):
                by_id[int(item.get("id", i))] = item

        results = []
        for i in range(1, len(alerts) + 1):
            item = by_id.get(i)
            if item is None:
                results.append({
                    "verdict": "정탐", "confidence": 0, "attack_type": "판별불가",
                    "reasoning": "배치 응답에서 해당 경보 누락", "indicators": [],
                    "recommended_action": "수동 검토 필요",
                    "is_true_positive": True, "_parse_error": True,
                })
            else:
                results.append(_normalize_verdict(item))
        return results, usage


triage_service = TriageService()
