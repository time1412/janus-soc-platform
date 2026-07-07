"""위협 인사이트 서비스 — Splunk 집계 데이터를 AI로 해석한다.

- get_trends(): 기간별 공격 트렌드 통계 + AI 해석
- get_summary(): 주간 경영진 보고용 위협 요약
"""
import json
from datetime import datetime
from typing import Any

import requests

import config
from splunk_client import splunk_client

_OR_URL = "https://openrouter.ai/api/v1/chat/completions"

_TRENDS_SYSTEM = """당신은 SOC 위협 인텔리전스 분석가입니다.
제공된 보안 이벤트 집계 통계를 분석하여 다음을 한국어로 작성하세요.

1. 이번 기간 주요 위협 트렌드 (증가·감소 패턴, 수치 인용)
2. 가장 심각한 위협 유형과 이유
3. 반복 공격 캠페인 징후 (있다면)
4. 분석가가 즉시 확인해야 할 사항

추측은 반드시 '추정'으로 명시하고 간결하게 작성하세요."""

_SUMMARY_SYSTEM = """당신은 SOC 팀장에게 보고하는 위협 분석가입니다.
제공된 보안 통계를 바탕으로 경영진 보고용 주간 위협 요약을 한국어로 작성하세요.

형식:
- 전체 현황 (1~2문장, 수치 포함)
- 주요 위협 3가지 (bullet, 전문 용어는 괄호로 설명)
- 권고 조치 (bullet)"""


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


class InsightsService:
    def get_trends(self, days: int = 7) -> dict[str, Any]:
        if config.SOC_MOCK:
            from mock_data import mock_trends
            return mock_trends(days)

        stats = self._fetch_stats(days)

        interpretation = None
        gemini_error = None
        try:
            interpretation = _call(
                _TRENDS_SYSTEM,
                f"[{days}일간 공격 집계]\n{json.dumps(stats, ensure_ascii=False, indent=2)}",
            )
        except Exception as exc:
            gemini_error = str(exc)

        return {
            "period_days": days,
            "stats": stats,
            "interpretation": interpretation,
            "gemini_error": gemini_error,
        }

    def get_summary(self) -> dict[str, Any]:
        if config.SOC_MOCK:
            from mock_data import mock_summary
            return mock_summary()

        stats = self._fetch_stats(7)
        top_attackers = self._fetch_top_attackers()
        payload = {
            "기간": "최근 7일",
            "공격_통계": stats,
            "상위_공격자_IP": top_attackers,
        }
        summary = _call(
            _SUMMARY_SYSTEM,
            json.dumps(payload, ensure_ascii=False, indent=2),
        )
        return {"summary": summary, "generated_at": datetime.now().isoformat()}

    def _fetch_stats(self, days: int) -> dict[str, Any]:
        earliest = f"-{days}d"
        base = config.ALERT_BASE_SPL

        sig_rows   = splunk_client.search(f"{base} | stats count by signature | sort -count | head 10", earliest=earliest)
        sev_rows   = splunk_client.search(f"{base} | stats count by severity", earliest=earliest)
        daily_rows = splunk_client.search(f"{base} | timechart span=1d count", earliest=earliest)
        total_rows = splunk_client.search(f"{base} | stats count", earliest=earliest)

        total = int(total_rows[0].get("count", 0)) if total_rows else 0
        return {
            "total": total,
            "by_signature": sig_rows,
            "by_severity": sev_rows,
            "daily_trend": daily_rows,
        }

    def _fetch_top_attackers(self) -> list[dict[str, Any]]:
        return splunk_client.search(
            f"{config.ALERT_BASE_SPL} | stats count by src_ip | sort -count | head 10",
            earliest="-7d",
        )


insights_service = InsightsService()
