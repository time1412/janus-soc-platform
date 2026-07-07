# -*- coding: utf-8 -*-
"""국내 사이버 위기 경보단계 — KISA 보호나라/KrCERT 공지 파싱.

공식 실시간 API가 없어 KrCERT '경보단계' 게시판의 '최신 공지 제목'에서 현재 단계를 추출한다.
예: "사이버위기 경보 단계 '주의' → '관심' 하향 조정"  → 현재 '관심'.
- 단계는 자주 바뀌지 않으므로 결과를 캐시(기본 1시간)하고, 조회 실패 시 마지막값/설정 기본값으로 폴백.
- 아웃바운드(인터넷)가 허용된 환경에서 실시간 갱신. 폐쇄망/차단 시 폴백값을 표시(stale 표시).
"""
import html as _html
import re
import time

import requests

import config

_URL = "https://www.krcert.or.kr/kr/bbs/list.do?menuNo=205024&bbsId=B0000342"
_LEVELS = ["정상", "관심", "주의", "경계", "심각"]
_META = {
    "정상": {"eng": "NORMAL", "color": "#16a34a", "idx": 0, "desc": "위기징후 없음 — 정상"},
    "관심": {"eng": "BLUE",   "color": "#2563eb", "idx": 1, "desc": "위기징후 있으나 활동수준 낮음"},
    "주의": {"eng": "YELLOW", "color": "#ca8a04", "idx": 2, "desc": "다수 기관 침해·위협 증가"},
    "경계": {"eng": "ORANGE", "color": "#ea580c", "idx": 3, "desc": "복수 분야 광범위 피해 우려"},
    "심각": {"eng": "RED",    "color": "#dc2626", "idx": 4, "desc": "전국적 대규모 피해·마비"},
}

_cache: dict = {"level": None, "notice": "", "ts": 0.0}
_TTL = 3600  # 1시간


def _parse(html_text: str) -> tuple[str | None, str]:
    """게시판 HTML에서 '최신 경보 공지'를 찾아 현재 단계를 추출."""
    cands = re.findall(r'사이버[^<>"\']{0,90}경보[^<>"\']{0,90}', html_text)
    for c in cands:                       # DOM 순서 = 최신순
        c = re.sub(r"\s+", " ", _html.unescape(c)).strip()
        if re.search(r"(조정|발령|상향|하향|격상|해제)", c) and any(lv in c for lv in _LEVELS):
            if "→" in c:                  # 'A' → 'B' : 화살표 뒤가 현재 단계
                cur = next((lv for lv in _LEVELS if lv in c.split("→")[-1]), None)
            else:                         # "'X' 경보 발령"
                cur = next((lv for lv in _LEVELS if lv in c), None)
            if cur:
                return cur, c
    return None, ""


def _build(level: str, notice: str, cached: bool, stale: bool = False) -> dict:
    m = _META.get(level, _META["관심"])
    return {
        "level": level, "eng": m["eng"], "color": m["color"], "index": m["idx"],
        "desc": m["desc"], "notice": notice,
        "levels": [{"level": lv, **_META[lv]} for lv in _LEVELS],
        "source": "KISA 보호나라 / KrCERT", "source_url": _URL,
        "cached": cached, "stale": stale,
    }


def get_crisis_level(force: bool = False) -> dict:
    now = time.time()
    if not force and _cache["level"] and (now - _cache["ts"] < _TTL):
        return _build(_cache["level"], _cache["notice"], cached=True)
    try:
        r = requests.get(_URL, timeout=10, headers={"User-Agent": "Mozilla/5.0"}, verify=False)
        r.raise_for_status()
        level, notice = _parse(r.text)
        if level:
            _cache.update(level=level, notice=notice, ts=now)
            return _build(level, notice, cached=False)
    except Exception:  # noqa: BLE001
        pass
    # 폴백: 마지막 성공값 → 설정 기본값
    fb = _cache["level"] or getattr(config, "CRISIS_LEVEL_FALLBACK", "관심")
    return _build(fb, _cache["notice"] or "조회 실패 — 폴백값 표시", cached=True, stale=True)


if __name__ == "__main__":
    import json
    print(json.dumps(get_crisis_level(force=True), ensure_ascii=False, indent=2))
