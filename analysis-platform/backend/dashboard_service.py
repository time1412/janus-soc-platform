# -*- coding: utf-8 -*-
"""대시보드 외부 피드 — 보안 뉴스(보안뉴스 RSS) + 기관 보안 권고(KrCERT 보안공지).

인터넷 아웃바운드가 허용된 환경에서 동작. 결과를 캐시(30분)하고, 조회 실패/폐쇄망이면
마지막 성공값(없으면 빈 목록)으로 폴백한다.
"""
import html as _html
import re
import time

import requests

_H = {"User-Agent": "Mozilla/5.0"}
_NEWS_URL = "https://www.boannews.com/media/news_rss.xml"   # 보안뉴스(EUC-KR)
_ADV_URL = "https://www.krcert.or.kr/kr/bbs/list.do?menuNo=205020&bbsId=B0000133"  # KrCERT 보안공지
_ADV_BASE = "https://www.krcert.or.kr"
_TTL = 1800  # 30분
_cache: dict = {"news": ([], 0.0), "adv": ([], 0.0)}


def _clean(s: str) -> str:
    s = re.sub(r"<!\[CDATA\[|\]\]>", "", s or "")
    return re.sub(r"\s+", " ", _html.unescape(s)).strip()


def security_news(limit: int = 8) -> list[dict]:
    cached, ts = _cache["news"]
    if cached and time.time() - ts < _TTL:
        return cached
    try:
        r = requests.get(_NEWS_URL, timeout=10, headers=_H, verify=False)
        r.encoding = "euc-kr"
        out = []
        for it in re.findall(r"<item>(.*?)</item>", r.text, re.DOTALL)[:limit]:
            t = re.search(r"<title>(.*?)</title>", it, re.DOTALL)
            l = re.search(r"<link>(.*?)</link>", it, re.DOTALL)
            d = re.search(r"<pubDate>(.*?)</pubDate>", it, re.DOTALL)
            if t and _clean(t.group(1)):
                out.append({"title": _clean(t.group(1)),
                            "link": _clean(l.group(1)) if l else "",
                            "date": _clean(d.group(1))[:22] if d else ""})
        if out:
            _cache["news"] = (out, time.time())
            return out
    except Exception:  # noqa: BLE001
        pass
    return _cache["news"][0]


def advisories(limit: int = 8) -> list[dict]:
    cached, ts = _cache["adv"]
    if cached and time.time() - ts < _TTL:
        return cached
    try:
        r = requests.get(_ADV_URL, timeout=10, headers=_H, verify=False)
        out, seen = [], set()
        for m in re.finditer(r'nttId=(\d+)[^>]*>([^<]{6,90})</a>', r.text):
            ntt, title = m.group(1), _clean(m.group(2))
            if not title or ntt in seen or "목록" in title:
                continue
            seen.add(ntt)
            out.append({
                "title": title,
                "link": f"{_ADV_BASE}/kr/bbs/view.do?menuNo=205020&bbsId=B0000133&nttId={ntt}",
            })
            if len(out) >= limit:
                break
        if out:
            _cache["adv"] = (out, time.time())
            return out
    except Exception:  # noqa: BLE001
        pass
    return _cache["adv"][0]
