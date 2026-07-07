# -*- coding: utf-8 -*-
"""최근 XSS 3건 정밀 분석 — modsec 원본 _raw 로그를 섹션별로 파싱."""
import re
from urllib.parse import unquote_plus

import requests

B = "http://localhost:8800"

# 최근 XSS(attack-xss 태그) modsec 원본 로그 5건
spl = ('search index=waf_audit sourcetype="modsec:audit:serial" "attack-xss" '
       '| sort -_time | head 5 | table _time _raw')
res = requests.post(f"{B}/api/search", json={"spl": spl, "earliest": "-24h"}, timeout=90).json()
rows = res.get("results", [])
print(f"수집된 XSS 원본 로그: {len(rows)}건\n")


def sections(raw: str) -> dict:
    """modsec serial 포맷을 섹션(A/B/C/F/H 등)으로 분해."""
    out = {}
    parts = re.split(r"-{2,}\w+-{2,}([A-Z])-{2,}", raw)
    # parts = ['', 'A', '<A내용>', 'B', '<B내용>', ...]
    for i in range(1, len(parts) - 1, 2):
        out[parts[i]] = parts[i + 1].strip()
    return out


def parse_H(h: str) -> list:
    """H 섹션에서 매칭된 룰들을 추출."""
    rules = []
    for line in h.splitlines():
        if "ModSecurity:" not in line:
            continue
        rid = re.search(r'\[id "(\d+)"\]', line)
        msg = re.search(r'\[msg "([^"]+)"\]', line)
        data = re.search(r'\[data "([^"]*)"\]', line)
        sev = re.search(r'\[severity "([^"]+)"\]', line)
        matched_var = re.search(r'(?:found within|Matched Data:.*?within) ([A-Z_]+(?::[^\s:]+)?)', line)
        rules.append({
            "id": rid.group(1) if rid else "?",
            "msg": msg.group(1) if msg else "",
            "data": data.group(1) if data else "",
            "sev": sev.group(1) if sev else "",
            "var": matched_var.group(1) if matched_var else "",
        })
    return rules


for n, row in enumerate(rows[:3], 1):
    raw = row.get("_raw", "")
    sec = sections(raw)
    a, b, c, f, h = sec.get("A", ""), sec.get("B", ""), sec.get("C", ""), sec.get("F", ""), sec.get("H", "")

    # A: 타임스탬프/IP
    am = re.search(r"\[([^\]]+)\]\s+\S+\s+([\d.]+)\s+\d+\s+([\d.]+)\s+\d+", a)
    ts = am.group(1) if am else "?"
    src = am.group(2) if am else "?"
    dst = am.group(3) if am else "?"

    # B: 요청 라인 + 주요 헤더
    req_line = b.splitlines()[0] if b else "?"
    method_uri = re.match(r"(\S+)\s+(\S+)", req_line)
    method = method_uri.group(1) if method_uri else "?"
    uri = method_uri.group(2) if method_uri else "?"
    ua = next((l.split(":", 1)[1].strip() for l in b.splitlines() if l.lower().startswith("user-agent:")), "")
    ref = next((l.split(":", 1)[1].strip() for l in b.splitlines() if l.lower().startswith("referer:")), "")
    host = next((l.split(":", 1)[1].strip() for l in b.splitlines() if l.lower().startswith("host:")), "")

    # F: 응답 코드
    status = re.match(r"HTTP/[\d.]+\s+(\d+)", f)
    resp_code = status.group(1) if status else "?"

    rules = parse_H(h)

    print("=" * 92)
    print(f"[XSS #{n}]  {ts}")
    print(f"  출발지→목적지 : {src} → {dst}  (Host: {host})")
    print(f"  요청          : {method} {uri}")
    print(f"  URI 디코딩    : {unquote_plus(uri)}")
    if c:
        print(f"  POST 본문     : {unquote_plus(c)}")
    if ref:
        print(f"  Referer       : {unquote_plus(ref)}")
    print(f"  User-Agent    : {ua}")
    print(f"  응답 코드     : {resp_code}  ({'차단됨' if resp_code in ('403','406') else '통과(서버 도달)' if resp_code=='200' else resp_code})")
    print(f"  매칭 룰 {len(rules)}개:")
    for r in rules:
        print(f"    - id={r['id']} sev={r['sev']} var={r['var']}")
        print(f"      msg : {r['msg']}")
        if r["data"]:
            print(f"      data: {r['data'][:160]}")
