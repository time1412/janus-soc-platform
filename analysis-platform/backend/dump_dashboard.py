# -*- coding: utf-8 -*-
"""스플렁크 대시보드(전체로그 탭 - 보안 이벤트 목록) 패널의 SPL을 추출."""
import re

import requests
import urllib3

import config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

s = requests.Session()
s.verify = False
if config.SPLUNK_TOKEN:
    s.headers["Authorization"] = f"Bearer {config.SPLUNK_TOKEN}"
else:
    s.auth = (config.SPLUNK_USERNAME, config.SPLUNK_PASSWORD)
base = f"https://{config.SPLUNK_HOST}:{config.SPLUNK_PORT}"

# 1) 모든 대시보드(뷰) 목록
r = s.get(f"{base}/servicesNS/-/-/data/ui/views",
          params={"output_mode": "json", "count": 0}, timeout=60)
r.raise_for_status()
views = r.json().get("entry", [])
print(f"전체 대시보드 수: {len(views)}\n")

KEY = ("보안 이벤트", "전체로그", "전체 로그", "pfSense", "WAF Web", "보안 이벤트 목록")
for v in views:
    name = v.get("name", "")
    data = v.get("content", {}).get("eai:data", "") or ""
    if not any(k in data for k in KEY) and not any(k in name for k in KEY):
        continue
    print("=" * 90)
    print(f"대시보드: {name}")
    print("=" * 90)
    # 패널 제목 + query 추출
    titles = re.findall(r"<title>(.*?)</title>", data, flags=re.DOTALL)
    print("패널/타이틀:", [t.strip() for t in titles][:20])
    queries = re.findall(r"<query>(.*?)</query>", data, flags=re.DOTALL | re.IGNORECASE)
    for i, q in enumerate(queries, 1):
        q = q.replace("<![CDATA[", "").replace("]]>", "").strip()
        if any(k in q for k in ("event", "alert", "search", "index", "pfSense", "waf", "snort", "보안")):
            print(f"\n--- query #{i} ---")
            print(q)
