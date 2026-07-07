# -*- coding: utf-8 -*-
"""미접수/접수/이관요청/무시종결 흐름을 정의한 스플렁크 대시보드 검색."""
import re
import requests
import urllib3
import config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
s = requests.Session(); s.verify = False
if config.SPLUNK_TOKEN:
    s.headers["Authorization"] = f"Bearer {config.SPLUNK_TOKEN}"
else:
    s.auth = (config.SPLUNK_USERNAME, config.SPLUNK_PASSWORD)
base = f"https://{config.SPLUNK_HOST}:{config.SPLUNK_PORT}"

KEY = ("미접수", "이관요청", "이관승인", "무시종결", "오탐종결", "오탐요청")
r = s.get(f"{base}/servicesNS/-/-/data/ui/views", params={"output_mode": "json", "count": 0}, timeout=60)
hits = []
for v in r.json().get("entry", []):
    data = v.get("content", {}).get("eai:data", "") or ""
    if any(k in data for k in KEY):
        hits.append((v.get("name"), data))

print(f"매칭 대시보드: {[h[0] for h in hits]}\n")
for name, data in hits[:2]:
    print("=" * 90); print("대시보드:", name); print("=" * 90)
    # 매크로/검색 추출
    for q in re.findall(r"<query>(.*?)</query>", data, flags=re.DOTALL | re.IGNORECASE):
        q = q.replace("<![CDATA[", "").replace("]]>", "").strip()
        if any(k in q for k in KEY) or "case(" in q or "eval" in q:
            print("\n--- query ---"); print(q[:1500])
