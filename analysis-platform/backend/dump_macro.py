# -*- coding: utf-8 -*-
"""soc_base 매크로 정의 + '보안 이벤트 목록' 패널 쿼리 + 토큰 기본값 추출."""
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

# 1) soc_base 및 관련 매크로 정의 전부
print("=" * 90)
print("매크로 정의 (conf-macros)")
print("=" * 90)
r = s.get(f"{base}/servicesNS/-/-/configs/conf-macros",
          params={"output_mode": "json", "count": 0, "search": "soc"}, timeout=60)
for e in r.json().get("entry", []):
    name = e.get("name", "")
    defn = e.get("content", {}).get("definition", "")
    if defn:
        print(f"\n[{name}]")
        print(defn)

# 2) '보안 이벤트 목록' 패널 쿼리 + 토큰(fieldset) 기본값
print("\n" + "=" * 90)
print("'보안 이벤트 목록' 패널 + 토큰 기본값")
print("=" * 90)
r = s.get(f"{base}/servicesNS/-/-/data/ui/views",
          params={"output_mode": "json", "count": 0}, timeout=60)
for v in r.json().get("entry", []):
    data = v.get("content", {}).get("eai:data", "") or ""
    if "보안 이벤트 목록" not in data:
        continue
    print(f"\n### 대시보드: {v.get('name')}")
    # 토큰 기본값(input default/choice)
    for m in re.finditer(r'<input[^>]*token="([^"]+)"[^>]*>(.*?)</input>', data, re.DOTALL):
        tok, body = m.group(1), m.group(2)
        dflt = re.search(r"<default>(.*?)</default>", body, re.DOTALL)
        print(f"  token {tok} default = {dflt.group(1).strip() if dflt else '(없음)'}")
    # '보안 이벤트 목록' 패널의 query
    for pm in re.finditer(r"<panel>(.*?)</panel>", data, re.DOTALL):
        panel = pm.group(1)
        if "보안 이벤트 목록" in panel:
            q = re.search(r"<query>(.*?)</query>", panel, re.DOTALL)
            if q:
                print("\n  [보안 이벤트 목록 query]")
                print("  " + q.group(1).replace("<![CDATA[", "").replace("]]>", "").strip())
