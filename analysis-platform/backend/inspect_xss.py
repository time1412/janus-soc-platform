"""최근 경보 중 XSS 관련 건을 source/시그니처/시간별로 비교 — 중복 원인 진단."""
import requests

r = requests.get("http://localhost:8800/api/alerts", params={"earliest": "-2h"}, timeout=30)
alerts = r.json().get("alerts", [])
print(f"전체 경보(2h): {len(alerts)}건\n")

# XSS/스크립트 관련만 추림
xss = [a for a in alerts if "xss" in str(a.get("signature", "")).lower()
       or "script" in str(a.get("uri", "")).lower()
       or "script" in str(a.get("signature", "")).lower()]

print(f"XSS 의심 경보: {len(xss)}건")
print("-" * 90)
for a in xss[:12]:
    print(f"_time   : {a.get('_time')}")
    print(f"source  : {a.get('source'):8}  sourcetype: {a.get('sourcetype')}")
    print(f"sig     : {a.get('signature')}")
    print(f"src->dst: {a.get('src_ip')} -> {a.get('dest_ip')}")
    print(f"uri     : {a.get('uri')}")
    print(f"host    : {a.get('host')}  severity: {a.get('severity')}")
    print("-" * 90)
