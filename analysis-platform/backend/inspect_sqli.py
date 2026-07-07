"""QnA POST SQLi 오탐 진단 — AI에 전달되는 필드(uri/status/body)와 원본 _raw 비교."""
import requests
import config

B = "http://localhost:8800"

# 1) 현재 대시보드 경보에서 SQLi 건이 어떤 필드를 갖는지
r = requests.get(f"{B}/api/alerts", params={"earliest": "-3h"}, timeout=30).json()
sqli = [a for a in r.get("alerts", []) if "sql" in str(a.get("signature", "")).lower()]
print(f"=== 대시보드 SQLi 경보 {len(sqli)}건 (triage가 보는 필드) ===")
for a in sqli[:6]:
    print(f"[{a.get('_time')}] {a.get('source')} sig={a.get('signature')}")
    print(f"   uri   = {a.get('uri')!r}")
    print(f"   status= {a.get('status')!r}   (triage가 본문으로 읽는 필드)")
    print(f"   body  = {a.get('body')!r}")
    print("-" * 80)

# 2) 원본 _raw에 POST 본문이 실제로 있는지 (modsec audit C 섹션)
spl = ('search index=waf_audit sourcetype="modsec:audit:serial" '
       '| rex field=_raw "(?:GET|POST) (?<u>\\S+) HTTP" '
       '| search _raw="*sqli*" OR _raw="*SQL*" '
       '| head 2 | table _raw')
sr = requests.post(f"{B}/api/search", json={"spl": spl, "earliest": "-3h"}, timeout=60).json()
print(f"\n=== 원본 _raw 샘플 {len(sr.get('results', []))}건 ===")
for row in sr.get("results", [])[:2]:
    raw = row.get("_raw", "")
    print(raw[:1500])
    print("=" * 80)
