# -*- coding: utf-8 -*-
"""수집 커버리지 진단 — 스플렁크 전체 vs 분석플랫폼(ALERT_SPL)이 가져오는 범위 비교."""
import requests
import config

B = "http://localhost:8800"


def run(spl, earliest="-24h"):
    r = requests.post(f"{B}/api/search", json={"spl": spl, "earliest": earliest}, timeout=120)
    return r.json().get("results", [])


print("=" * 80)
print("① 스플렁크에 들어오는 소스타입별 이벤트 수 (최근 24h)")
print("=" * 80)
for row in run('| tstats count where index=* by sourcetype | sort -count'):
    print(f"  {row.get('count','?'):>8}  {row.get('sourcetype','?')}")

print("\n" + "=" * 80)
print("② ModSecurity(waf_audit): 전체 vs attack 태그 보유 vs 미보유")
print("=" * 80)
total = run('search index=waf_audit sourcetype="modsec:audit:serial" | stats count')
tagged = run('search index=waf_audit sourcetype="modsec:audit:serial" "attack-" | stats count')
print(f"  전체 modsec 이벤트     : {total[0].get('count') if total else 0}")
print(f"  attack- 태그 있음(수집) : {tagged[0].get('count') if tagged else 0}")

print("\n  [attack- 태그가 없어서 분석플랫폼에서 누락되는 modsec 이벤트 샘플]")
miss = run('search index=waf_audit sourcetype="modsec:audit:serial" NOT "attack-" '
           '| rex field=_raw "(?:GET|POST|PUT|DELETE) (?<u>\\S+) HTTP" '
           '| rex field=_raw "\\[msg \\"(?<m>[^\\"]+)\\"\\]" '
           '| head 8 | table _time u m')
for row in miss:
    print(f"    [{row.get('_time','?')}] {row.get('u','?')}")
    print(f"        rule msg: {row.get('m','(태그/룰 없음 — 정상 트래픽 가능성)')}")

print("\n" + "=" * 80)
print("③ 분석플랫폼 ALERT_SPL이 최종적으로 반환하는 경보 수")
print("=" * 80)
alerts = requests.get(f"{B}/api/alerts", params={"earliest": "-24h"}, timeout=120).json()
print(f"  분석플랫폼 표시 경보 수 : {alerts.get('count', 0)}")
src = {}
for a in alerts.get("alerts", []):
    src[a.get("source", "?")] = src.get(a.get("source", "?"), 0) + 1
print(f"  소스별: {src}")
