# -*- coding: utf-8 -*-
"""분석플랫폼이 '수집하지 않는' 보안 소스에 실제 공격/경보가 있는지 확인."""
import requests

B = "http://localhost:8800"


def run(spl, earliest="-24h"):
    return requests.post(f"{B}/api/search", json={"spl": spl, "earliest": earliest}, timeout=120).json().get("results", [])


print("=== waf_web (316건, 현재 미수집) 샘플 ===")
for r in run('search index=* sourcetype=waf_web | head 4 | table _time _raw'):
    print(f"[{r.get('_time')}] {str(r.get('_raw'))[:200]}")

print("\n=== ossec_alert (2660건, 현재 미수집) 샘플 ===")
for r in run('search index=* sourcetype=ossec_alert | head 5 | table _time _raw'):
    print(f"[{r.get('_time')}] {str(r.get('_raw'))[:220]}")

print("\n=== sguil / snort 존재 여부 (ALERT_SPL에 설정됐지만 결과 0) ===")
for name, spl in [("sguild_alert", 'search index=* sguild_alert | stats count'),
                  ("snort:alert", 'search index=* sourcetype="snort:alert" | stats count'),
                  ("snort 아무거나", 'search index=* sourcetype=*snort* | stats count')]:
    c = run(spl)
    print(f"  {name:18}: {c[0].get('count') if c else 0}건")

print("\n=== bro/Zeek 중 notice(공격 징후) 로그 존재 여부 ===")
for r in run('search index=* sourcetype=bro* (notice OR weird OR intel) | head 3 | table _time sourcetype _raw'):
    print(f"[{r.get('_time')}] {r.get('sourcetype')}: {str(r.get('_raw'))[:160]}")
