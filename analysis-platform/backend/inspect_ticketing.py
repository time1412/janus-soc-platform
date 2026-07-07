# -*- coding: utf-8 -*-
"""스플렁크 ticketing:application 데이터의 상태 흐름 확인 (관제 티켓팅 프로세스 원본)."""
import requests
B = "http://localhost:8800"


def run(spl, e="-30d"):
    return requests.post(f"{B}/api/search", json={"spl": spl, "earliest": e}, timeout=120).json().get("results", [])


print("=== ticketing:application 원본 샘플 2건 ===")
for r in run('search index=* sourcetype=ticketing:application | head 2 | table _raw'):
    print(str(r.get("_raw"))[:600]); print("-" * 80)

print("\n=== 상태(status) 분포 ===")
for f in ["status", "ticket_status", "state", "stage", "단계", "상태"]:
    rows = run(f'search index=* sourcetype=ticketing:application | stats count by {f}')
    if rows and any(r.get(f) for r in rows):
        print(f"[필드 '{f}']")
        for r in rows:
            print(f"  {r.get('count'):>6}  {r.get(f)}")
        break
else:
    print("표준 필드명 미발견 — 필드 목록 확인:")
    for r in run('search index=* sourcetype=ticketing:application | head 1 | fieldsummary | table field')[:40]:
        print("  ", r.get("field"))
