# -*- coding: utf-8 -*-
"""소스 교차 병합 검증 — 52개 원본 경보가 인시던트(유형+IP)로 합쳐지는지."""
import requests
B = "http://localhost:8800"
j = requests.get(f"{B}/api/triage", params={"limit": 80}, timeout=240).json()
c = j["counts"]
print(f"원본경보수={c.get('원본경보수')} → 인시던트(병합후)={c['total']}  (정탐={c['정탐']} 오탐={c['오탐']} 신규판정={c['신규판정']})")
print("-" * 80)
for r in j["results"]:
    a, t = r["alert"], r["triage"]
    src = ",".join(a.get("merged_sources", []))
    print(f"[{t['verdict']} {t['confidence']:3d}%] {a.get('signature'):42} | {a.get('src_ip')} "
          f"| 병합 {a.get('merged_count')}건 ({src})")
