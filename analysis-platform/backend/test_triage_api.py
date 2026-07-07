"""분석플랫폼 /api/triage 동작 확인 — 정탐/오탐 혼합 샘플."""
import requests

B = "http://localhost:8800"

evts = [
    {"signature": "SQL Injection", "src_ip": "10.44.44.44",
     "uri": "/concert/list.do?keyword=%27%20OR%201%3D1%20--", "severity": "3", "source": "modsec"},
    {"signature": "Command Injection", "src_ip": "10.20.30.40",
     "uri": "/concert/listJson.do;jsessionid=A1B2C3D4E5F6", "severity": "3", "source": "modsec"},
    {"signature": "XSS", "src_ip": "10.20.30.41",
     "uri": "/faq/selectFaqList.do?page=1&size=10", "severity": "2", "source": "modsec"},
    {"signature": "Path Traversal", "src_ip": "10.44.44.44",
     "uri": "/qna/downloadFile.do?fileName=../../../../etc/passwd", "severity": "3", "source": "modsec"},
]

r = requests.post(f"{B}/api/triage", json={"events": evts}, timeout=150).json()
print("counts:", r["counts"])
for x in r["results"]:
    t = x["triage"]
    print(f" - {x['alert']['signature']:16} -> {t['verdict']} {t['confidence']}%  ({t.get('attack_type')})")
    print(f"     {t.get('reasoning')}")
