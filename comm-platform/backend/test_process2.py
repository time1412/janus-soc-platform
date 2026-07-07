# -*- coding: utf-8 -*-
"""다이어그램 프로세스 검증: 미접수→접수→대응→승인대기→종결, 오탐요청→오탐종결, 무시종결, 재오픈."""
import requests
B = "http://localhost:8810"


def get(eid): return requests.get(f"{B}/api/events/{eid}", timeout=10).json()
def st(eid, uid, status, code=""):
    requests.post(f"{B}/api/events/{eid}/status", json={"user_id": uid, "status": status, "resolution_code": code}, timeout=10)
def ingest(sig, ip, atk):
    return requests.post(f"{B}/api/events/ingest", json={"events": [{"signature": sig, "src_ip": ip, "ai_attack_type": atk, "severity": "3", "ai_confidence": 90}]}, timeout=15).json()["ids"][0]


users = requests.get(f"{B}/api/users", timeout=10).json()
soc = next(u for u in users if u["team"] == "보안관제팀")
wa = next(u for u in users if u["team"] == "웹관리자")
inf = next(u for u in users if u["team"] == "정보보호팀")

# 1) 정탐 본류: 미접수→접수→대응→승인대기→종결
e = ingest("SQL Injection", "203.0.113.10", "SQL Injection")
print("[정탐]", get(e)["status"], end="")
st(e, soc["id"], "접수");    print(" →", get(e)["status"], end="")
st(e, soc["id"], "대응");    print(" →", get(e)["status"], "(정탐 이관)", end="")
st(e, wa["id"], "승인대기"); print(" →", get(e)["status"], "(대응완료)", end="")
requests.post(f"{B}/api/events/{e}/status", json={"user_id": inf["id"], "status": "종결", "resolution_code": "정탐/조치완료"}, timeout=10)
d = get(e); print(" →", d["status"], f"판정={d['resolution_code']}")
assert d["status"] == "종결" and d["resolution_code"] == "정탐/조치완료"

# 2) 오탐 분기: 미접수→접수→오탐요청→오탐종결
e2 = ingest("XSS", "198.51.100.20", "XSS")
st(e2, soc["id"], "접수"); st(e2, soc["id"], "오탐요청")
print("[오탐]", get(e2)["status"], end="")
st(e2, inf["id"], "오탐종결", "오탐확정")
d2 = get(e2); print(" →", d2["status"], f"판정={d2['resolution_code']}")
assert d2["status"] == "오탐종결"

# 3) 무시종결(오탐·중복): 미접수→무시종결
e3 = ingest("XSS", "198.51.100.30", "XSS")
st(e3, soc["id"], "무시종결", "오탐·중복")
d3 = get(e3); print("[무시]", d3["status"], f"판정={d3['resolution_code']}")
assert d3["status"] == "무시종결"

# 4) 재오픈: 종결→접수(초기화)
st(e, soc["id"], "접수")
d = get(e); print("[재오픈] 종결 →", d["status"], f"(종결정보 초기화: {'O' if not d['resolution_code'] else 'X'})")
assert d["status"] == "접수" and not d["resolution_code"]

print("\nOK — 다이어그램 프로세스(미접수·접수·대응·승인대기·종결 + 오탐요청·오탐종결 + 무시종결 + 재오픈) 검증 완료")
