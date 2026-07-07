# -*- coding: utf-8 -*-
"""정보보안 관제 프로세스 검증:
이벤트→티켓(신규)→판정(보안관제)→대응(웹관리자)→최종승인(정보보호)→완료, 및 오탐 반려/재오픈.
+ 웹관리자 권한(회원가입) 생성 확인.
"""
import requests
B = "http://localhost:8810"


def get(eid):
    return requests.get(f"{B}/api/events/{eid}", timeout=10).json()


def st(eid, uid, status, code=""):
    requests.post(f"{B}/api/events/{eid}/status",
                  json={"user_id": uid, "status": status, "resolution_code": code}, timeout=10)


# 0) 웹관리자 권한 회원가입 (이미 있으면 무시)
import random
uname = "webadmin_" + str(abs(hash("wa")) % 9999)
r = requests.post(f"{B}/api/signup", json={"username": uname, "password": "1234",
                  "display_name": "웹관리자테스트", "team": "웹관리자", "role": "웹마스터"}, timeout=10)
if r.status_code == 200:
    wa = r.json()
    print(f"0) 웹관리자 권한 가입 OK: {wa['display_name']} (team={wa['team']})")
else:
    wa = next(u for u in requests.get(f"{B}/api/users", timeout=10).json() if u["team"] == "웹관리자")
    print(f"0) 웹관리자 계정 존재: {wa['display_name']}")
users = requests.get(f"{B}/api/users", timeout=10).json()
soc = next(u for u in users if u["team"] == "보안관제팀")
inf = next(u for u in users if u["team"] == "정보보호팀")

# 1) 정탐 경로: 신규→판정→대응→승인대기→완료
ing = requests.post(f"{B}/api/events/ingest", json={"events": [{
    "signature": "SQL Injection", "src_ip": "203.0.113.99", "uri": "/q?id=1' UNION SELECT--",
    "severity": "3", "ai_attack_type": "SQL Injection", "ai_confidence": 98}]}, timeout=15).json()
eid = ing["ids"][0]
print(f"\n[정탐 경로] 티켓 {eid}")
print("  수신:", get(eid)["status"])
st(eid, soc["id"], "판정");      print("  보안관제 판정 시작:", get(eid)["status"])
st(eid, soc["id"], "대응");      print("  보안관제 정탐 확정→대응:", get(eid)["status"])
st(eid, wa["id"], "승인대기");   print("  웹관리자 대응 완료→승인요청:", get(eid)["status"])
requests.post(f"{B}/api/events/{eid}/status", json={"user_id": inf["id"], "status": "완료",
              "resolution_code": "정탐/조치완료", "root_cause": "WAF 룰 적용"}, timeout=10)
d = get(eid); print(f"  정보보호 최종 승인→완료: {d['status']} 판정={d['resolution_code']} resolved={'O' if d['resolved_at'] else 'X'}")
assert d["status"] == "완료" and d["resolution_code"] == "정탐/조치완료"

# 1b) 재오픈(보안관제) → 판정
st(eid, soc["id"], "판정")
d = get(eid); print(f"  보안관제 재오픈→판정: {d['status']} (종결정보 초기화: {'O' if not d['resolution_code'] else 'X'})")
assert d["status"] == "판정" and not d["resolution_code"]

# 2) 오탐 경로: 신규→판정→반려
ing2 = requests.post(f"{B}/api/events/ingest", json={"events": [{
    "signature": "XSS", "src_ip": "198.51.100.7", "uri": "/p?x=normal",
    "severity": "2", "ai_attack_type": "XSS", "ai_confidence": 20}]}, timeout=15).json()
eid2 = ing2["ids"][0]
print(f"\n[오탐 경로] 티켓 {eid2}")
st(eid2, soc["id"], "반려", "오탐/반려")
d2 = get(eid2); print(f"  보안관제 오탐 반려: {d2['status']} 판정={d2['resolution_code']}")
assert d2["status"] == "반려" and d2["resolution_code"] == "오탐/반려"

print("\nOK — 프로세스(판정/대응/최종승인) + 웹관리자 권한 + 오탐 반려/재오픈 검증 완료")
