# -*- coding: utf-8 -*-
"""티켓 라이프사이클 + 기본 태그/MITRE + 역할 전이 검증."""
import requests
B = "http://localhost:8810"

# 0) 사용자(팀별) 확보
users = requests.get(f"{B}/api/users", timeout=10).json()
soc = next((u for u in users if u["team"] == "보안관제팀"), users[0])
infosec = next((u for u in users if u["team"] == "정보보호팀"), users[0])

# 1) 분석플랫폼 정탐 수신 → 기본 태그/MITRE 자동 + 상태 신규
ing = requests.post(f"{B}/api/events/ingest", json={"events": [{
    "signature": "SQL Injection", "src_ip": "203.0.113.50", "uri": "/q?id=1' OR 1=1--",
    "severity": "3", "ai_attack_type": "SQL Injection", "ai_confidence": 95,
}]}, timeout=15).json()
eid = ing["ids"][0]
d = requests.get(f"{B}/api/events/{eid}", timeout=10).json()
print(f"1) 수신: status={d['status']} tags={d['tags']!r} mitre={d['mitre']!r}")
assert d["status"] == "신규" and d["tags"] and d["mitre"], "기본 태그/MITRE 또는 상태 오류"

# 2) 배정 → 상태 자동 배정
requests.post(f"{B}/api/events/{eid}/assign", json={"user_id": soc["id"], "assignee_id": infosec["id"]}, timeout=10)
d = requests.get(f"{B}/api/events/{eid}", timeout=10).json()
print(f"2) 배정: status={d['status']} 담당={d['assignee']['display_name'] if d['assignee'] else None}")
assert d["status"] == "배정"

# 3) 진행 → 보류 → 재개(진행)
for st in ["진행", "보류", "진행"]:
    requests.post(f"{B}/api/events/{eid}/status", json={"user_id": infosec["id"], "status": st}, timeout=10)
d = requests.get(f"{B}/api/events/{eid}", timeout=10).json()
print(f"3) 진행→보류→재개: status={d['status']}")
assert d["status"] == "진행"

# 4) 완료(판정 결과) → resolved_at + resolution_code
requests.post(f"{B}/api/events/{eid}/status", json={"user_id": infosec["id"], "status": "완료",
              "resolution_code": "정탐/조치완료", "root_cause": "WAF 차단 룰 적용"}, timeout=10)
d = requests.get(f"{B}/api/events/{eid}", timeout=10).json()
print(f"4) 완료: status={d['status']} 판정={d['resolution_code']!r} resolved_at={'있음' if d['resolved_at'] else '없음'}")
assert d["status"] == "완료" and d["resolution_code"] == "정탐/조치완료" and d["resolved_at"]

# 5) 재오픈 → 진행 + 종결정보 초기화
requests.post(f"{B}/api/events/{eid}/status", json={"user_id": soc["id"], "status": "진행"}, timeout=10)
d = requests.get(f"{B}/api/events/{eid}", timeout=10).json()
print(f"5) 재오픈: status={d['status']} 판정={d['resolution_code']!r} resolved_at={'있음' if d['resolved_at'] else '없음'}")
assert d["status"] == "진행" and not d["resolution_code"] and not d["resolved_at"]

# 6) 종료(관제팀)
requests.post(f"{B}/api/events/{eid}/status", json={"user_id": soc["id"], "status": "종료"}, timeout=10)
d = requests.get(f"{B}/api/events/{eid}", timeout=10).json()
print(f"6) 종료: status={d['status']}")
assert d["status"] == "종료"

# 7) 플레이북 불러오기 = 기존 작업 초기화 후 로드
requests.post(f"{B}/api/events/{eid}/tasks", json={"user_id": soc["id"], "title": "임시작업"}, timeout=10)
pbs = requests.get(f"{B}/api/events/playbooks", timeout=10).json()["playbooks"]
if pbs:
    requests.post(f"{B}/api/events/{eid}/playbook", json={"user_id": soc["id"], "key": pbs[0]["key"]}, timeout=10)
    d = requests.get(f"{B}/api/events/{eid}", timeout=10).json()
    titles = [t["title"] for t in d["tasks"]]
    print(f"7) 플레이북 '{pbs[0]['key']}' 불러오기 후 작업 {len(titles)}개 (임시작업 제거됨: {'임시작업' not in titles})")
    assert "임시작업" not in titles, "기존 작업이 초기화되지 않음"

print("\nOK — 라이프사이클(신규→배정→진행↔보류→완료→재오픈→종료) + 기본 태그/MITRE + 플레이북 초기화 검증 완료")
