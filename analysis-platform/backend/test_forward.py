"""정탐 자동 전달 E2E: 분석플랫폼 /api/forward → 소통플랫폼 이벤트 적재 + 멱등성."""
import requests

ANALYSIS = "http://localhost:8800"
COMM = "http://localhost:8810"

# 정탐 1건(SQLi) + 오탐 1건(jsessionid) — 정탐만 전달돼야 함
evts = [
    {"signature": "SQL Injection", "src_ip": "203.0.113.77", "dest_ip": "10.0.10.100",
     "uri": "/board/list.do?id=1%27%20OR%201=1--", "severity": "3", "source": "modsec", "_time": "2026-06-12T10:00:00"},
    {"signature": "Command Injection", "src_ip": "198.51.100.5", "dest_ip": "10.0.10.100",
     "uri": "/app/view;jsessionid=AB12CD34EF", "severity": "3", "source": "modsec", "_time": "2026-06-12T10:01:00"},
]

before = requests.get(f"{COMM}/api/events", timeout=10).json()
n_before = len(before) if isinstance(before, list) else len(before.get("events", before))

r1 = requests.post(f"{ANALYSIS}/api/forward", json={"events": evts}, timeout=120).json()
print("1차 전달:", r1)

after = requests.get(f"{COMM}/api/events", timeout=10).json()
rows = after if isinstance(after, list) else after.get("events", after)
n_after = len(rows)
print(f"소통플랫폼 이벤트 수: {n_before} -> {n_after}")

# 적재된 최신 이벤트 확인
newest = rows[0] if rows else {}
print("최신 이벤트:", {k: newest.get(k) for k in ("id", "ticket_no", "signature", "src_ip", "ai_confidence", "ai_attack_type", "origin", "status")})

# 멱등성: 동일 정탐 재전달 → forwarded 0, skipped_dup로 분류
r2 = requests.post(f"{ANALYSIS}/api/forward", json={"events": evts}, timeout=120).json()
print("2차 전달(멱등):", r2)

assert r1["forwarded"] == 1, f"정탐 1건 전달 기대, got {r1}"
assert r1["total_tp"] == 1, f"정탐 총계 1 기대(오탐 제외), got {r1}"
assert n_after == n_before + 1, "소통플랫폼에 1건만 적재돼야 함"
assert r2["forwarded"] == 0 and r2["skipped_dup"] == 1, f"재전달은 0이어야(멱등), got {r2}"
print("\nOK — 정탐만 전달 + 오탐 제외 + 중복 재전달 차단 확인")
