"""티켓팅 2차: 플레이북/체크리스트 · 종결(코드+RCA) · 지표 · 대장 컬럼."""
import requests

B = "http://localhost:8810"


def main() -> None:
    u = requests.post(f"{B}/api/signup", json={"username": "tkt2", "password": "1234", "display_name": "분석가2", "team": "보안관제팀"}).json()
    if not u.get("id"):
        u = requests.post(f"{B}/api/login", json={"username": "tkt2", "password": "1234"}).json()

    t = requests.post(f"{B}/api/events/ticket", json={"user_id": u["id"], "signature": "웹 공격 의심", "severity": "3", "src_ip": "10.44.44.44"}).json()
    tid = t["id"]

    # 담당 배정 (지표 분석가별용)
    requests.post(f"{B}/api/events/{tid}/assign", json={"user_id": u["id"], "assignee_id": u["id"]})

    # ── 플레이북 적용 ──
    pbs = requests.get(f"{B}/api/events/playbooks").json()["playbooks"]
    key = pbs[0]["key"]
    d = requests.post(f"{B}/api/events/{tid}/playbook", json={"user_id": u["id"], "key": key}).json()
    assert len(d["tasks"]) == len(pbs[0]["tasks"])
    print(f"✅ 플레이북 '{key}' 적용: 작업 {len(d['tasks'])}개")

    # 작업 추가 + 완료 토글
    d = requests.post(f"{B}/api/events/{tid}/tasks", json={"user_id": u["id"], "title": "추가 점검"}).json()
    task = d["tasks"][-1]
    d = requests.patch(f"{B}/api/events/{tid}/tasks/{task['id']}", json={"user_id": u["id"], "done": True}).json()
    done = [t for t in d["tasks"] if t["id"] == task["id"]][0]["done"]
    assert done
    print(f"✅ 작업 추가+완료 토글: '{task['title']}' done={done}")

    # ── 종결(코드 + RCA) ──
    d = requests.post(f"{B}/api/events/{tid}/status", json={"user_id": u["id"], "status": "조치완료", "resolution_code": "차단조치", "root_cause": "WAF 룰 미흡으로 우회됨 → 룰 보강"}).json()
    assert d["status"] == "조치완료" and d["resolution_code"] == "차단조치" and d["resolved_at"] and "WAF" in d["root_cause"]
    print(f"✅ 종결: {d['status']} · 코드={d['resolution_code']} · resolved_at={d['resolved_at'][:16]}")
    print(f"   RCA: {d['root_cause']}")

    # ── 지표 ──
    m = requests.get(f"{B}/api/events/metrics").json()
    assert "mttr_hours" in m and "sla_rate" in m and "by_priority" in m
    print(f"✅ 지표: 전체 {m['total']} · 종결 {m['closed']} · MTTR {m['mttr_hours']}h · SLA {m['sla_rate']}% · 초과 {m['open_overdue']}")
    print(f"   우선순위 분포: {m['by_priority']}")
    print(f"   분석가별: {m['by_assignee']}")

    # ── 대장에 티켓번호/우선순위/종결코드 반영 ──
    led = requests.get(f"{B}/api/ledger").json()["rows"]
    row = [r for r in led if r["id"] == tid][0]
    assert row["ticket_no"].startswith("INC-") and row["priority"] == "P1"
    print(f"✅ 대장 반영: {row['ticket_no']} · {row['priority']} · 종결코드={row['resolution_code']}")
    csv = requests.get(f"{B}/api/ledger/export").text
    assert "티켓번호" in csv and "우선순위" in csv and "종결코드" in csv
    print("✅ CSV 헤더에 티켓번호·우선순위·종결코드 포함")

    print("\n🎉 티켓팅 2차(플레이북·종결·지표·대장) 검증 통과")


if __name__ == "__main__":
    main()
