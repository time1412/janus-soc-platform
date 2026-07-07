"""버그 헌트 — 실제 플로우 + 엣지케이스/정합성 집중 점검."""
import io

import requests

B = "http://localhost:8810"
PNG = bytes.fromhex("89504e470d0a1a0a0000000d49484452000000010000000108020000009077"
                    "53de0000000c4944415408d7636060606000000005000157a1d0fe0000000049454e44ae426082")

bugs = []


def check(name, ok, detail=""):
    print(("  ✅ " if ok else "  ❌ BUG ") + name + (f"  [{detail}]" if detail and not ok else ""))
    if not ok:
        bugs.append(f"{name} — {detail}")


def login(uname, name="X", team="보안관제팀"):
    u = requests.post(f"{B}/api/signup", json={"username": uname, "password": "1234", "display_name": name, "team": team}).json()
    return u if u.get("id") else requests.post(f"{B}/api/login", json={"username": uname, "password": "1234"}).json()


def main() -> None:
    u = login("bh_u", "헌터", "보안관제팀")
    u2 = login("bh_u2", "동료", "정보보호팀")

    print("\n[1] 인증/가입 엣지케이스")
    check("짧은 비밀번호 거부", requests.post(f"{B}/api/signup", json={"username": "bh_x", "password": "12", "display_name": "x", "team": "보안관제팀"}).status_code == 400)
    check("잘못된 소속 거부", requests.post(f"{B}/api/signup", json={"username": "bh_y", "password": "1234", "display_name": "y", "team": "개발팀"}).status_code == 400)
    check("틀린 비밀번호 로그인 거부", requests.post(f"{B}/api/login", json={"username": "bh_u", "password": "wrong"}).status_code == 401)
    check("중복 가입은 기존 계정 무변경", login("bh_u")["id"] == u["id"])

    print("\n[2] 티켓 상태 전이 / 종결 / 재오픈")
    t = requests.post(f"{B}/api/events/ticket", json={"user_id": u["id"], "signature": "버그 테스트 티켓", "severity": "3"}).json()
    tid = t["id"]
    check("잘못된 상태값 거부", requests.post(f"{B}/api/events/{tid}/status", json={"user_id": u["id"], "status": "이상한값"}).status_code == 400)
    check("잘못된 우선순위 거부", requests.post(f"{B}/api/events/{tid}/priority", json={"user_id": u["id"], "priority": "P9"}).status_code == 400)
    # 종결
    d = requests.post(f"{B}/api/events/{tid}/status", json={"user_id": u["id"], "status": "조치완료", "resolution_code": "차단조치", "root_cause": "원인X"}).json()
    check("종결 시 resolved_at 기록", bool(d["resolved_at"]))
    check("종결 코드 기록", d["resolution_code"] == "차단조치")
    # 재오픈 → resolved_at + 종결정보가 정리돼야 함
    d2 = requests.post(f"{B}/api/events/{tid}/status", json={"user_id": u["id"], "status": "검토중"}).json()
    check("재오픈 시 resolved_at 해제", d2["resolved_at"] is None)
    check("재오픈 시 종결코드 정리", d2["resolution_code"] == "", f"잔존='{d2['resolution_code']}'")
    check("재오픈 시 RCA 정리", d2["root_cause"] == "", f"잔존='{d2['root_cause']}'")

    print("\n[3] 우선순위→SLA 재계산")
    before = requests.get(f"{B}/api/events/{tid}").json()["due_at"]
    after = requests.post(f"{B}/api/events/{tid}/priority", json={"user_id": u["id"], "priority": "P4"}).json()["due_at"]
    check("우선순위 변경 시 SLA 변경", before != after)

    print("\n[4] 작업/플레이북/첨부")
    pb = requests.get(f"{B}/api/events/playbooks").json()["playbooks"][0]
    d = requests.post(f"{B}/api/events/{tid}/playbook", json={"user_id": u["id"], "key": pb["key"]}).json()
    check("플레이북 적용 작업 수 일치", len(d["tasks"]) == len(pb["tasks"]))
    check("없는 플레이북 거부", requests.post(f"{B}/api/events/{tid}/playbook", json={"user_id": u["id"], "key": "없는PB"}).status_code == 400)
    task = d["tasks"][0]
    d = requests.patch(f"{B}/api/events/{tid}/tasks/{task['id']}", json={"user_id": u["id"], "done": True}).json()
    check("작업 완료 토글", [x for x in d["tasks"] if x["id"] == task["id"]][0]["done"])
    check("없는 작업 토글 404", requests.patch(f"{B}/api/events/{tid}/tasks/999999", json={"user_id": u["id"], "done": True}).status_code == 404)
    up = requests.post(f"{B}/api/upload", files={"file": ("e.png", io.BytesIO(PNG), "image/png")}).json()
    d = requests.post(f"{B}/api/events/{tid}/attachments", json={"user_id": u["id"], "url": up["url"], "name": "e.png", "size": up["size"]}).json()
    aid = d["attachments"][0]["id"]
    check("다른 이벤트의 첨부 삭제 404", requests.delete(f"{B}/api/events/99999/attachments/{aid}").status_code == 404)

    print("\n[5] IOC 추출 + dedup + 날짜")
    requests.post(f"{B}/api/events/{tid}/assign", json={"user_id": u["id"], "assignee_id": u["id"]})
    iocs = requests.post(f"{B}/api/iocs/extract/{tid}?user_id={u['id']}").json()
    check("수동티켓 IOC 추출(IP 없음→0건 무crash)", isinstance(iocs, list))
    requests.post(f"{B}/api/iocs", json={"ioc_type": "IP", "value": "9.9.9.9", "first_seen": "2026-06-01"})
    n1 = requests.get(f"{B}/api/iocs/stats").json()["total"]
    requests.post(f"{B}/api/iocs", json={"ioc_type": "IP", "value": "9.9.9.9"})
    n2 = requests.get(f"{B}/api/iocs/stats").json()["total"]
    check("IOC 중복 upsert(증가X)", n1 == n2)
    r = requests.get(f"{B}/api/iocs?date_from=2026-06-05").json()
    check("IOC 날짜필터(6/1건 제외)", all(x["value"] != "9.9.9.9" for x in r))

    print("\n[6] 메일(인앱/외부/삭제)")
    check("없는 수신자 인앱메일 404", requests.post(f"{B}/api/mail", json={"sender_id": u["id"], "recipient_id": 999999, "subject": "x", "body": "y"}).status_code == 404)
    check("제목없는 메일 거부", requests.post(f"{B}/api/mail", json={"sender_id": u["id"], "recipient_id": u2["id"], "subject": "  ", "body": "y"}).status_code == 400)
    ext = requests.post(f"{B}/api/mail", json={"sender_id": u["id"], "recipient_email": "dev@company.local", "recipient_name": "개발", "recipient_dept": "개발팀", "subject": "외부", "body": "z"}).json()
    check("외부메일 채널=email + 드라이런 ok", ext.get("channel") == "email" and ext.get("ok"))
    mail = requests.post(f"{B}/api/mail", json={"sender_id": u["id"], "recipient_id": u2["id"], "subject": "삭제테스트", "body": "y"}).json()
    requests.delete(f"{B}/api/mail/{mail['id']}?user_id={u2['id']}")
    sent_still = any(m["id"] == mail["id"] for m in requests.get(f"{B}/api/mail/sent?user_id={u['id']}").json())
    inbox_gone = all(m["id"] != mail["id"] for m in requests.get(f"{B}/api/mail/inbox?user_id={u2['id']}").json())
    check("수신자 삭제→발신자 보낸함 유지", sent_still)
    check("수신자 삭제→받은함에서 제거", inbox_gone)

    print("\n[7] 채팅/DM 엣지")
    ch = requests.get(f"{B}/api/chat/channels").json()[0]
    check("빈 채팅 거부", requests.post(f"{B}/api/chat/channels/{ch['id']}/messages", json={"user_id": u["id"], "body": "   "}).status_code == 400)
    check("없는 채널 채팅 404", requests.post(f"{B}/api/chat/channels/99999/messages", json={"user_id": u["id"], "body": "x"}).status_code == 404)
    check("자기자신 DM 거부", requests.post(f"{B}/api/dm", json={"sender_id": u["id"], "recipient_id": u["id"], "body": "x"}).status_code == 400)
    check("빈 DM 거부", requests.post(f"{B}/api/dm", json={"sender_id": u["id"], "recipient_id": u2["id"], "body": "  "}).status_code == 400)

    print("\n[8] 대장/지표 정합성")
    led = requests.get(f"{B}/api/ledger").json()
    row = [r for r in led["rows"] if r["id"] == tid][0]
    check("대장에 티켓번호/우선순위 존재", row["ticket_no"].startswith("INC-") and row["priority"] in ("P1", "P2", "P3", "P4"))
    m = requests.get(f"{B}/api/events/metrics").json()
    check("지표 SLA 0~100 범위", 0 <= m["sla_rate"] <= 100)
    check("지표 진행중+종결=전체", m["open"] + m["closed"] == m["total"])

    print("\n" + "=" * 60)
    if bugs:
        print(f" 발견된 버그 {len(bugs)}건:")
        for b in bugs:
            print("  · " + b)
    else:
        print(" 버그 없음 — 모든 점검 통과")
    print("=" * 60)


if __name__ == "__main__":
    main()
