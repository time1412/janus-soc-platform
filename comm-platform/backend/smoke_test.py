"""소통플랫폼 전체 플로우 엔드투엔드 스모크 테스트."""
import requests

B = "http://localhost:8810"


def main() -> None:
    ok = 0

    # 1) 로그인
    u = requests.post(f"{B}/api/login", json={"username": "soc_lee", "password": "1234"}).json()
    assert u["display_name"] == "이분석"; ok += 1
    print(f"✅ 로그인: {u['display_name']} ({u['team']})")

    ist = requests.post(f"{B}/api/login", json={"username": "ist_choi", "password": "1234"}).json()

    # 2) 분석플랫폼 → 이벤트 수신(ingest)
    r = requests.post(f"{B}/api/events/ingest", json={"events": [{
        "signature": "SQL Injection", "src_ip": "203.0.113.9", "dest_ip": "10.0.10.2",
        "uri": "/board.do?id=1 UNION SELECT pw FROM users--", "severity": "3",
        "source": "modsec", "ai_verdict": "정탐", "ai_confidence": 96,
        "ai_attack_type": "SQL Injection", "ai_reasoning": "UNION SELECT 구문 확인", "dup_count": 1,
    }]}).json()
    eid = r["ids"][0]; ok += 1
    print(f"✅ 이벤트 수신: id={eid} (ingested={r['ingested']})")

    # 3) 상태 변경 (검토중 → 승인)
    requests.post(f"{B}/api/events/{eid}/status", json={"user_id": u["id"], "status": "검토중"})
    d = requests.post(f"{B}/api/events/{eid}/status",
                      json={"user_id": ist["id"], "status": "승인", "note": "실제 공격 확인"}).json()
    assert d["status"] == "승인"; ok += 1
    print(f"✅ 상태 변경: {d['status']} (이력 {len(d['history'])}건)")

    # 4) 담당자 배정 + 코멘트
    requests.post(f"{B}/api/events/{eid}/assign", json={"user_id": ist["id"], "assignee_id": ist["id"]})
    c = requests.post(f"{B}/api/events/{eid}/comments",
                      json={"user_id": ist["id"], "body": "차단 룰 적용 요청드립니다."}).json()
    assert c["body"]; ok += 1
    print(f"✅ 코멘트 등록: {c['user']['display_name']}: {c['body']}")

    # 5) 채팅
    ch = requests.get(f"{B}/api/chat/channels").json()[1]
    m = requests.post(f"{B}/api/chat/channels/{ch['id']}/messages",
                      json={"user_id": u["id"], "body": f"이벤트 #{eid} 승인됐습니다. 확인 부탁해요."}).json()
    msgs = requests.get(f"{B}/api/chat/channels/{ch['id']}/messages").json()
    assert any(x["id"] == m["id"] for x in msgs); ok += 1
    print(f"✅ 채팅 [{ch['name']}]: \"{m['body']}\" (총 {len(msgs)}건)")

    # 6) 메일 (이벤트 연결)
    mail = requests.post(f"{B}/api/mail", json={
        "sender_id": u["id"], "recipient_id": ist["id"],
        "subject": f"[정탐 #{eid}] 차단 조치 요청", "body": "검토 후 차단 부탁드립니다.",
        "related_event_id": eid,
    }).json()
    inbox = requests.get(f"{B}/api/mail/inbox?user_id={ist['id']}").json()
    unread = requests.get(f"{B}/api/mail/unread_count?user_id={ist['id']}").json()
    assert any(x["id"] == mail["id"] for x in inbox); ok += 1
    print(f"✅ 메일 전송: \"{mail['subject']}\" → {ist['display_name']} (받은편지함 {len(inbox)}건, 안읽음 {unread['unread']})")

    # 7) 통계
    st = requests.get(f"{B}/api/events/stats").json()
    print(f"✅ 통계: 전체 {st['total']}건, 상태별={st['by_status']}")
    ok += 1

    print(f"\n🎉 전체 {ok}/7 단계 통과")


if __name__ == "__main__":
    main()
