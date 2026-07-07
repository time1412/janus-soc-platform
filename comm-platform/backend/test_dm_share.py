"""DM(1:1) + 채팅 이벤트 카드 공유 검증."""
import requests

B = "http://localhost:8810"


def login(u):
    return requests.post(f"{B}/api/login", json={"username": u, "password": "1234"}).json()


def main() -> None:
    a = login("soc_lee")    # 보낸이
    b = login("ist_choi")   # 받는이

    # ── DM ──
    requests.post(f"{B}/api/dm", json={"sender_id": a["id"], "recipient_id": b["id"], "body": "최보안님, 이벤트 확인 부탁드려요"})
    requests.post(f"{B}/api/dm", json={"sender_id": b["id"], "recipient_id": a["id"], "body": "네 확인 중입니다"})
    requests.post(f"{B}/api/dm", json={"sender_id": a["id"], "recipient_id": b["id"], "body": "감사합니다"})

    # b의 안읽음(2건: a가 보낸 것)
    un = requests.get(f"{B}/api/dm/unread_count?user_id={b['id']}").json()["unread"]
    assert un == 2, un
    print(f"✅ DM 전송 3건, ist_choi 안읽음 {un}건")

    # b의 스레드 목록
    threads = requests.get(f"{B}/api/dm/threads?user_id={b['id']}").json()
    assert threads and threads[0]["partner"]["username"] == "soc_lee"
    print(f"✅ DM 스레드: {threads[0]['partner']['display_name']} / 마지막='{threads[0]['last_body']}' / 안읽음={threads[0]['unread']}")

    # b가 대화 조회 → 읽음 처리
    convo = requests.get(f"{B}/api/dm/conversation?user_id={b['id']}&other_id={a['id']}").json()
    assert len(convo) == 3
    un2 = requests.get(f"{B}/api/dm/unread_count?user_id={b['id']}").json()["unread"]
    assert un2 == 0, un2
    print(f"✅ 대화 조회 {len(convo)}건 → 읽음 처리 후 안읽음 {un2}건")

    # ── 채팅 이벤트 카드 공유 ──
    ev = requests.get(f"{B}/api/events").json()[0]
    ch = requests.get(f"{B}/api/chat/channels").json()[1]
    msg = requests.post(f"{B}/api/chat/channels/{ch['id']}/messages",
                        json={"user_id": a["id"], "body": f"정탐 이벤트 공유: {ev['signature']}", "event_id": ev["id"]}).json()
    assert msg.get("event") and msg["event"]["id"] == ev["id"]
    print(f"✅ 채팅 이벤트 카드 공유: [{ch['name']}] '{msg['body']}' → 카드(시그니처={msg['event']['signature']}, AI={msg['event']['ai_verdict']} {msg['event']['ai_confidence']}%)")

    # 메시지 재조회 시 카드 유지
    msgs = requests.get(f"{B}/api/chat/channels/{ch['id']}/messages").json()
    assert any(m.get("event") and m["event"]["id"] == ev["id"] for m in msgs)
    print("✅ 재조회 시 이벤트 카드 유지")

    print("\n🎉 DM + 이벤트 카드 공유 검증 통과")


if __name__ == "__main__":
    main()
