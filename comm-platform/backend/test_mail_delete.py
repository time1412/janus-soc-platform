"""메일 삭제 기능 검증 — 사용자별 소프트 삭제, 양쪽 삭제 시 완전 제거."""
import requests

B = "http://localhost:8810"


def login(u):
    return requests.post(f"{B}/api/login", json={"username": u, "password": "1234"}).json()


def main() -> None:
    snd = login("soc_lee")   # 보낸이
    rcp = login("ist_choi")  # 받는이

    # 메일 전송
    m = requests.post(f"{B}/api/mail", json={
        "sender_id": snd["id"], "recipient_id": rcp["id"],
        "subject": "삭제 테스트 메일", "body": "내용",
    }).json()
    mid = m["id"]
    print(f"전송: id={mid}")

    def in_inbox(uid):
        return any(x["id"] == mid for x in requests.get(f"{B}/api/mail/inbox?user_id={uid}").json())
    def in_sent(uid):
        return any(x["id"] == mid for x in requests.get(f"{B}/api/mail/sent?user_id={uid}").json())

    assert in_inbox(rcp["id"]) and in_sent(snd["id"])
    print("✅ 전송 직후: 받은이 inbox O, 보낸이 sent O")

    # 받는이가 삭제 → 받은이 inbox에서만 사라지고, 보낸이 sent는 유지
    requests.delete(f"{B}/api/mail/{mid}?user_id={rcp['id']}")
    assert not in_inbox(rcp["id"]), "받은이 inbox에서 사라져야 함"
    assert in_sent(snd["id"]), "보낸이 sent는 유지돼야 함"
    print("✅ 받는이 삭제: 받은이 inbox X, 보낸이 sent O (상대방 영향 없음)")

    # 보낸이도 삭제 → 완전 제거
    requests.delete(f"{B}/api/mail/{mid}?user_id={snd['id']}")
    assert not in_sent(snd["id"])
    r = requests.delete(f"{B}/api/mail/{mid}?user_id={snd['id']}")
    print(f"✅ 보낸이도 삭제: 완전 제거 (재삭제 응답 {r.status_code})")

    print("\n🎉 메일 삭제 검증 통과")


if __name__ == "__main__":
    main()
